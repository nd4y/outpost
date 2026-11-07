package generation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
)

type entry struct {
	Sequence uint64 `json:"sequence"`
	Bytes    int    `json:"bytes"`
	Complete bool   `json:"complete"`
}
type Pin struct {
	Generation string `json:"generation"`
	Kind       string `json:"kind"`
}
type state struct {
	Format          string            `json:"format"`
	Trust           Trust             `json:"trust"`
	Revision        uint64            `json:"revision"`
	HighestSequence uint64            `json:"highestSequence"`
	HighestID       string            `json:"highestId"`
	Latest          string            `json:"latestComplete"`
	Generations     map[string]entry  `json:"generations"`
	Pins            map[string]Pin    `json:"pins"`
	Receipts        map[string]string `json:"maintenanceReceipts"`
}
type Status struct {
	Revision        uint64         `json:"revision"`
	HighestSequence uint64         `json:"highestSequence"`
	LatestComplete  string         `json:"latestKnownComplete"`
	Complete        []string       `json:"complete"`
	Receiving       []string       `json:"receiving"`
	Pins            map[string]Pin `json:"pins"`
}
type Replica struct {
	root  *os.Root
	trust Trust
	// Fault is a development-test hook; production callers leave it nil.
	Fault func(string) error
	Admit statefile.Admission
}

// Open requires an existing directory on an independently admitted filesystem.
// First enrollment is explicit and requires an empty directory. It does not
// implement volume/sentinel admission or an epoch transition procedure.
func Open(dir string, t Trust, initialize bool) (*Replica, error) {
	return OpenAt(nil, dir, t, initialize)
}
func OpenAt(parent *os.Root, dir string, t Trust, initialize bool) (*Replica, error) {
	if !t.valid() {
		return nil, ErrInvalid
	}
	t.Writer = append([]byte(nil), t.Writer...)
	t.Maintenance = append([]byte(nil), t.Maintenance...)
	r, err := localfs.Directory(parent, dir, false)
	if err != nil {
		return nil, err
	}
	p := &Replica{root: r, trust: t}
	if initialize {
		f, e := r.Open(".")
		if e != nil {
			r.Close()
			return nil, e
		}
		entries, e := f.ReadDir(1)
		f.Close()
		if len(entries) != 0 || e != io.EOF {
			r.Close()
			return nil, ErrInvalid
		}
		for _, name := range []string{"objects", ".txn", "catalogs"} {
			if e = r.Mkdir(name, 0700); e != nil {
				r.Close()
				return nil, e
			}
		}
		s := state{Format: StateFormat, Trust: t, Generations: map[string]entry{}, Pins: map[string]Pin{}, Receipts: map[string]string{}}
		if e = p.save(s); e != nil {
			r.Close()
			return nil, e
		}
	}
	if err = p.locked(context.Background(), func(s *state) error {
		for id := range s.Generations {
			if _, _, e := p.get(s, id, true); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		r.Close()
		return nil, err
	}
	return p, nil
}
func (r *Replica) Close() error { return r.root.Close() }
func (r *Replica) point(name string) error {
	if r.Fault != nil {
		return r.Fault(name)
	}
	return nil
}
func syncDir(root *os.Root, name string) error {
	f, e := root.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func read(root *os.Root, name string, limit int) ([]byte, error) {
	f, e := localfs.OpenFile(root, name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Size() < 1 || i.Size() > int64(limit) {
		return nil, ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > limit || int64(len(b)) != i.Size() {
		return nil, ErrInvalid
	}
	return b, nil
}
func randomID() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func atomic(root *os.Root, name string, b []byte) error {
	id, e := randomID()
	if e != nil {
		return e
	}
	temp := ".txn/" + id
	f, e := localfs.OpenFile(root, temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(temp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = root.Rename(temp, name); e != nil {
		return e
	}
	return syncDir(root, filepath.Dir(name))
}
func (r *Replica) write(name string, b []byte) error {
	return statefile.Guard(r.Admit, name, len(b), func() error { return atomic(r.root, name, b) })
}
func (r *Replica) save(s state) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if len(b) > MaxState {
		return statefile.ErrCapacity
	}
	if e = r.write("state.json", b); e != nil {
		return e
	}
	return r.point("state-durable")
}
func (r *Replica) load() (state, error) {
	var s state
	b, e := read(r.root, "state.json", MaxState)
	if e != nil {
		return s, e
	}
	var header struct {
		Format string `json:"format"`
	}
	if json.Unmarshal(b, &header) == nil && header.Format == Format {
		return s, ErrMigrationRequired
	}
	if e = canonical(b, &s, MaxState); e != nil {
		return s, e
	}
	return r.validateState(s)
}
func (r *Replica) validateState(s state) (state, error) {
	t, _ := json.Marshal(r.trust)
	u, _ := json.Marshal(s.Trust)
	if s.Format != StateFormat || !bytes.Equal(t, u) || s.Generations == nil || s.Pins == nil || s.Receipts == nil || len(s.Generations) > MaxGenerations || len(s.Pins) > MaxPins || len(s.Receipts) > MaxPins || s.Revision == ^uint64(0) {
		return s, ErrInvalid
	}
	for id, digest := range s.Receipts {
		if !validID(id) || !validID(digest) {
			return s, ErrInvalid
		}
	}
	if (s.HighestSequence == 0) != (s.HighestID == "") || (s.HighestID != "" && !validID(s.HighestID)) {
		return s, ErrInvalid
	}
	sequences := map[uint64]string{}
	latestSequence := uint64(0)
	latestID := ""
	for id, item := range s.Generations {
		if !validID(id) || item.Sequence == 0 || item.Sequence > s.HighestSequence || item.Bytes < 1 || item.Bytes > MaxCatalog {
			return s, ErrInvalid
		}
		if old, ok := sequences[item.Sequence]; ok && old != id {
			return s, ErrConflict
		}
		sequences[item.Sequence] = id
		if item.Sequence == s.HighestSequence && id != s.HighestID {
			return s, ErrConflict
		}
		if item.Complete && item.Sequence > latestSequence {
			latestSequence = item.Sequence
			latestID = id
		}
	}
	if s.Latest != latestID {
		return s, ErrInvalid
	}
	for id, pin := range s.Pins {
		if !validID(id) || !pinKind(pin.Kind) {
			return s, ErrInvalid
		}
		if item, ok := s.Generations[pin.Generation]; !ok || !item.Complete {
			return s, ErrInvalid
		}
	}
	return s, nil
}
func pinKind(k string) bool { return k == "generation" || k == "kit" || k == "restore" }
func (r *Replica) locked(ctx context.Context, fn func(*state) error) error {
	return r.exclusive(ctx, func() error {
		s, e := r.load()
		if e != nil {
			return e
		}
		return fn(&s)
	})
}
func (r *Replica) exclusive(ctx context.Context, fn func() error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	f, e := localfs.OpenFile(r.root, ".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return ErrInvalid
	}
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func (r *Replica) object(ref Object) ([]byte, error) {
	b, e := read(r.root, "objects/"+ref.ID, MaxObject)
	if e != nil {
		return nil, e
	}
	if len(b) != ref.Bytes || Hash(b) != ref.ID {
		return nil, ErrIncomplete
	}
	return b, nil
}
func (r *Replica) get(s *state, id string, fresh bool) (Catalog, map[string]Object, error) {
	item, ok := s.Generations[id]
	if !ok {
		return Catalog{}, nil, ErrInvalid
	}
	return r.catalogEntry(id, item, fresh)
}
func (r *Replica) Begin(ctx context.Context, raw []byte) (string, error) {
	c, e := VerifyCatalog(raw, r.trust)
	if e != nil {
		return "", e
	}
	id := Hash(raw)
	e = r.locked(ctx, func(s *state) error {
		if _, ok := s.Generations[id]; ok {
			_, _, e := r.get(s, id, true)
			return e
		}
		if c.Sequence == s.HighestSequence && id != s.HighestID {
			return ErrConflict
		}
		if c.Sequence <= s.HighestSequence {
			return ErrRollback
		}
		if len(s.Generations) >= MaxGenerations {
			return statefile.ErrCapacity
		}
		if e := r.putCatalog(id, raw); e != nil {
			return e
		}
		s.Generations[id] = entry{Sequence: c.Sequence, Bytes: len(raw)}
		s.HighestID = id
		s.HighestSequence = c.Sequence
		s.Revision++
		return r.save(*s)
	})
	return id, e
}
func (r *Replica) Put(ctx context.Context, generation, id string, b []byte) error {
	if len(b) > MaxObject || !validID(id) || Hash(b) != id {
		return ErrInvalid
	}
	return r.locked(ctx, func(s *state) error {
		_, refs, e := r.get(s, generation, false)
		if e != nil {
			return e
		}
		ref, ok := refs[id]
		if !ok || ref.Bytes != len(b) {
			return ErrInvalid
		}
		if _, e = r.object(ref); e == nil {
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e = r.write("objects/"+id, b); e != nil {
			return e
		}
		return r.point("object-durable")
	})
}
func (r *Replica) Complete(ctx context.Context, id string) error {
	return r.locked(ctx, func(s *state) error {
		c, refs, e := r.get(s, id, true)
		if e != nil {
			return e
		}
		for _, key := range sortedIDs(refs) {
			if e = ctx.Err(); e != nil {
				return e
			}
			if _, e = r.object(refs[key]); e != nil {
				return ErrIncomplete
			}
		}
		if s.Generations[id].Complete {
			return nil
		}
		if e = r.point("before-complete"); e != nil {
			return e
		}
		item := s.Generations[id]
		item.Complete = true
		s.Generations[id] = item
		if s.Latest == "" {
			s.Latest = id
		} else {
			latest, _, e := r.get(s, s.Latest, false)
			if e != nil {
				return e
			}
			if c.Sequence > latest.Sequence {
				s.Latest = id
			}
		}
		s.Revision++
		return r.save(*s)
	})
}

// Receive may be retried after interruption. Begin durably protects the entire
// unfinished closure before any object is accepted. The fetcher has no key.
func (r *Replica) Receive(ctx context.Context, raw []byte, fetch func(Object) ([]byte, error)) (string, error) {
	if fetch == nil {
		return "", ErrInvalid
	}
	id, e := r.Begin(ctx, raw)
	if e != nil {
		return id, e
	}
	var missing []Object
	e = r.locked(ctx, func(s *state) error {
		_, refs, e := r.get(s, id, false)
		if e != nil {
			return e
		}
		for _, key := range sortedIDs(refs) {
			if e = ctx.Err(); e != nil {
				return e
			}
			_, e = r.object(refs[key])
			if errors.Is(e, os.ErrNotExist) {
				missing = append(missing, refs[key])
			} else if e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return id, e
	}
	for _, ref := range missing {
		if e = ctx.Err(); e != nil {
			return id, e
		}
		b, e := fetch(ref)
		if e != nil {
			return id, e
		}
		if e = r.Put(ctx, id, ref.ID, b); e != nil {
			return id, e
		}
	}
	return id, r.Complete(ctx, id)
}
func (r *Replica) ReadObject(ctx context.Context, id string, ref Object) ([]byte, error) {
	var b []byte
	e := r.locked(ctx, func(s *state) error {
		_, refs, e := r.get(s, id, false)
		if e != nil {
			return e
		}
		expected, ok := refs[ref.ID]
		if !ok || expected != ref {
			return ErrInvalid
		}
		b, e = r.object(ref)
		return e
	})
	return b, e
}
func (r *Replica) Catalog(ctx context.Context, id string) ([]byte, error) {
	var b []byte
	e := r.locked(ctx, func(s *state) error {
		item, ok := s.Generations[id]
		if !ok || !item.Complete {
			return ErrIncomplete
		}
		raw, err := r.catalogRaw(id, item)
		b = raw
		return err
	})
	return b, e
}
func (r *Replica) Status(ctx context.Context) (Status, error) {
	var result Status
	e := r.locked(ctx, func(s *state) error {
		result = Status{Revision: s.Revision, HighestSequence: s.HighestSequence, LatestComplete: s.Latest, Pins: s.Pins}
		for id, item := range s.Generations {
			if item.Complete {
				result.Complete = append(result.Complete, id)
			} else {
				result.Receiving = append(result.Receiving, id)
			}
		}
		sort.Strings(result.Complete)
		sort.Strings(result.Receiving)
		return nil
	})
	return result, e
}
func (r *Replica) Pin(ctx context.Context, id, generation, kind string) error {
	if !validID(id) || !pinKind(kind) {
		return ErrInvalid
	}
	return r.locked(ctx, func(s *state) error {
		p := Pin{generation, kind}
		if old, ok := s.Pins[id]; ok {
			if old != p {
				return ErrConflict
			}
			return nil
		}
		item, ok := s.Generations[generation]
		if !ok || !item.Complete || len(s.Pins) >= MaxPins {
			return ErrInvalid
		}
		s.Pins[id] = p
		s.Revision++
		return r.save(*s)
	})
}

// ReleasePin is a local operator API, not a remotely exposed permission. It
// never deletes data; subsequent retirement still needs maintenance authority.
func (r *Replica) ReleasePin(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrInvalid
	}
	return r.locked(ctx, func(s *state) error {
		if _, ok := s.Pins[id]; !ok {
			return nil
		}
		delete(s.Pins, id)
		s.Revision++
		return r.save(*s)
	})
}
