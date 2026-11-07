package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

const SessionFormat = "outpost-ingress-session-1"

type SessionOptions struct {
	Parent                  *os.Root
	Directory               string
	Authority, Intent       []byte
	Owner                   ed25519.PublicKey
	Replica                 *generation.Replica
	Initialize              bool
	AdmitState, AdmitObject statefile.Admission
	RemoveObject            func(context.Context, string, int64) error
}
type sessionState struct {
	Format       string          `json:"format"`
	Intent       json.RawMessage `json:"intent"`
	Authority    json.RawMessage `json:"authority"`
	LastObserved int64           `json:"lastObserved"`
	Catalog      json.RawMessage `json:"catalog,omitempty"`
	Complete     bool            `json:"complete"`
	CompletedAt  int64           `json:"completedAt,omitempty"`
	Receipt      *Receipt        `json:"receipt,omitempty"`
	Acknowledged bool            `json:"acknowledged,omitempty"`
}
type Receipt struct {
	Operation  string `json:"operation"`
	Ingress    string `json:"ingress"`
	Tenant     string `json:"tenant"`
	Domain     string `json:"domain"`
	Generation string `json:"generation"`
	NewBytes   int64  `json:"newBytes"`
	NewObjects int    `json:"newObjects"`
	VerifiedAt int64  `json:"verifiedAt"`
}
type Session struct {
	root          *os.Root
	mu            sync.Mutex
	state         sessionState
	intent        Intent
	owner         ed25519.PublicKey
	meta, objects *statefile.Store
	objectRoot    *os.Root
	lease         *os.File
	replica       *generation.Replica
	refs, base    map[string]generation.Object
	baseID        string
	bytes         int64
	poisoned      bool
	removeObject  func(context.Context, string, int64) error
	Fault         func(string) error
}

func (s *Session) point(name string) error {
	if s.Fault != nil {
		return s.Fault(name)
	}
	return nil
}
func (s *Session) pin(kind string) string {
	return storage.Hash([]byte(SessionFormat + "/" + s.intent.Tenant + "/" + s.intent.Operation + "/" + kind))
}
func (s *Session) save() error {
	b, e := json.Marshal(s.state)
	if e != nil {
		return e
	}
	e = s.meta.Write("session.json", b)
	if e != nil {
		s.poisoned = true
	}
	return e
}
func (s *Session) guard(ctx context.Context) error {
	return s.guardMode(ctx, false)
}
func (s *Session) guardMode(ctx context.Context, cleanup bool) error {
	if s.poisoned {
		return ErrConflict
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	now := time.Now()
	if now.Unix() < s.state.LastObserved {
		return ErrDenied
	}
	checkTime := now
	if cleanup {
		if !s.state.Complete || s.state.Receipt == nil {
			return ErrIncomplete
		}
		checkTime = time.Unix(s.intent.NotBefore, 0)
	}
	if _, _, e := VerifyIntent(s.state.Intent, s.state.Authority, s.owner, checkTime); e != nil {
		return e
	}
	if now.Unix() > s.state.LastObserved {
		old := s.state.LastObserved
		s.state.LastObserved = now.Unix()
		if e := s.save(); e != nil {
			s.state.LastObserved = old
			return e
		}
	}
	return nil
}

// OpenSession holds an exclusive process lease until Close. Durable object
// files themselves are acceptance records: reopening inventories their bounded
// names and lengths, rather than rewriting an ever-growing index on each PUT.
// Bytes are rehashed on reads and before publication. The service must also
// enforce a bounded number of admitted sessions and a shared disk budget.
func OpenSession(ctx context.Context, o SessionOptions) (*Session, error) {
	return openSession(ctx, o, false)
}
func openSession(ctx context.Context, o SessionOptions, acknowledgedOnly bool) (*Session, error) {
	checkTime := time.Now()
	if acknowledgedOnly {
		// Historical validation opens only an existing COMPLETE slot for cleanup.
		// Every data operation still requires current authority.
		if o.Initialize {
			return nil, ErrDenied
		}
		var old Intent
		if canonical(o.Intent, &old) != nil {
			return nil, ErrDenied
		}
		checkTime = time.Unix(old.NotBefore, 0)
	}
	i, a, e := VerifyIntent(o.Intent, o.Authority, o.Owner, checkTime)
	if e != nil {
		return nil, e
	}
	if o.Replica == nil {
		return nil, ErrDenied
	}
	x, _ := json.Marshal(o.Replica.Trust())
	y, _ := json.Marshal(a.Trust)
	if !bytes.Equal(x, y) {
		return nil, ErrDenied
	}
	r, e := localfs.Directory(o.Parent, o.Directory, o.Initialize)
	if e != nil {
		return nil, e
	}
	// Transferred to the instance only after the lease is held.
	owned := false
	defer func() {
		if !owned {
			r.Close()
		}
	}()
	info, e := r.Stat(".")
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}

	lease, e := localfs.OpenFile(r, ".capture-lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	info, e = lease.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		lease.Close()
		return nil, ErrDenied
	}
	if e = unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lease.Close()
		return nil, ErrConflict
	}
	owned = true
	s := &Session{root: r, intent: i, owner: bytes.Clone(o.Owner), lease: lease, replica: o.Replica, refs: map[string]generation.Object{}, base: map[string]generation.Object{}, removeObject: o.RemoveObject}
	fail := func(e error) (*Session, error) { s.Close(); return nil, e }
	s.meta, e = statefile.OpenAt(r, "state", generation.MaxCatalog+2*MaxDocument+4096, o.Initialize)
	if e != nil {
		return fail(e)
	}
	s.meta.Admit = o.AdmitState
	s.objects, e = statefile.OpenAt(r, "objects", generation.MaxObject, o.Initialize)
	if e != nil {
		return fail(e)
	}
	s.objects.Admit = o.AdmitObject
	s.objectRoot, e = localfs.OpenAt(r, "objects", false)
	if e != nil {
		return fail(e)
	}
	raw, e := s.meta.Read("session.json")
	if errors.Is(e, os.ErrNotExist) && o.Initialize {
		s.state = sessionState{Format: SessionFormat, Intent: bytes.Clone(o.Intent), Authority: bytes.Clone(o.Authority), LastObserved: time.Now().Unix()}
		if e = s.save(); e != nil {
			return fail(e)
		}
	} else if e != nil {
		return fail(e)
	} else {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&s.state) != nil {
			return fail(ErrDenied)
		}
		canonical, _ := json.Marshal(s.state)
		if !bytes.Equal(canonical, raw) || s.state.Format != SessionFormat || !bytes.Equal(s.state.Intent, o.Intent) || !bytes.Equal(s.state.Authority, o.Authority) {
			return fail(ErrConflict)
		}
	}
	if acknowledgedOnly {
		if !s.state.Complete || s.state.LastObserved > time.Now().Unix() || ctx.Err() != nil {
			return fail(ErrConflict)
		}
	} else {
		if e = s.guard(ctx); e != nil {
			return fail(e)
		}
	}
	if s.state.LastObserved < 1 || s.state.CompletedAt > s.state.LastObserved || s.state.Complete && s.state.CompletedAt < 1 || !s.state.Complete && s.state.CompletedAt != 0 {
		return fail(ErrConflict)
	}
	if len(s.state.Catalog) > 0 {
		c, e := generation.VerifyCatalog(s.state.Catalog, a.Trust)
		if e != nil || !i.matches(c) {
			return fail(ErrConflict)
		}
	} else if s.state.Complete && !s.state.Acknowledged {
		return fail(ErrConflict)
	}
	if s.state.Receipt != nil {
		r := *s.state.Receipt
		if !s.state.Complete || !r.matches(i) || r.VerifiedAt != s.state.CompletedAt || (!s.state.Acknowledged && r.Generation != storage.Hash(s.state.Catalog)) {
			return fail(ErrConflict)
		}
	} else if s.state.Complete {
		return fail(ErrConflict)
	}
	if s.state.Acknowledged && (!s.state.Complete || len(s.state.Catalog) != 0) {
		return fail(ErrConflict)
	}
	s.baseID = i.Parent
	if s.state.Complete {
		s.baseID = storage.Hash(s.state.Catalog)
	}
	if s.baseID != "" && !s.state.Acknowledged {
		kind := "base"
		if s.state.Complete {
			kind = "receipt"
		}
		if e = o.Replica.Pin(ctx, s.pin(kind), s.baseID, "generation"); e != nil {
			return fail(e)
		}
		// Base reuse is a hint from a retained COMPLETE catalog. Payload is
		// freshly verified in bounded batches before the new generation commits.
		raw, e := o.Replica.Catalog(ctx, s.baseID)
		if e != nil {
			return fail(e)
		}
		refs, e := generation.Dependencies(raw, a.Trust)
		if e != nil {
			return fail(e)
		}
		for _, ref := range refs {
			s.base[ref.ID] = ref
		}
		if s.state.Complete && i.Parent != "" {
			if e = o.Replica.ReleasePin(ctx, s.pin("base")); e != nil {
				return fail(e)
			}
		}
	}
	f, e := s.objectRoot.Open(".")
	if e != nil {
		return fail(e)
	}
	entries, e := f.ReadDir(generation.MaxObjects*2 + 17)
	f.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return fail(e)
	}
	if len(entries) > generation.MaxObjects*2+16 {
		return fail(statefile.ErrCapacity)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".tmp-") {
			continue
		}
		if !storage.ID(name) {
			return fail(ErrDenied)
		}
		info, e := localfs.Stat(s.objectRoot, name)
		if e != nil {
			return fail(e)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > generation.MaxObject {
			return fail(ErrDenied)
		}
		ref := generation.Object{ID: name, Bytes: int(info.Size())}
		s.refs[name] = ref
		s.bytes += info.Size()
		if len(s.refs) > i.MaxObjects || s.bytes > i.MaxBytes {
			return fail(statefile.ErrCapacity)
		}
	}
	return s, nil
}
func (s *Session) Close() error {
	var e error
	if s.objectRoot != nil {
		e = errors.Join(e, s.objectRoot.Close())
	}
	if s.objects != nil {
		e = errors.Join(e, s.objects.Close())
	}
	if s.meta != nil {
		e = errors.Join(e, s.meta.Close())
	}
	if s.lease != nil {
		e = errors.Join(e, unix.Flock(int(s.lease.Fd()), unix.LOCK_UN), s.lease.Close())
	}
	if s.root != nil {
		e = errors.Join(e, s.root.Close())
		s.root = nil
	}
	return e
}
func validObject(ref filekit.Object) bool {
	return storage.ID(ref.ID) && ref.Bytes > 0 && ref.Bytes <= generation.MaxObject
}
func (s *Session) read(ctx context.Context, ref filekit.Object) ([]byte, error) {
	if !validObject(ref) {
		return nil, ErrDenied
	}
	o := generation.Object{ID: ref.ID, Bytes: ref.Bytes}
	if own, ok := s.refs[ref.ID]; ok {
		if own != o {
			return nil, ErrConflict
		}
		b, e := s.objects.Read(ref.ID)
		if e != nil {
			return nil, e
		}
		if len(b) != ref.Bytes || storage.Hash(b) != ref.ID {
			return nil, ErrIncomplete
		}
		return b, nil
	}
	if base, ok := s.base[ref.ID]; ok && base == o {
		return s.replica.ReadObject(ctx, s.baseID, o)
	}
	return nil, os.ErrNotExist
}
func (s *Session) Read(ctx context.Context, ref filekit.Object) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.guard(ctx); e != nil {
		return nil, e
	}
	if s.state.Acknowledged {
		return nil, ErrConflict
	}
	return s.read(ctx, ref)
}
func (s *Session) Check(ctx context.Context, ref filekit.Object) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.guard(ctx); e != nil {
		return e
	}
	if s.state.Acknowledged {
		return ErrConflict
	}
	if !validObject(ref) {
		return ErrDenied
	}
	o := generation.Object{ID: ref.ID, Bytes: ref.Bytes}
	if own, ok := s.refs[ref.ID]; ok {
		if own != o {
			return ErrConflict
		}
		f, e := localfs.OpenFile(s.objectRoot, ref.ID, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() != int64(ref.Bytes) {
			return ErrIncomplete
		}
		return nil
	}
	if base, ok := s.base[ref.ID]; ok && base == o {
		return s.replica.CheckObject(ctx, s.baseID, o)
	}
	return os.ErrNotExist
}
func (s *Session) Write(ctx context.Context, ref filekit.Object, b []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.guard(ctx); e != nil {
		return false, e
	}
	if s.state.Acknowledged {
		return false, ErrConflict
	}
	if !validObject(ref) || len(b) != ref.Bytes || storage.Hash(b) != ref.ID {
		return false, ErrDenied
	}
	if _, ok := s.refs[ref.ID]; ok {
		prior, e := s.read(ctx, ref)
		if e != nil {
			return false, e
		}
		if !bytes.Equal(prior, b) {
			return false, ErrConflict
		}
		return false, nil
	}
	if _, ok := s.base[ref.ID]; ok {
		prior, e := s.read(ctx, ref)
		if e != nil {
			return false, e
		}
		if !bytes.Equal(prior, b) {
			return false, ErrConflict
		}
		return false, nil
	}
	if len(s.state.Catalog) > 0 || s.state.Complete {
		return false, ErrConflict
	}
	if len(s.refs) >= s.intent.MaxObjects || s.bytes+int64(len(b)) > s.intent.MaxBytes {
		return false, statefile.ErrCapacity
	}
	if e := s.objects.Write(ref.ID, b); e != nil {
		return false, e
	}
	s.refs[ref.ID] = generation.Object{ID: ref.ID, Bytes: ref.Bytes}
	s.bytes += int64(ref.Bytes)
	return true, s.point("capture-object-durable")
}
func (s *Session) prepare(ctx context.Context, raw []byte) ([]generation.Object, error) {
	if e := s.guard(ctx); e != nil {
		return nil, e
	}
	if s.state.Acknowledged {
		return nil, ErrConflict
	}
	c, e := generation.VerifyCatalog(raw, s.replica.Trust())
	if e != nil || !s.intent.matches(c) {
		return nil, ErrDenied
	}
	if len(s.state.Catalog) > 0 && !bytes.Equal(s.state.Catalog, raw) {
		return nil, ErrConflict
	}
	refs, e := generation.Dependencies(raw, s.replica.Trust())
	if e != nil {
		return nil, e
	}
	for _, ref := range refs {
		if s.refs[ref.ID] != ref && s.base[ref.ID] != ref {
			return nil, ErrIncomplete
		}
	}
	if len(s.state.Catalog) == 0 {
		s.state.Catalog = bytes.Clone(raw)
		if e = s.save(); e != nil {
			s.state.Catalog = nil
			return nil, e
		}
		if e = s.point("capture-catalog-durable"); e != nil {
			return nil, e
		}
	}
	return refs, nil
}
func (s *Session) Finish(ctx context.Context, raw []byte) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs, e := s.prepare(ctx, raw)
	if e != nil {
		return Receipt{}, e
	}
	id, e := s.replica.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) {
		return s.read(ctx, filekit.Object{ID: ref.ID, Bytes: ref.Bytes})
	})
	if e != nil {
		return Receipt{}, e
	}
	return s.accepted(ctx, id, refs, time.Now().Unix())
}
func (s *Session) FinishBatch(ctx context.Context, raw []byte, maxObjects int, maxBytes int64) (generation.BatchResult, Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result generation.BatchResult
	refs, e := s.prepare(ctx, raw)
	if e != nil {
		return result, Receipt{}, e
	}
	result, e = s.replica.ReceiveBatch(ctx, raw, maxObjects, maxBytes, func(ref generation.Object) ([]byte, error) {
		return s.read(ctx, filekit.Object{ID: ref.ID, Bytes: ref.Bytes})
	})
	if e != nil || !result.Complete {
		return result, Receipt{}, e
	}
	receipt, e := s.accepted(ctx, result.Generation, refs, result.VerifiedAt)
	return result, receipt, e
}
func (s *Session) accepted(ctx context.Context, id string, refs []generation.Object, verifiedAt int64) (Receipt, error) {
	var result Receipt
	var e error
	if e = s.replica.Pin(ctx, s.pin("receipt"), id, "generation"); e != nil {
		return result, e
	}
	if e = s.point("capture-replica-complete"); e != nil {
		return result, e
	}
	wasComplete := s.state.Complete
	oldTime := s.state.CompletedAt
	oldReceipt := s.state.Receipt
	if e := s.guard(ctx); e != nil {
		return result, e
	}
	if verifiedAt < s.intent.NotBefore || verifiedAt > s.state.LastObserved {
		return result, ErrConflict
	}
	s.state.Complete = true
	if !wasComplete {
		s.state.CompletedAt = verifiedAt
		s.state.Receipt = &Receipt{Operation: s.intent.Operation, Ingress: s.intent.Ingress, Tenant: s.intent.Tenant, Domain: s.intent.Domain, Generation: id, NewBytes: s.bytes, NewObjects: len(s.refs), VerifiedAt: verifiedAt}
	}
	if e = s.save(); e != nil {
		s.state.Complete = wasComplete
		s.state.CompletedAt = oldTime
		s.state.Receipt = oldReceipt
		return result, e
	}
	if s.intent.Parent != "" {
		if e = s.replica.ReleasePin(ctx, s.pin("base")); e != nil {
			return result, e
		}
	}
	s.baseID = id
	s.base = map[string]generation.Object{}
	for _, ref := range refs {
		s.base[ref.ID] = ref
	}
	if e = s.point("capture-receipt-durable"); e != nil {
		return result, e
	}
	return *s.state.Receipt, nil
}
