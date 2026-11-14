package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
)

const moveBucketLimit = 128
const moveBookBytes = 512 << 10

type MoveBookOptions struct {
	Parent     *os.Root
	Directory  string
	Scope      string
	Profile    Profile
	Initialize bool
	Admission  statefile.Admission
	Guard      func(context.Context) error
	Fault      func(string) error
}
type moveBookHeader struct {
	Format      string            `json:"format"`
	Scope       string            `json:"scope"`
	Profile     string            `json:"profile"`
	MaxAttempts int               `json:"maxAttempts"`
	CreatedUnix int64             `json:"createdUnix"`
	Buckets     map[string]string `json:"buckets"`
}
type moveBucket struct {
	Format  string                `json:"format"`
	Scope   string                `json:"scope"`
	Prefix  string                `json:"prefix"`
	Records map[string]MoveRecord `json:"records"`
}
type MoveBook struct {
	o        MoveBookOptions
	store    *statefile.Store
	poisoned bool
}

func OpenMoveBook(ctx context.Context, o MoveBookOptions) (*MoveBook, error) {
	if o.Parent == nil || !ID(o.Scope) || o.Profile.Validate() != nil || o.Profile.WriteMode != WebDAVMoveMode {
		return nil, ErrDenied
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if o.Guard != nil {
		if e := o.Guard(ctx); e != nil {
			return nil, e
		}
	}
	s, e := statefile.OpenAt(o.Parent, o.Directory, moveBookBytes, o.Initialize)
	if e != nil {
		return nil, e
	}
	s.Admit = o.Admission
	b := &MoveBook{o: o, store: s}
	e = s.WithLock(ctx, func() error {
		_, e := b.header()
		if !errors.Is(e, os.ErrNotExist) || !o.Initialize {
			return e
		}
		// Missing initialized history must never be reconstructed from records.
		root, e := localfs.OpenAt(o.Parent, o.Directory, false)
		if e != nil {
			return e
		}
		defer root.Close()
		dir, e := root.Open(".")
		if e != nil {
			return e
		}
		entries, readErr := dir.ReadDir(8)
		dir.Close()
		if len(entries) == 8 || readErr != nil && !errors.Is(readErr, io.EOF) {
			return ErrConflict
		}
		for _, entry := range entries {
			if entry.Name() != ".lock" && !strings.HasPrefix(entry.Name(), ".tmp-") {
				return ErrConflict
			}
		}
		h := moveBookHeader{Format: MoveBookFormat, Scope: o.Scope, Profile: o.Profile.ID(), MaxAttempts: o.Profile.MaxStagingAttempts, CreatedUnix: time.Now().Unix(), Buckets: map[string]string{}}
		return b.persist(ctx, "book.json", h, "move-book-created")
	})
	if e != nil {
		s.Close()
		return nil, e
	}
	return b, nil
}
func (b *MoveBook) Close() error { return b.store.Close() }
func (b *MoveBook) guard(ctx context.Context) error {
	if b.poisoned {
		return ErrConflict
	}
	return b.Check(ctx)
}

func (b *MoveBook) Check(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if b.o.Guard != nil {
		return b.o.Guard(ctx)
	}
	return nil
}
func (b *MoveBook) persist(ctx context.Context, name string, v any, point string) error {
	if e := b.guard(ctx); e != nil {
		return e
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > moveBookBytes {
		return ErrCapacity
	}
	if e = b.store.Write(name, raw); e != nil {
		b.poisoned = true
		if errors.Is(e, statefile.ErrCapacity) {
			return errors.Join(ErrCapacity, e)
		}
		return e
	}
	if e = b.guard(ctx); e != nil {
		return e
	}
	if b.o.Fault != nil {
		return b.o.Fault(point)
	}
	return nil
}
func movePrefix(s string) bool {
	if len(s) != 3 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (b *MoveBook) header() (moveBookHeader, error) {
	var h moveBookHeader
	raw, e := b.store.Read("book.json")
	if e != nil {
		return h, e
	}
	if Decode(raw, &h, moveBookBytes) != nil || h.Format != MoveBookFormat || h.Scope != b.o.Scope || h.Profile != b.o.Profile.ID() || h.MaxAttempts != b.o.Profile.MaxStagingAttempts || h.CreatedUnix < 1 || h.CreatedUnix > time.Now().Unix() || h.Buckets == nil || len(h.Buckets) > 4096 {
		return h, ErrConflict
	}
	for prefix, phase := range h.Buckets {
		if !movePrefix(prefix) || phase != "ALLOCATING" && phase != "READY" {
			return h, ErrConflict
		}
	}
	return h, nil
}
func validMoveRecord(r MoveRecord, maxAttempts, maxBytes int) bool {
	if !safeName(r.Key, 170) || !ID(r.Digest) || r.Bytes < 1 || r.Bytes > maxBytes || r.UpdatedUnix < 1 || r.UpdatedUnix > time.Now().Unix() || len(r.Attempts) < 1 || len(r.Attempts) > maxAttempts {
		return false
	}
	seen := map[string]bool{}
	for i, a := range r.Attempts {
		if !ID(a.Nonce) || seen[a.Nonce] || a.Phase != "ALLOCATED" && a.Phase != "WRITING" && a.Phase != "STAGED" && a.Phase != "PUBLISHED" && a.Phase != "ABANDONED" {
			return false
		}
		if i < len(r.Attempts)-1 && a.Phase != "ABANDONED" && a.Phase != "PUBLISHED" {
			return false
		}
		if a.WriteStartedMillis < 0 || a.WriteStartedMillis > time.Now().UnixMilli() ||
			a.Phase == "ALLOCATED" && a.WriteStartedMillis != 0 ||
			a.Phase != "ALLOCATED" && a.Phase != "PUBLISHED" && a.WriteStartedMillis == 0 {
			return false
		}
		seen[a.Nonce] = true
	}
	return true
}
func (b *MoveBook) readBucket(prefix string) (moveBucket, error) {
	out := moveBucket{Format: MoveBookFormat, Scope: b.o.Scope, Prefix: prefix, Records: map[string]MoveRecord{}}
	raw, e := b.store.Read("bucket-" + prefix + ".json")
	if e != nil {
		return out, e
	}
	if Decode(raw, &out, moveBookBytes) != nil || out.Format != MoveBookFormat || out.Scope != b.o.Scope || out.Prefix != prefix || out.Records == nil || len(out.Records) > moveBucketLimit {
		return out, ErrConflict
	}
	for id, record := range out.Records {
		if !ID(id) || id[:3] != prefix || id != Hash([]byte(record.Key)) || !validMoveRecord(record, b.o.Profile.MaxStagingAttempts, b.o.Profile.MaxObjectBytes) {
			return out, ErrConflict
		}
	}
	return out, nil
}

func (b *MoveBook) bucket(ctx context.Context, h *moveBookHeader, prefix string) (moveBucket, error) {
	phase, known := h.Buckets[prefix]
	if !known {
		h.Buckets[prefix] = "ALLOCATING"
		if e := b.persist(ctx, "book.json", h, "move-bucket-intent"); e != nil {
			return moveBucket{}, e
		}
		phase = "ALLOCATING"
	}
	out, e := b.readBucket(prefix)
	if errors.Is(e, os.ErrNotExist) && phase == "ALLOCATING" {
		e = b.persist(ctx, "bucket-"+prefix+".json", out, "move-bucket-created")
	}
	if e != nil {
		return out, e
	}
	if phase == "ALLOCATING" {
		if len(out.Records) != 0 {
			return out, ErrConflict
		}
		h.Buckets[prefix] = "READY"
		if e = b.persist(ctx, "book.json", h, "move-bucket-ready"); e != nil {
			return out, e
		}
	}
	return out, nil
}

func (b *MoveBook) WithRecord(ctx context.Context, profile, key, digest string, size int, fn func(MoveTransaction) error) error {
	if profile != b.o.Profile.ID() || !safeName(key, 170) || !ID(digest) || size < 1 || size > b.o.Profile.MaxObjectBytes || fn == nil {
		return ErrDenied
	}
	return b.store.WithLock(ctx, func() error {
		if e := b.guard(ctx); e != nil {
			return e
		}
		h, e := b.header()
		if e != nil {
			return e
		}
		id := Hash([]byte(key))
		bucket, e := b.bucket(ctx, &h, id[:3])
		if e != nil {
			return e
		}
		record, exists := bucket.Records[id]
		if exists {
			if record.Key != key || record.Digest != digest || record.Bytes != size {
				return ErrConflict
			}
		} else {
			if len(bucket.Records) >= moveBucketLimit {
				return ErrCapacity
			}
			record = MoveRecord{Key: key, Digest: digest, Bytes: size, Attempts: []MoveAttempt{}}
		}
		tx := &moveTransaction{book: b, ctx: ctx, bucket: bucket, id: id, record: record, active: true}
		defer func() { tx.active = false }()
		if e = fn(tx); e != nil {
			return e
		}
		return b.guard(ctx)
	})
}

type moveTransaction struct {
	book   *MoveBook
	ctx    context.Context
	bucket moveBucket
	id     string
	record MoveRecord
	active bool
}

func (t *moveTransaction) State() MoveRecord {
	r := t.record
	r.Attempts = append([]MoveAttempt(nil), r.Attempts...)
	return r
}
func (t *moveTransaction) save(point string) error {
	if !t.active {
		return ErrConflict
	}
	now := time.Now().Unix()
	if now < t.record.UpdatedUnix {
		t.active = false
		return ErrConflict
	}
	t.record.UpdatedUnix = now
	if !validMoveRecord(t.record, t.book.o.Profile.MaxStagingAttempts, t.book.o.Profile.MaxObjectBytes) {
		return ErrConflict
	}
	t.bucket.Records[t.id] = t.record
	e := t.book.persist(t.ctx, "bucket-"+t.bucket.Prefix+".json", t.bucket, point)
	if e != nil {
		t.active = false
	}
	return e
}
func (t *moveTransaction) Allocate() (MoveAttempt, error) {
	if !t.active {
		return MoveAttempt{}, ErrConflict
	}
	if e := t.book.guard(t.ctx); e != nil {
		return MoveAttempt{}, e
	}
	if len(t.record.Attempts) >= t.book.o.Profile.MaxStagingAttempts {
		return MoveAttempt{}, ErrCapacity
	}
	if n := len(t.record.Attempts); n > 0 && t.record.Attempts[n-1].Phase != "ABANDONED" && t.record.Attempts[n-1].Phase != "PUBLISHED" {
		return MoveAttempt{}, ErrConflict
	}
	var random [32]byte
	if _, e := rand.Read(random[:]); e != nil {
		return MoveAttempt{}, e
	}
	a := MoveAttempt{Nonce: hex.EncodeToString(random[:]), Phase: "ALLOCATED"}
	t.record.Attempts = append(t.record.Attempts, a)
	if e := t.save("move-attempt-allocated"); e != nil {
		return MoveAttempt{}, e
	}
	return a, nil
}
func (t *moveTransaction) Transition(nonce, phase string) error {
	if !t.active || len(t.record.Attempts) == 0 {
		return ErrConflict
	}
	i := len(t.record.Attempts) - 1
	a := t.record.Attempts[i]
	if a.Nonce != nonce {
		return ErrConflict
	}
	if a.Phase == phase {
		return t.book.guard(t.ctx)
	}
	allowed := a.Phase == "ALLOCATED" && (phase == "WRITING" || phase == "PUBLISHED") ||
		a.Phase == "WRITING" && (phase == "STAGED" || phase == "ABANDONED" || phase == "PUBLISHED") ||
		a.Phase == "STAGED" && (phase == "PUBLISHED" || phase == "ABANDONED")
	if !allowed {
		return ErrConflict
	}
	if phase == "WRITING" {
		a.WriteStartedMillis = time.Now().UnixMilli()
	}
	a.Phase = phase
	t.record.Attempts[i] = a
	return t.save("move-attempt-" + strings.ToLower(phase))
}
func (t *moveTransaction) Temporary(a MoveAttempt) (string, error) {
	if !t.active || !ID(a.Nonce) {
		return "", ErrDenied
	}
	found := false
	for _, known := range t.record.Attempts {
		if known.Nonce == a.Nonce {
			found = true
			break
		}
	}
	if !found {
		return "", ErrDenied
	}
	return t.book.temporaryName(t.record, a), nil
}
