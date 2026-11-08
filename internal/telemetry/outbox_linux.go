package telemetry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

// Options binds a journal to one locally admitted sink and domain. Binding is
// the digest of the private endpoint/profile, never the endpoint itself.
// MaxBytes bounds the complete serialized journal. Admission must separately
// reserve the physical peak of atomic replacement, including the old journal.
type Options struct {
	Root                    *os.Root
	Directory               string
	Signer                  ed25519.PrivateKey
	Target, Domain, Binding string
	MaxBytes, MaxItems      int
	Initialize              bool
	Guard                   func(context.Context) error
	Admission               statefile.Admission
	Owner                   ed25519.PublicKey
	Enrollment              []byte // Initial owner-signed scope; only Renew changes it later.
	Authorize               func(context.Context, management.Enrollment) error
}
type frame struct {
	Position  uint64    `json:"position"`
	Record    Record    `json:"record"`
	Messages  []Message `json:"messages"`
	Next      int       `json:"next"`
	Attempts  uint64    `json:"attempts"`
	NotBefore int64     `json:"notBefore"`
	Blocked   string    `json:"blocked,omitempty"`
	Rejected  int64     `json:"rejected"`
}
type journal struct {
	Format       string            `json:"format"`
	Node         string            `json:"node"`
	Target       string            `json:"target"`
	Domain       string            `json:"domain"`
	Binding      string            `json:"binding"`
	MaxBytes     int               `json:"maxBytes"`
	MaxItems     int               `json:"maxItems"`
	Cursor       uint64            `json:"cursor"`
	LastDigest   string            `json:"lastDigest,omitempty"`
	Frames       []frame           `json:"frames"`
	Accepted     uint64            `json:"accepted"`
	Warnings     uint64            `json:"warnings"`
	Discarded    uint64            `json:"discarded"`
	DiscardChain string            `json:"discardChain,omitempty"`
	Signature    []byte            `json:"signature,omitempty"`
	Owner        ed25519.PublicKey `json:"owner,omitempty"`
	Enrollment   []byte            `json:"enrollment,omitempty"`
	NextSample   int64             `json:"nextSample"`
	EventsDigest string            `json:"eventsDigest,omitempty"`
}
type Status struct {
	Cursor             uint64 `json:"cursor"`
	Pending            int    `json:"pending"`
	Bytes              int    `json:"bytes"`
	Accepted           uint64 `json:"accepted"`
	Warnings           uint64 `json:"warnings"`
	Rejected           int64  `json:"rejected"`
	Discarded          uint64 `json:"discarded"`
	DiscardChain       string `json:"discardChain,omitempty"`
	Position           uint64 `json:"position,omitempty"`
	Digest             string `json:"digest,omitempty"`
	Signal             string `json:"signal,omitempty"`
	Attempts           uint64 `json:"attempts,omitempty"`
	NotBefore          int64  `json:"notBefore,omitempty"`
	Blocked            string `json:"blocked,omitempty"`
	EnrollmentRevision uint64 `json:"enrollmentRevision,omitempty"`
	EnrollmentActive   bool   `json:"enrollmentActive"`
	NextSample         int64  `json:"nextSample"`
}
type Outbox struct {
	store, delivery *statefile.Store
	opts            Options
	node            string
	// Fault is for process-boundary acceptance tests, never remote configuration.
	Fault func(string) error
}

func Open(o Options) (*Outbox, error) {
	if len(o.Signer) != ed25519.PrivateKeySize || !storage.ID(o.Target) || !storage.ID(o.Domain) || !storage.ID(o.Binding) || o.MaxItems < 1 || o.MaxItems > 128 || o.MaxBytes < 4096 || o.MaxBytes > 4<<20 {
		return nil, ErrInvalid
	}
	public, e := x509.MarshalPKIXPublicKey(o.Signer.Public())
	if e != nil {
		return nil, ErrInvalid
	}
	o.Signer = append(ed25519.PrivateKey(nil), o.Signer...)
	if len(o.Owner) != 0 && len(o.Owner) != 32 || len(o.Owner) == 0 && (len(o.Enrollment) != 0 || o.Authorize != nil) || !o.Initialize && len(o.Enrollment) != 0 {
		return nil, ErrInvalid
	}
	o.Owner = append(ed25519.PublicKey(nil), o.Owner...)
	q := &Outbox{opts: o, node: storage.Hash(public)}
	if e = q.check(context.Background()); e != nil {
		return nil, e
	}
	if o.Initialize {
		if o.Root != nil {
			_, e = o.Root.Lstat(o.Directory)
		} else {
			_, e = os.Lstat(o.Directory)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return nil, ErrConflict
		}
	}
	root, e := localfs.Directory(o.Root, o.Directory, o.Initialize)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	q.store, e = statefile.OpenAt(root, ".", o.MaxBytes, false)
	if e != nil {
		return nil, e
	}
	q.store.Admit = o.Admission
	q.delivery, e = statefile.OpenAt(root, "delivery", 1, o.Initialize)
	if e != nil {
		q.store.Close()
		return nil, e
	}
	e = q.store.WithLock(context.Background(), func() error {
		_, _, err := q.load()
		if !o.Initialize {
			return err
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ErrConflict
		}
		s := journal{Format: Format, Node: q.node, Target: o.Target, Domain: o.Domain, Binding: o.Binding, MaxBytes: o.MaxBytes, MaxItems: o.MaxItems, Frames: []frame{}, Owner: o.Owner, Enrollment: append([]byte(nil), o.Enrollment...)}
		if e := q.authorize(context.Background(), s); e != nil {
			return e
		}
		return q.save(s)
	})
	if e != nil {
		q.Close()
		return nil, e
	}
	return q, nil
}
func (q *Outbox) Close() error { return errors.Join(q.store.Close(), q.delivery.Close()) }
func (q *Outbox) check(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if q.opts.Guard != nil {
		return q.opts.Guard(ctx)
	}
	return nil
}
func (q *Outbox) point(name string) error {
	if q.Fault != nil {
		return q.Fault(name)
	}
	return nil
}
func (q *Outbox) load() (journal, int, error) {
	var s journal
	raw, e := q.store.Read("queue.json")
	if e != nil {
		return s, 0, e
	}
	if storage.Decode(raw, &s, q.opts.MaxBytes) != nil {
		return s, 0, ErrInvalid
	}
	signature := s.Signature
	s.Signature = nil
	unsigned, _ := json.Marshal(s)
	if !ed25519.Verify(q.opts.Signer.Public().(ed25519.PublicKey), append([]byte(Format+"\x00"), unsigned...), signature) {
		return s, 0, ErrInvalid
	}
	s.Signature = signature
	if !bytes.Equal(s.Owner, q.opts.Owner) || s.NextSample < 0 || !optionalID(s.EventsDigest) {
		return s, 0, ErrConflict
	}
	if _, e := q.grant(s.Enrollment); e != nil {
		return s, 0, e
	}
	if s.Format != Format || s.Node != q.node || s.Target != q.opts.Target || s.Domain != q.opts.Domain || s.Binding != q.opts.Binding || s.MaxBytes != q.opts.MaxBytes || s.MaxItems != q.opts.MaxItems {
		return s, 0, ErrConflict
	}
	if len(s.Frames) > s.MaxItems || s.Cursor == 0 && s.LastDigest != "" || s.Cursor > 0 && !storage.ID(s.LastDigest) || s.Discarded == 0 && s.DiscardChain != "" || s.Discarded > 0 && !storage.ID(s.DiscardChain) {
		return s, 0, ErrInvalid
	}
	var previous uint64
	for _, f := range s.Frames {
		if f.Position <= previous || f.Position > s.Cursor || f.Next < 0 || f.Next >= len(f.Messages) || f.NotBefore < 0 || !member(f.Blocked, "", "PARTIAL_REJECTION", "PERMANENT_REJECTION", "INVALID_RESPONSE") {
			return s, 0, ErrInvalid
		}
		previous = f.Position
		expected, e := Encode(q.node, s.Domain, f.Record)
		a, _ := json.Marshal(expected)
		b, _ := json.Marshal(f.Messages)
		if e != nil || !bytes.Equal(a, b) {
			return s, 0, ErrInvalid
		}
	}
	return s, len(raw), nil
}
func (q *Outbox) save(s journal) error {
	s.Signature = nil
	raw, e := json.Marshal(s)
	if e != nil {
		return ErrInvalid
	}
	s.Signature = ed25519.Sign(q.opts.Signer, append([]byte(Format+"\x00"), raw...))
	raw, e = json.Marshal(s)
	if e != nil {
		return ErrInvalid
	}
	if len(raw) > q.opts.MaxBytes {
		return ErrCapacity
	}
	return errors.Join(q.store.Write("queue.json", raw), q.check(context.Background()))
}

// Keep journal space for attempt/deadline/rejection and outcome counters when
// the record limit is reached. This is logical headroom, not a promise of free
// physical space under pressure from other telemetry writers or the host.
func (q *Outbox) saveAdmission(s journal) error {
	s.Signature = make([]byte, ed25519.SignatureSize)
	raw, e := json.Marshal(s)
	if e != nil {
		return ErrInvalid
	}
	if len(raw) > q.opts.MaxBytes-1024 {
		return ErrCapacity
	}
	return q.save(s)
}
func (q *Outbox) transaction(ctx context.Context, fn func(*journal) error) error {
	if e := q.check(ctx); e != nil {
		return e
	}
	return q.store.WithLock(ctx, func() error {
		if e := q.check(ctx); e != nil {
			return e
		}
		s, _, e := q.load()
		if e != nil {
			return e
		}
		return fn(&s)
	})
}

// Enqueue atomically commits the typed source position and immutable requests.
// Only the latest source position is an idempotent retry; gaps and rewinds fail.
func (q *Outbox) Enqueue(ctx context.Context, position uint64, r Record) error {
	messages, e := Encode(q.node, q.opts.Domain, r)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(r)
	digest := storage.Hash(raw)
	return q.transaction(ctx, func(s *journal) error {
		if e := q.authorize(ctx, *s); e != nil {
			return e
		}
		if position == s.Cursor && position > 0 {
			if digest == s.LastDigest {
				return nil
			}
			return ErrConflict
		}
		if s.Cursor == math.MaxUint64 || position != s.Cursor+1 || r.ObservedUnix > time.Now().Unix() {
			return ErrConflict
		}
		if len(s.Frames) >= s.MaxItems {
			return ErrCapacity
		}
		s.Cursor = position
		s.LastDigest = digest
		s.Frames = append(s.Frames, frame{Position: position, Record: r, Messages: messages})
		if e := q.saveAdmission(*s); e != nil {
			return e
		}
		return q.point("enqueued")
	})
}
func (q *Outbox) Status(ctx context.Context) (Status, error) {
	var out Status
	e := q.transaction(ctx, func(s *journal) error {
		raw, _ := json.Marshal(s)
		out = Status{Cursor: s.Cursor, Pending: len(s.Frames), Bytes: len(raw), Accepted: s.Accepted, Discarded: s.Discarded, DiscardChain: s.DiscardChain}
		out.NextSample = s.NextSample
		out.Warnings = s.Warnings
		if len(s.Enrollment) > 0 {
			g, e := q.grant(s.Enrollment)
			if e != nil {
				return e
			}
			out.EnrollmentRevision = g.Revision
			out.EnrollmentActive = g.Active(time.Now())
		}
		if len(s.Frames) > 0 {
			f := s.Frames[0]
			m := f.Messages[f.Next]
			out.Position = f.Position
			out.Digest = m.Digest
			out.Signal = m.Signal
			out.Attempts = f.Attempts
			out.NotBefore = f.NotBefore
			out.Blocked = f.Blocked
			out.Rejected = f.Rejected
		}
		return nil
	})
	return out, e
}

// DiscardBlocked is a separate explicit local operator decision. It requires the
// exact current request digest and retains a signed cumulative discard chain.
// It must never be invoked by a scheduler or on ordinary retryable failures.
func (q *Outbox) DiscardBlocked(ctx context.Context, digest string) error {
	if !storage.ID(digest) {
		return ErrInvalid
	}
	return q.delivery.WithLock(ctx, func() error {
		return q.transaction(ctx, func(s *journal) error {
			if len(s.Frames) == 0 {
				return ErrConflict
			}
			f := &s.Frames[0]
			if f.Blocked == "" || f.Messages[f.Next].Digest != digest || s.Discarded == math.MaxUint64 {
				return ErrConflict
			}
			s.Discarded++
			s.DiscardChain = storage.Hash([]byte(s.DiscardChain + "/" + digest + "/" + f.Blocked))
			advance(s)
			return q.save(*s)
		})
	})
}
func advance(s *journal) {
	f := &s.Frames[0]
	f.Next++
	f.Attempts = 0
	f.NotBefore = 0
	f.Blocked = ""
	f.Rejected = 0
	if f.Next == len(f.Messages) {
		s.Frames = s.Frames[1:]
	}
}
