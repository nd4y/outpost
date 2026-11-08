package telemetry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

type sendFunc func(context.Context, Message) Outcome

func (f sendFunc) Send(ctx context.Context, m Message) Outcome { return f(ctx, m) }
func fixtureOptions(dir string) Options {
	return Options{Directory: dir, Signer: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32)), Target: storage.Hash([]byte("sink")), Domain: storage.Hash([]byte("domain")), Binding: storage.Hash([]byte("private-profile")), MaxBytes: 64 << 10, MaxItems: 4, Initialize: true}
}
func fixtureRecord() Record {
	return Record{ObservedUnix: time.Now().Unix() - 10, Events: []Event{{Kind: "STATE_CHANGED", State: "COMPLETE"}}}
}
func fixtureOpen(t *testing.T, o Options) *Outbox {
	t.Helper()
	q, e := Open(o)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { q.Close() })
	return q
}
func due(t *testing.T, q *Outbox) {
	t.Helper()
	e := q.transaction(context.Background(), func(s *journal) error { s.Frames[0].NotBefore = 0; return q.save(*s) })
	if e != nil {
		t.Fatal(e)
	}
}

func TestTelemetryTypedPayloadPrivacyAndUnknown(t *testing.T) {
	r := fixtureRecord()
	zero := int64(0)
	r.Metrics = []Metric{{Name: "space_free_bytes"}, {Name: "jobs_running", Value: &zero}}
	m, e := Encode(storage.Hash([]byte("node")), storage.Hash([]byte("domain")), r)
	if e != nil || len(m) != 2 {
		t.Fatal(e, m)
	}
	if bytes.Contains(m[0].Body, []byte(`"name":"outpost_space_free_bytes"`)) || !bytes.Contains(m[0].Body, []byte(`"name":"outpost_space_free_bytes_known"`)) {
		t.Fatal("unknown measurement fabricated")
	}
	if bytes.Contains(m[0].Body, []byte("outpost.operation")) {
		t.Fatal("unbounded metric label")
	}
	for _, mutate := range []func(*Record){func(r *Record) { r.Events[0].Kind = "secret-filename" }, func(r *Record) { r.Events[0].Code = "https://credential.invalid" }, func(r *Record) { r.Metrics[0].Name = "source_read_bytes_total" }, func(r *Record) { r.Events[0].Operation = "source-path" }, func(r *Record) { r.Metrics = append(r.Metrics, r.Metrics[0]) }} {
		raw, _ := json.Marshal(r)
		var bad Record
		json.Unmarshal(raw, &bad)
		mutate(&bad)
		if _, e := Encode(storage.Hash([]byte("node")), storage.Hash([]byte("domain")), bad); !errors.Is(e, ErrInvalid) {
			t.Fatal("unsafe record admitted", e)
		}
	}
}
func TestTelemetryJournalAtomicCursorQuotaAndRestart(t *testing.T) {
	ctx := context.Background()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	o.MaxItems = 1
	deny := false
	o.Admission = func(string, int) (func(bool) error, error) {
		if deny {
			return nil, statefile.ErrCapacity
		}
		return func(bool) error { return nil }, nil
	}
	q := fixtureOpen(t, o)
	r := fixtureRecord()
	deny = true
	if e := q.Enqueue(ctx, 1, r); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal(e)
	}
	s, _ := q.Status(ctx)
	if s.Cursor != 0 {
		t.Fatal("cursor advanced without admitted record")
	}
	deny = false
	if e := q.Enqueue(ctx, 1, r); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(o.Directory, "queue.json"))
	if e := q.Enqueue(ctx, 1, r); e != nil {
		t.Fatal(e)
	}
	changed := r
	changed.ObservedUnix--
	if !errors.Is(q.Enqueue(ctx, 1, changed), ErrConflict) {
		t.Fatal("position conflict")
	}
	if !errors.Is(q.Enqueue(ctx, 2, r), ErrCapacity) {
		t.Fatal("queue overflow")
	}
	after, _ := os.ReadFile(filepath.Join(o.Directory, "queue.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected enqueue changed journal")
	}
	o.Initialize = false
	q2 := fixtureOpen(t, o)
	s, e := q2.Status(ctx)
	if e != nil || s.Cursor != 1 || s.Pending != 1 {
		t.Fatal(s, e)
	}
	s, e = q2.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { return Outcome{State: "ACCEPTED"} }))
	if e != nil || s.Pending != 0 || s.Accepted != 1 {
		t.Fatal(s, e)
	}
	if e = q2.Enqueue(ctx, 1, r); e != nil {
		t.Fatal("acknowledged cursor retry", e)
	}
	if e = q2.Enqueue(ctx, 3, r); !errors.Is(e, ErrConflict) {
		t.Fatal("source gap accepted", e)
	}
}
func TestTelemetryUncertainAckAndExplicitRejection(t *testing.T) {
	ctx := context.Background()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	q := fixtureOpen(t, o)
	if e := q.Enqueue(ctx, 1, fixtureRecord()); e != nil {
		t.Fatal(e)
	}
	var first []byte
	q.Fault = func(p string) error {
		if p == "after-send" {
			return errors.New("interrupted")
		}
		return nil
	}
	_, e := q.Deliver(ctx, sendFunc(func(_ context.Context, m Message) Outcome {
		first = append([]byte(nil), m.Body...)
		return Outcome{State: "ACCEPTED"}
	}))
	if e == nil {
		t.Fatal("fault not injected")
	}
	o.Initialize = false
	q2 := fixtureOpen(t, o)
	s, _ := q2.Status(ctx)
	if s.Pending != 1 || s.Accepted != 0 || s.Attempts != 1 {
		t.Fatal(s)
	}
	due(t, q2)
	s, e = q2.Deliver(ctx, sendFunc(func(_ context.Context, m Message) Outcome {
		if !bytes.Equal(first, m.Body) {
			t.Fatal("retry body changed")
		}
		return Outcome{State: "BLOCKED", Code: "PARTIAL_REJECTION"}
	}))
	if e != nil || s.Blocked != "PARTIAL_REJECTION" || s.Accepted != 0 {
		t.Fatal(s, e)
	}
	var calls atomic.Int32
	_, e = q2.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { calls.Add(1); return Outcome{State: "ACCEPTED"} }))
	if !errors.Is(e, ErrBlocked) || calls.Load() != 0 {
		t.Fatal("partial retry", e)
	}
	if e = q2.DiscardBlocked(ctx, storage.Hash([]byte("wrong"))); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e = q2.DiscardBlocked(ctx, s.Digest); e != nil {
		t.Fatal(e)
	}
	s, _ = q2.Status(ctx)
	if s.Pending != 0 || s.Accepted != 0 || s.Discarded != 1 || !storage.ID(s.DiscardChain) {
		t.Fatal(s)
	}
}
func TestTelemetrySlowDeliveryDoesNotLockProducer(t *testing.T) {
	ctx := context.Background()
	q := fixtureOpen(t, fixtureOptions(filepath.Join(t.TempDir(), "queue")))
	q.Enqueue(ctx, 1, fixtureRecord())
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, e := q.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { close(started); <-release; return Outcome{State: "ACCEPTED"} }))
		done <- e
	}()
	<-started
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if e := q.Enqueue(short, 2, fixtureRecord()); e != nil {
		close(release)
		t.Fatal("network held journal lock", e)
	}
	_, e := q.Deliver(short, sendFunc(func(context.Context, Message) Outcome { t.Error("parallel sender"); return Outcome{State: "ACCEPTED"} }))
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Error(e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	s, _ := q.Status(ctx)
	if s.Cursor != 2 || s.Pending != 1 {
		t.Fatal(s)
	}
}
func TestTelemetrySignedBindingsCorruptionAndMissingState(t *testing.T) {
	ctx := context.Background()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	q := fixtureOpen(t, o)
	q.Enqueue(ctx, 1, fixtureRecord())
	o.Initialize = false
	wrong := o
	wrong.Binding = storage.Hash([]byte("new endpoint"))
	if other, e := Open(wrong); e == nil {
		other.Close()
		t.Fatal("sink rebind")
	}
	file := filepath.Join(o.Directory, "queue.json")
	raw, _ := os.ReadFile(file)
	raw = bytes.Replace(raw, []byte("COMPLETE"), []byte("WITHDRAWN"), 1)
	os.WriteFile(file, raw, 0600)
	if _, e := q.Status(ctx); !errors.Is(e, ErrInvalid) {
		t.Fatal("unsigned change admitted", e)
	}
	os.Remove(file)
	if other, e := Open(o); e == nil {
		other.Close()
		t.Fatal("lost queue silently initialized")
	}
	o.Initialize = true
	if other, e := Open(o); e == nil {
		other.Close()
		t.Fatal("existing directory reset")
	}
}
func TestTelemetryPersistedRetryGuardAndByteLimit(t *testing.T) {
	ctx := context.Background()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	blocked := false
	o.Guard = func(context.Context) error {
		if blocked {
			return ErrBlocked
		}
		return nil
	}
	q := fixtureOpen(t, o)
	q.Enqueue(ctx, 1, fixtureRecord())
	s, e := q.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { return Outcome{State: "RETRY_WAIT", RetryAfter: time.Hour} }))
	if e != nil || s.NotBefore < time.Now().Add(59*time.Minute).Unix() {
		t.Fatal(s, e)
	}
	o.Initialize = false
	q2 := fixtureOpen(t, o)
	_, e = q2.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { t.Fatal("persisted retry ignored"); return Outcome{} }))
	if e != nil {
		t.Fatal(e)
	}
	due(t, q2)
	blocked = true
	_, e = q2.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { t.Fatal("revoked guard sent data"); return Outcome{} }))
	if !errors.Is(e, ErrBlocked) {
		t.Fatal(e)
	}
	limited := fixtureOptions(filepath.Join(t.TempDir(), "small"))
	limited.MaxBytes = 4096
	small := fixtureOpen(t, limited)
	r := fixtureRecord()
	for range 50 {
		r.Events = append(r.Events, Event{Kind: "STATE_CHANGED", State: "COMPLETE", Operation: storage.Hash([]byte("operation"))})
	}
	if e = small.Enqueue(ctx, 1, r); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	s, _ = small.Status(ctx)
	if s.Cursor != 0 {
		t.Fatal(s)
	}
}

func TestTelemetryFullByteQueueRetainsOutcomeHeadroom(t *testing.T) {
	ctx := context.Background()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	o.MaxBytes = 8192
	o.MaxItems = 128
	q := fixtureOpen(t, o)
	accepted := uint64(0)
	for position := uint64(1); position < 128; position++ {
		e := q.Enqueue(ctx, position, fixtureRecord())
		if errors.Is(e, ErrCapacity) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		accepted = position
	}
	if accepted == 0 || accepted >= 127 {
		t.Fatal("byte boundary not exercised", accepted)
	}
	s, e := q.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome {
		return Outcome{State: "BLOCKED", Code: "PARTIAL_REJECTION", Rejected: 9223372036854775807}
	}))
	if e != nil || s.Cursor != accepted || s.Rejected != 9223372036854775807 || s.Blocked != "PARTIAL_REJECTION" {
		t.Fatal(s, e)
	}
}
