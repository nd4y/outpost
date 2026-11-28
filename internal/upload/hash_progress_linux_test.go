package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestCloudHashProgressRestartsAfterEveryActualPart(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureBytes(t, 512<<10)
			var mu sync.Mutex
			reads := map[string]int{}
			s := f.server(t, kind, 0, func(_ http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
				if r.Method == "GET" {
					mu.Lock()
					reads[key]++
					mu.Unlock()
				}
				return false
			})
			b := f.backend(t, s, 0)
			ctx := context.Background()
			dir := filepath.Join(f.base, "hash-journal")
			must(t, os.Mkdir(dir, 0700))
			j, e := Open(dir, f.plan(t, s, 1, 500), f.workers[0].ID, f.authority, true)
			must(t, e)
			defer j.Close()
			j.Readback.MaxAgeSeconds = 3600
			blob := j.plan.Blobs[0]
			for _, candidate := range j.plan.Blobs {
				if len(candidate.Parts) > len(blob.Parts) {
					blob = candidate
				}
			}
			if len(blob.Parts) < 4 {
				t.Fatal("fixture did not split")
			}
			data, e := f.replicas[0].ReadObject(ctx, f.id, blob.Object)
			must(t, e)
			offset := 0
			for _, part := range blob.Parts {
				must(t, b.PutPart(ctx, part, data[offset:offset+part.Bytes]))
				offset += part.Bytes
			}
			// PutPart performs its own durable-write readback. Measure the
			// subsequent independently resumable whole-object verification only.
			mu.Lock()
			reads = map[string]int{}
			mu.Unlock()
			var first int64
			for i := 0; i < len(blob.Parts); i++ {
				a, e := j.newAudit(ctx, b)
				must(t, e)
				a.afterPart = func() error { return context.Canceled }
				if e = a.verify(ctx, blob.Object.ID, true); !errors.Is(e, context.Canceled) {
					t.Fatal("did not stop after durable prefix", i, e)
				}
				p, e := a.hashWindow(blob.Object.ID).load()
				must(t, e)
				if p.Next != i+1 || p.Sealed {
					t.Fatal("wrong checkpoint", p.Next, p.Sealed)
				}
				if i == 0 {
					first = p.ObservedUnix
					time.Sleep(1100 * time.Millisecond)
				}
				if p.ObservedUnix != first {
					t.Fatal("prefix age replaced")
				}
				a.close()
			}
			a, e := j.newAudit(ctx, b)
			must(t, e)
			defer a.close()
			must(t, a.verify(ctx, blob.Object.ID, true))
			proof := a.proofs[blob.Object.ID]
			if !proof.Reused || proof.ObservedUnix != first || proof.Bytes != blob.Object.Bytes {
				t.Fatal("resumed read claimed freshness", proof)
			}
			mu.Lock()
			for _, part := range blob.Parts {
				if reads["part-"+part.ID] != 1 {
					t.Error("part reread across restart", reads["part-"+part.ID])
				}
			}
			mu.Unlock()
			restored, e := b.ReadBlob(ctx, blob.Object)
			must(t, e)
			if !bytes.Equal(restored, data) {
				t.Fatal("independent full read differs")
			}
			// The private checkpoint is hash state, not a second copy of ciphertext.
			raw, e := a.cache.Store.Read(a.hashWindow(blob.Object.ID).name())
			must(t, e)
			if len(raw) > 4096 {
				t.Fatal("unbounded hash checkpoint")
			}
			// Explicit invalidation after cancellation must also fence completed state.
			stopped, cancel := context.WithCancel(ctx)
			cancel()
			must(t, a.invalidate(stopped, blob.Object.ID))
			must(t, os.Remove(s.Path("part-"+blob.Parts[0].ID)))
			if e = a.verify(ctx, blob.Object.ID, false); !storage.Missing(e) {
				t.Fatal("invalidated full prefix hid missing bytes", e)
			}
		})
	}
}

func hashFixture(t *testing.T) (hashWindow, []byte) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	store, e := statefile.Open(dir, readback.MaxPage, true)
	must(t, e)
	t.Cleanup(func() { store.Close() })
	data := append(bytes.Repeat([]byte{13}, 64<<10), bytes.Repeat([]byte{29}, 64<<10)...)
	blob, e := storage.Describe(generation.Object{ID: storage.Hash(data), Bytes: len(data)}, data, 64<<10)
	must(t, e)
	return hashWindow{store: store, scope: storage.Hash([]byte("test-window")), blob: blob, maxAge: 3600}, data
}
func prefix(t *testing.T, w hashWindow, data []byte, count int) hashProgress {
	t.Helper()
	p, e := w.empty(1)
	must(t, e)
	h := sha256.New()
	for _, part := range w.blob.Parts[:count] {
		p.Bytes += part.Bytes
	}
	_, e = h.Write(data[:p.Bytes])
	must(t, e)
	p.State, e = marshalHash(h)
	must(t, e)
	p.StateHash = storage.Hash(p.State)
	p.Next = count
	if count > 0 {
		p.ObservedUnix = time.Now().Add(-2 * time.Second).Unix()
	}
	return p
}
func TestCloudHashProgressCorruptionIsPreserved(t *testing.T) {
	for _, mutation := range []string{"state", "bytes", "scope", "future", "unknown", "final-digest"} {
		t.Run(mutation, func(t *testing.T) {
			w, data := hashFixture(t)
			p := prefix(t, w, data, 1)
			switch mutation {
			case "state":
				p.State[10] ^= 1
			case "bytes":
				p.Bytes++
			case "scope":
				p.Scope = storage.Hash([]byte("another-window"))
			case "future":
				p.ObservedUnix = time.Now().Add(time.Hour).Unix()
			case "unknown":
				p.Format = "unknown"
			case "final-digest":
				p = prefix(t, w, bytes.Repeat([]byte{5}, len(data)), 2)
			}
			raw, e := json.Marshal(p)
			must(t, e)
			must(t, w.store.Write(w.name(), raw))
			if _, e = w.start(context.Background(), false); e == nil {
				t.Fatal("corrupt progress accepted")
			}
			kept, e := w.store.Read(w.name())
			must(t, e)
			if !bytes.Equal(kept, raw) {
				t.Fatal("corrupt progress overwritten")
			}
		})
	}
}
func TestCloudHashProgressEpochFencesStaleCommitAndReceipt(t *testing.T) {
	w, data := hashFixture(t)
	ctx := context.Background()
	p := prefix(t, w, data, 1)
	_, e := w.commit(ctx, p)
	must(t, e)
	full := prefix(t, w, data, 2)
	must(t, w.store.WithLock(ctx, func() error { return w.resetLocked(true) }))
	if _, e = w.commit(ctx, full); !errors.Is(e, ErrConflict) {
		t.Fatal("stale writer resurrected prefix", e)
	}
	if e = w.store.WithLock(ctx, func() error { return w.sealLocked(full) }); !errors.Is(e, ErrConflict) {
		t.Fatal("stale receipt accepted", e)
	}
	reset, e := w.start(ctx, false)
	must(t, e)
	if reset.Next != 0 || reset.Epoch != 2 {
		t.Fatal("reset not durable")
	}
	// Expired and previously sealed prefixes cannot resurrect absent evidence.
	p.Epoch = 2
	p.ObservedUnix = time.Now().Add(-2 * time.Hour).Unix()
	must(t, w.write(p))
	reset, e = w.start(ctx, false)
	must(t, e)
	if reset.Next != 0 || reset.Epoch != 3 {
		t.Fatal("expired prefix retained")
	}
	full.Epoch = 3
	full.Sealed = true
	full.DescriptorSeen = true
	must(t, w.write(full))
	reset, e = w.start(ctx, false)
	must(t, e)
	if reset.Next != 0 || reset.Epoch != 4 {
		t.Fatal("sealed prefix resurrected")
	}
	// Advancing writers cannot be replaced by a stale shorter prefix.
	full.Epoch = 4
	full.Sealed = false
	_, e = w.commit(ctx, full)
	must(t, e)
	p = prefix(t, w, data, 1)
	p.Epoch = 4
	got, e := w.commit(ctx, p)
	must(t, e)
	if got.Next != 2 {
		t.Fatal("progress regressed")
	}
	must(t, w.store.WithLock(ctx, func() error { return w.resetLocked(true) }))
	w.store.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	p.Epoch = 5
	if _, e = w.commit(ctx, p); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("quota bypassed", e)
	}
}
