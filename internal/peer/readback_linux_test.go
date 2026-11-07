package peer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
)

type payloadCounter struct {
	http.ResponseWriter
	bytes *atomic.Int64
}

func (w payloadCounter) Write(b []byte) (int, error) {
	n, e := w.ResponseWriter.Write(b)
	w.bytes.Add(int64(n))
	return n, e
}

func TestExplicitReadbackReuseTransfersOnlyNewObjectsAndPreservesAge(t *testing.T) {
	f := newFixture(t)
	f.old = make([]byte, 16<<20)
	_, e := rand.Read(f.old)
	must(t, e)
	must(t, os.WriteFile(f.input, f.old, 0640))
	first, v1 := f.seal(t, 1, "")
	var responseBytes atomic.Int64
	s := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/objects/") {
				w = payloadCounter{w, &responseBytes}
			}
			next.ServeHTTP(w, r)
		})
	})
	p := f.policy(f.b, f.a)
	p.ReadbackMaxAgeSeconds = 3600
	c := f.client(t, f.b, f.a, s.URL, p)
	one, e := c.Push(testContext, generation.Hash([]byte("first")), first, f.b.replica)
	must(t, e)
	if one.CachedObjects != 0 || one.Receipt.Verification != "client-full-readback" || responseBytes.Load() < int64(len(f.old)) {
		t.Fatal("initial transfer did not independently read payload", one)
	}
	raw, e := f.b.replica.Catalog(testContext, first)
	must(t, e)
	oldRefs, e := generation.Dependencies(raw, f.trust)
	must(t, e)
	seen := map[string]bool{}
	for _, r := range oldRefs {
		seen[r.ID] = true
	}
	c.Close()
	must(t, f.b.journal.Close())
	f.b.journal, e = OpenJournal(filepath.Join(f.b.dir, "journal"), f.b.id, f.trust, false)
	must(t, e)
	c = f.client(t, f.b, f.a, s.URL, p)
	time.Sleep(1100 * time.Millisecond)
	responseBytes.Store(0)
	repeated, e := c.Push(testContext, generation.Hash([]byte("repeat")), first, f.b.replica)
	must(t, e)
	if repeated.CachedObjects != len(oldRefs) || responseBytes.Load() != 0 || repeated.Counters.ObjectBytesSubmitted != 0 || repeated.Counters.ReadbackBytes != int64(len(raw)) || repeated.Receipt.Format != CachedReceiptFormat || repeated.Receipt.ObservedUnix > one.Receipt.ObservedUnix || repeated.Receipt.ObservedUnix >= repeated.TargetReceipt.ObservedUnix {
		t.Fatal("repeat invented fresh evidence or reread payload", repeated, responseBytes.Load())
	}
	changed := append([]byte(nil), f.old...)
	copy(changed[10000:18000], bytes.Repeat([]byte{73}, 8000))
	must(t, os.WriteFile(f.input, changed, 0640))
	envelope, _, e := f.source.LoadVersionContext(testContext, v1)
	must(t, e)
	version, e := f.source.Backup(testContext, f.input, filekit.BackupOptions{File: envelope.File, Previous: v1, Names: []string{"private.bin", "alias.bin"}})
	must(t, e)
	v2 := version.Version
	second, e := generation.Seal(testContext, f.source, []string{v2}, f.b.replica, generation.Catalog{Format: generation.Format, Domain: f.trust.Domain, Repository: f.trust.Repository, Epoch: 1, Sequence: 2, Parent: first, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, f.writer)
	must(t, e)
	nextRaw, e := f.b.replica.Catalog(testContext, second)
	must(t, e)
	refs, e := generation.Dependencies(nextRaw, f.trust)
	must(t, e)
	var newBytes int64
	reused := 0
	for _, r := range refs {
		if seen[r.ID] {
			reused++
		} else {
			newBytes += int64(r.Bytes)
		}
	}
	if reused == 0 || newBytes == 0 {
		t.Fatal("fixture did not exercise changed and retained objects")
	}
	responseBytes.Store(0)
	two, e := c.Push(testContext, generation.Hash([]byte("second")), second, f.b.replica)
	must(t, e)
	if two.CachedObjects != reused || responseBytes.Load() != newBytes || two.Counters.ObjectBytesSubmitted != newBytes || two.Counters.ReadbackBytes != newBytes+int64(len(nextRaw)) {
		t.Fatal("changed-generation payload amplification", two, responseBytes.Load(), newBytes)
	}
	responseBytes.Store(0)
	fresh := p
	fresh.ReadbackMaxAgeSeconds = 0
	audit := f.client(t, f.b, f.a, s.URL, fresh)
	result, e := audit.Push(testContext, generation.Hash([]byte("fresh audit")), second, f.b.replica)
	must(t, e)
	if result.CachedObjects != 0 || result.Receipt.Verification != "client-full-readback" || responseBytes.Load() <= newBytes {
		t.Fatal("fresh-only policy reused evidence")
	}
	must(t, os.Remove(f.input))
	must(t, f.source.Close())
	must(t, f.b.replica.Close())
	s.Close()
	restore(t, f, f.a, first, v1, f.old)
	restore(t, f, f.a, second, v2, changed)
	t.Logf("synthetic16MiB change: new object payload=%d, peer response payload=%d plus catalog=%d; excludes protocol overhead", newBytes, two.Counters.ReadbackBytes-int64(len(nextRaw)), len(nextRaw))
}

func TestMalformedReadbackCacheFailsClosedWithoutReplacingEvidence(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	s := f.endpoint(t, f.a, f.policy(f.a, f.b), nil)
	p := f.policy(f.b, f.a)
	p.ReadbackMaxAgeSeconds = 60
	c := f.client(t, f.b, f.a, s.URL, p)
	_, e := c.Push(testContext, generation.Hash([]byte("initial")), id, f.b.replica)
	must(t, e)
	raw, e := f.b.replica.Catalog(testContext, id)
	must(t, e)
	refs, e := generation.Dependencies(raw, f.trust)
	must(t, e)
	path := filepath.Join(f.b.dir, "journal", "readback-"+c.readbackScope()+"-"+refs[0].ID[:2]+".json")
	must(t, os.WriteFile(path, []byte("{}"), 0600))
	if _, e = c.Push(testContext, generation.Hash([]byte("bad cache")), id, f.b.replica); !errors.Is(e, readback.ErrInvalid) {
		t.Fatal("malformed evidence silently ignored", e)
	}
	got, e := os.ReadFile(path)
	must(t, e)
	if string(got) != "{}" {
		t.Fatal("malformed evidence overwritten")
	}
	must(t, f.a.replica.VerifyComplete(testContext, id))
}
