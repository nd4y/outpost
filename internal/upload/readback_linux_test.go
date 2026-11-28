package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestCloudReadbackReusePreservesAgeAndReadsOnlyChangedObjects(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureBytes(t, 16<<20)
			ctx := context.Background()
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
			cacheDir := filepath.Join(f.base, "readback")
			cache, e := statefile.Open(cacheDir, readback.MaxPage, true)
			must(t, e)
			defer func() { cache.Close() }()
			q, dir := queueFor(t, f, queueLimits())
			q.Readback = ReadbackOptions{Store: cache, MaxAgeSeconds: 3600}
			run := func(raw []byte) Receipt {
				started := time.Now()
				must(t, q.Enqueue(ctx, f.replicas[0], raw))
				bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				if e := q.Run(bounded, f.replicas[0], f.resolve(t, s), f.keys[0]); e != nil {
					state, se := q.Status(ctx)
					must(t, se)
					job := state.Jobs[planOperation(t, raw, f.authority)]
					j, se := q.journal(job, false)
					must(t, se)
					journalState, se := j.Status(ctx)
					must(t, se)
					complete := 0
					for _, part := range journalState.Parts {
						if part.Complete {
							complete++
						}
					}
					a, se := j.newAudit(ctx, f.backend(t, s, 0))
					must(t, se)
					proofs := 0
					if a != nil {
						proofs = len(a.proofs)
						a.close()
					}
					j.Close()
					t.Fatalf("cloud operation failed: %v, attempts=%d phase=%s error=%s completeParts=%d recordedParts=%d objectProofs=%d", e, job.Attempts, job.Phase, job.ErrorCode, complete, len(journalState.Parts), proofs)
				}
				state, e := q.Status(ctx)
				must(t, e)
				t.Logf("operation finished in %s", time.Since(started))
				return *state.Jobs[planOperation(t, raw, f.authority)].Receipt
			}
			raw := f.plan(t, s, 1, 500)
			raw = changePlan(t, f, raw, func(p *Plan) { p.ExpiresUnix = time.Now().Add(5 * time.Minute).Unix() })
			p, e := Verify(raw, f.authority)
			must(t, e)
			first := run(raw)
			initialState, e := q.Status(ctx)
			must(t, e)
			attempts := initialState.Jobs[p.Operation].Attempts
			if !validVerification(first.Verification) || first.Verification == "cached-target-readback" && attempts < 2 {
				t.Fatal("cache evidence without an earlier attempt", first, attempts)
			}
			t.Logf("initial upload completed in %d bounded attempts with %s", attempts, first.Verification)
			must(t, q.Close())
			must(t, cache.Close())
			cache, e = statefile.Open(cacheDir, readback.MaxPage, false)
			must(t, e)
			q, e = OpenQueue(dir, f.workers[0].ID, f.authority, queueLimits(), false)
			must(t, e)
			defer q.Close()
			q.Readback = ReadbackOptions{Store: cache, MaxAgeSeconds: 3600}
			time.Sleep(1100 * time.Millisecond)
			mu.Lock()
			reads = map[string]int{}
			mu.Unlock()
			repeat := run(changePlan(t, f, raw, func(p *Plan) { p.Operation = storage.Hash([]byte("repeat")) }))
			if repeat.Verification != "cached-target-readback" || repeat.ObservedUnix != first.ObservedUnix || repeat.ObservedUnix >= time.Now().Unix() {
				t.Fatal("cache invented fresh evidence", repeat, first)
			}
			mu.Lock()
			for _, blob := range p.Blobs {
				for _, part := range blob.Parts {
					if reads["part-"+part.ID] != 0 {
						t.Error("unchanged payload reread", part.ID)
					}
				}
			}
			mu.Unlock()
			// A fresh full scan deliberately cannot use saved object evidence.
			// Give that distinct operation a budget for its complete scan; the
			// cached upload still retries with the original 4s attempt limit.
			cachedQueue := q
			freshLimits := queueLimits()
			freshLimits.AttemptMillis = 30000
			q, _ = queueFor(t, f, freshLimits)
			fresh := run(changePlan(t, f, raw, func(p *Plan) { p.Operation = storage.Hash([]byte("fresh-only")) }))
			if fresh.Verification != "full-target-readback" || fresh.ObservedUnix <= repeat.ObservedUnix {
				t.Fatal("fresh policy not applied", fresh)
			}
			q = cachedQueue
			oldID, oldVersion := f.id, f.version
			changed := bytes.Clone(f.data)
			copy(changed[10000:18000], bytes.Repeat([]byte{73}, 8000))
			must(t, os.WriteFile(f.input, changed, 0640))
			envelope, _, e := f.store.LoadVersionContext(ctx, oldVersion)
			must(t, e)
			v, e := f.store.Backup(ctx, f.input, filekit.BackupOptions{File: envelope.File, Previous: oldVersion, Names: []string{"do-not-export-private-name.bin", "alias.bin"}})
			must(t, e)
			f.id, e = generation.Seal(ctx, f.store, []string{v.Version}, f.replicas[0], generation.Catalog{Format: generation.Format, Domain: f.authority.Generation.Domain, Repository: f.authority.Generation.Repository, Epoch: 1, Sequence: 2, Parent: oldID, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, f.writer)
			must(t, e)
			nextRaw := f.plan(t, s, 1, 500)
			next, e := Verify(nextRaw, f.authority)
			must(t, e)
			// The oldest original object may itself have changed. The new
			// receipt uses the oldest evidence among dependencies actually retained.
			must(t, q.Enqueue(ctx, f.replicas[0], nextRaw))
			pending, e := q.Status(ctx)
			must(t, e)
			journal, e := q.journal(pending.Jobs[next.Operation], false)
			must(t, e)
			audit, e := journal.newAudit(ctx, f.backend(t, s, 0))
			must(t, e)
			expectedAge := time.Now().Unix()
			if len(audit.proofs) == 0 {
				t.Fatal("new generation retained no cached evidence")
			}
			for _, proof := range audit.proofs {
				expectedAge = min(expectedAge, proof.ObservedUnix)
			}
			audit.close()
			must(t, journal.Close())
			old := map[string]bool{}
			for _, blob := range p.Blobs {
				old[blob.Object.ID] = true
			}
			mu.Lock()
			reads = map[string]int{}
			mu.Unlock()
			delta := run(nextRaw)
			if delta.Verification != "cached-target-readback" || delta.ObservedUnix != expectedAge {
				t.Fatal("delta lost old evidence age", delta)
			}
			reused, newBytes := 0, 0
			mu.Lock()
			for _, blob := range next.Blobs {
				if old[blob.Object.ID] {
					reused++
					for _, part := range blob.Parts {
						if reads["part-"+part.ID] != 0 {
							t.Error("delta reread unchanged blob")
						}
					}
				} else {
					newBytes += blob.Object.Bytes
				}
			}
			mu.Unlock()
			if reused == 0 || newBytes == 0 {
				t.Fatal("fixture lacked real delta")
			}
			t.Logf("%s: reused %d objects; new object closure %d bytes after 8000-byte edit", kind, reused, newBytes)
			for _, r := range f.replicas {
				must(t, r.Close())
			}
			for _, d := range f.dirs {
				must(t, os.RemoveAll(d))
			}
			must(t, f.store.Close())
			must(t, os.RemoveAll(filepath.Join(f.base, "source-store")))
			must(t, os.Remove(f.input))
			recoverBytes(t, f, s, oldID, oldVersion, f.data)
			recoverBytes(t, f, s, f.id, v.Version, changed)
		})
	}
}

func TestCloudReadbackRestartDescriptorBindingAndMissingDataInvalidation(t *testing.T) {
	f := newFixture(t)
	s := f.server(t, "webdav", 0, nil)
	raw := f.plan(t, s, 1, 500)
	dir := filepath.Join(f.base, "journal")
	must(t, os.Mkdir(dir, 0700))
	j, e := Open(dir, raw, f.workers[0].ID, f.authority, true)
	must(t, e)
	defer j.Close()
	b := f.backend(t, s, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, e = j.Run(ctx, f.replicas[0], b, f.keys[0])
	must(t, e)
	j.Readback.MaxAgeSeconds = 3600
	a, e := j.newAudit(ctx, b)
	must(t, e)
	blob := j.plan.Blobs[0]
	must(t, a.verify(ctx, blob.Object.ID, false))
	first := a.proofs[blob.Object.ID]
	stopped, stop := context.WithCancel(ctx)
	stop()
	if e = a.verify(stopped, j.plan.Blobs[len(j.plan.Blobs)-1].Object.ID, false); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled audit proceeded", e)
	}
	a.close()
	a, e = j.newAudit(ctx, b)
	must(t, e)
	defer a.close()
	if !a.proofs[blob.Object.ID].Reused || a.proofs[blob.Object.ID].Record != first.Record {
		t.Fatal("successful bounded audit lost across restart")
	}
	must(t, a.verify(ctx, blob.Object.ID, false))
	descriptorPath := s.Path("blob-" + blob.Object.ID)
	original, e := os.ReadFile(descriptorPath)
	must(t, e)
	bad := blob
	bad.Parts = append([]generation.Object(nil), blob.Parts...)
	bad.Parts[0].ID = storage.Hash([]byte("forged physical map"))
	forged, e := json.Marshal(bad)
	must(t, e)
	must(t, os.WriteFile(descriptorPath, forged, 0600))
	if e = a.verify(ctx, blob.Object.ID, false); !errors.Is(e, storage.ErrConflict) {
		t.Fatal("cached evidence accepted altered descriptor", e)
	}
	got, e := a.cache.Lookup(ctx, []generation.Object{a.keys[blob.Object.ID]}, time.Now(), 3600)
	must(t, e)
	if len(got) != 0 {
		t.Fatal("observed conflict retained evidence")
	}
	must(t, os.WriteFile(descriptorPath, original, 0600))
	must(t, a.verify(ctx, blob.Object.ID, false))
	must(t, a.invalidate(stopped, blob.Object.ID))
	got, e = a.cache.Lookup(ctx, []generation.Object{a.keys[blob.Object.ID]}, time.Now(), 3600)
	must(t, e)
	if len(got) != 0 {
		t.Fatal("cancelled request left known-invalid evidence")
	}
	must(t, a.verify(ctx, blob.Object.ID, false))
	// A missing descriptor invalidates even a valid previous payload proof.
	must(t, os.Remove(descriptorPath))
	must(t, os.Remove(s.Path("part-"+blob.Parts[0].ID)))
	if e = a.verify(ctx, blob.Object.ID, true); !storage.Missing(e) {
		t.Fatal("lost descriptor bypassed missing payload", e)
	}
	got, e = a.cache.Lookup(ctx, []generation.Object{a.keys[blob.Object.ID]}, time.Now(), 3600)
	must(t, e)
	if len(got) != 0 {
		t.Fatal("known loss retained cache evidence")
	}
	if _, e = os.Stat(descriptorPath); !os.IsNotExist(e) {
		t.Fatal("incomplete blob resealed")
	}
	// Failure during an actual recovery must never use the uploader's cache.
	if _, e = b.ReadBlob(ctx, blob.Object); !storage.Missing(e) {
		t.Fatal("restore trusted cached proof", e)
	}
	must(t, os.WriteFile(descriptorPath, original, 0600))
	ref := a.keys[blob.Object.ID]
	must(t, a.cache.Remember(ctx, map[string]readback.Record{ref.ID: {Bytes: ref.Bytes, ObservedUnix: time.Now().Add(-5 * time.Second).Unix()}}, time.Now()))
	j.Readback.MaxAgeSeconds = 1
	expired, e := j.newAudit(ctx, b)
	must(t, e)
	if e = expired.verify(ctx, blob.Object.ID, false); !storage.Missing(e) {
		t.Fatal("expired evidence hid missing payload", e)
	}
	expired.close()
	current, e := j.newAudit(ctx, b)
	must(t, e)
	ref = current.keys[blob.Object.ID]
	current.close()
	page := filepath.Join(dir, "readback-"+a.cache.Scope+"-"+ref.ID[:2]+".json")
	must(t, os.WriteFile(page, []byte("{}"), 0600))
	if _, e = j.newAudit(ctx, b); !errors.Is(e, readback.ErrInvalid) {
		t.Fatal("malformed cloud evidence ignored", e)
	}
	kept, e := os.ReadFile(page)
	must(t, e)
	if string(kept) != "{}" {
		t.Fatal("corrupt evidence overwritten")
	}
}
