package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestMultipartPlanningResumesAfterDurableObjectWithoutRereadingIt(t *testing.T) {
	f := newFixture(t)
	target := f.server(t, "webdav", 0, nil)
	d := Delegation{Format: DelegationFormat, Trust: f.authority.Generation, Epoch: 1, Profile: profile(target), AllowedClasses: []string{"trusted"}, Workers: f.workers, StartMillis: time.Now().Add(-time.Second).UnixMilli(), ExpiresUnix: time.Now().Add(time.Minute).Unix(), SlotMillis: 1000}
	grant, e := SignDelegation(d, f.planner)
	must(t, e)
	ctx := context.Background()
	expected, e := BuildDerived(ctx, f.replicas[1], f.id, grant, f.authority)
	must(t, e)
	dir := filepath.Join(f.base, "planning-state")
	store, e := statefile.Open(dir, maxPlanningPage, true)
	must(t, e)
	cancelled, cancel := context.WithCancel(ctx)
	cache := &PlanningCache{Store: store, Fault: func(string) error { cancel(); return context.Canceled }}
	if _, e = BuildDerivedCached(cancelled, f.replicas[0], f.id, grant, f.authority, cache); !errors.Is(e, context.Canceled) {
		t.Fatal("attempt did not stop at saved object", e)
	}
	entries, e := os.ReadDir(dir)
	must(t, e)
	var pagePath string
	var page planningPage
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "upload-parts-") {
			if pagePath != "" {
				t.Fatal("unbounded progress after cancellation")
			}
			pagePath = filepath.Join(dir, entry.Name())
			raw, e := os.ReadFile(pagePath)
			must(t, e)
			must(t, storage.Decode(raw, &page, maxPlanningPage))
		}
	}
	if pagePath == "" || len(page.Objects) != 1 {
		t.Fatal("no exact object checkpoint")
	}
	must(t, store.Close())
	missing := page.Objects[0].Blob.Object
	must(t, os.Remove(filepath.Join(f.dirs[0], "objects", missing.ID)))
	if _, e = BuildDerived(ctx, f.replicas[0], f.id, grant, f.authority); e == nil {
		t.Fatal("fixture missing object not exercised")
	}
	store, e = statefile.Open(dir, maxPlanningPage, false)
	must(t, e)
	defer store.Close()
	cache = &PlanningCache{Store: store}
	resumed, e := BuildDerivedCached(ctx, f.replicas[0], f.id, grant, f.authority, cache)
	must(t, e)
	if !bytes.Equal(resumed, expected) {
		t.Fatal("resumed deterministic plan changed")
	}
	// A new planner grant cannot borrow metadata from another operation's page.
	d.Epoch++
	changed, e := SignDelegation(d, f.planner)
	must(t, e)
	if _, e = BuildDerivedCached(ctx, f.replicas[0], f.id, changed, f.authority, cache); e == nil {
		t.Fatal("changed grant reused old operation cache")
	}
	before, e := os.ReadFile(pagePath)
	must(t, e)
	must(t, os.WriteFile(pagePath, []byte("{}"), 0600))
	if _, e = BuildDerivedCached(ctx, f.replicas[1], f.id, grant, f.authority, cache); !errors.Is(e, ErrConflict) {
		t.Fatal("corruption silently rebuilt", e)
	}
	kept, e := os.ReadFile(pagePath)
	must(t, e)
	if string(kept) != "{}" {
		t.Fatal("corrupt evidence overwritten")
	}
	// A valid JSON page with a different signed reference also fails closed.
	must(t, json.Unmarshal(before, &page))
	page.Objects[0].Blob.Object.ID = storage.Hash([]byte("wrong object"))
	bad, e := json.Marshal(page)
	must(t, e)
	must(t, os.WriteFile(pagePath, bad, 0600))
	if _, e = BuildDerivedCached(ctx, f.replicas[1], f.id, grant, f.authority, cache); !errors.Is(e, ErrConflict) {
		t.Fatal("reference substitution accepted", e)
	}
}

func TestPlanningPagesEnforceQuotaAndRejectOversizedPlanBeforePayload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "planning-state")
	store, e := statefile.Open(dir, maxPlanningPage, true)
	must(t, e)
	defer store.Close()
	store.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	cache := &PlanningCache{Store: store}
	data := bytes.Repeat([]byte("split"), 20000)
	ref := generation.Object{ID: storage.Hash(data), Bytes: len(data)}
	compute := func() (storage.Blob, error) { return storage.Describe(ref, data, 64<<10) }
	if _, e = cache.describe(context.Background(), ref.ID, []generation.Object{ref}, 0, 64<<10, compute); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("planning ignored private state quota", e)
	}
	// This would describe 16GiB as 262144 parts. Metadata alone exceeds the
	// established 16MiB plan format; no source needs to be opened to reject it.
	refs := make([]generation.Object, 2048)
	for i := range refs {
		refs[i] = generation.Object{ID: ref.ID, Bytes: generation.MaxObject}
	}
	p := Plan{Profile: storage.Profile{MaxObjectBytes: 64 << 10}}
	if e = preflightPlan(p, refs); !errors.Is(e, ErrDenied) {
		t.Fatal("oversized plan admitted", e)
	}
	p.Profile.MaxObjectBytes = storage.MaxPhysical
	must(t, preflightPlan(p, refs))
}
