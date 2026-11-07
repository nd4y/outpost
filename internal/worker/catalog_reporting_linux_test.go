package worker

import (
	"bytes"
	"context"
	"errors"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCatalogReportingKeepsHealthyGenerationAndRespectsForeignQuota(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w := f.nodes[0]
	cfg := f.config(t, 0, nil)
	ctx := context.Background()
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	replica, e := generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	raw, e := replica.Catalog(ctx, f.generation)
	must(t, e)
	catalog, e := generation.VerifyCatalog(raw, f.domain.Trust)
	must(t, e)
	catalog.Sequence = 2
	catalog.Parent = f.generation
	next, e := generation.SignCatalog(catalog, f.writer)
	must(t, e)
	healthy, e := replica.Begin(ctx, next)
	must(t, e)
	must(t, replica.Complete(ctx, healthy))
	must(t, replica.Close())
	must(t, w.admit(ctx, cfg))
	bad := bytes.Clone(raw)
	bad[0] ^= 1
	must(t, os.WriteFile(filepath.Join(dir, "catalogs", f.generation), bad, 0600))
	before, e := os.ReadFile(filepath.Join(dir, "state.json"))
	must(t, e)
	second, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer second.Close()
	used, e := w.budget.Status(ctx)
	must(t, e)
	available := (cfg.Limits.SpoolBytes - used.Used["spool"] - (2 << 20) - (64 << 10)) / 4096 * 4096
	if available <= 0 {
		t.Fatal("no fixture quota")
	}
	finish, e := w.budget.Reserve(ctx, "state/foreign-backup.json", int(available))
	must(t, e)
	released := false
	defer func() {
		if !released {
			must(t, finish(false))
		}
	}()
	grant := workerEnrollment(t, f, 0)
	if _, e = second.ManagementSnapshot(ctx, grant, f.domain.Trust.Domain); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("catalog diagnosis bypassed quota", e)
	}
	after, e := os.ReadFile(filepath.Join(dir, "state.json"))
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("quota denial changed journal")
	}
	pending, e := w.budget.Status(ctx)
	must(t, e)
	if len(pending.Pending) != 1 || second.budget != nil {
		t.Fatal("reporter stole foreign reservation")
	}
	// A failed/unknown write remains conservatively charged. The foreign
	// writer confirms its own small durable file before the reporter retries.
	file, e := w.root.Create("state/foreign-backup.json")
	must(t, e)
	_, e = file.Write([]byte("{}"))
	must(t, e)
	must(t, file.Sync())
	must(t, file.Close())
	directory, e := w.root.Open("state")
	must(t, e)
	must(t, directory.Sync())
	must(t, directory.Close())
	must(t, finish(true))
	released = true
	snapshot, e := second.ManagementSnapshot(ctx, grant, f.domain.Trust.Domain)
	must(t, e)
	if snapshot.InventoryState != "OBSERVED" || len(snapshot.Generations) != 2 {
		t.Fatal("healthy inventory hidden", snapshot)
	}
	for _, g := range snapshot.Generations {
		if g.Generation == healthy {
			if g.Status != "COMPLETE" || g.MetadataState != "" || g.CreatedUnix < 1 {
				t.Fatal("healthy metadata lost", g)
			}
		} else {
			if g.Generation != f.generation || g.Status != "CORRUPT" || g.MetadataState != "UNAVAILABLE" || g.CreatedUnix != 0 || g.Objects != 0 || g.Verification != "NONE" {
				t.Fatal("invented catalog metadata", g)
			}
		}
	}
	reporter, e := second.OpenReporter(ctx, storage.Hash([]byte("catalog-report")), f.domain.Trust.Domain, grant, true)
	must(t, e)
	defer reporter.Close()
	encoded, e := reporter.Enqueue(ctx, snapshot)
	must(t, e)
	enrollment, e := management.VerifyEnrollment(grant, w.owner)
	must(t, e)
	report, e := management.VerifyReport(encoded, enrollment, time.Now())
	must(t, e)
	if report.Format != management.ExternalReportFormat {
		t.Fatal("unknown metadata used old report")
	}
	out := filepath.Join(f.base, "healthy-restore")
	_, e = generation.RecoverMaterialized(ctx, dir, healthy, f.domain.Trust, f.dataOwner, generation.RecoverySelection{}, out)
	must(t, e)
	actual, e := os.ReadFile(filepath.Join(out, "dataset/данные.bin"))
	must(t, e)
	if !bytes.Equal(actual, f.content) {
		t.Fatal("healthy independent recovery changed")
	}
}
