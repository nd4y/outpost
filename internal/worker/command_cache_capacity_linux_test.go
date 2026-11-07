package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/statefile"
)

func TestWorkerCommandCacheWriteRespectsForeignReservationAndSpoolQuota(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	cfg, _ := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	second, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer second.Close()
	shadow, _, close, e := second.commandSession(ctx)
	must(t, e)
	defer close()
	used, e := w.budget.Status(ctx)
	must(t, e)
	// A foreign write consumes spool quota including the ledger reserve and
	// per-write accounting overhead. Leave less than one allocation unit.
	available := (cfg.Limits.SpoolBytes - used.Used["spool"] - (2 << 20) - (64 << 10)) / 4096 * 4096
	if available <= 0 {
		t.Fatal("fixture lacks spool space")
	}
	finish, e := w.budget.Reserve(ctx, "state/foreign-backup.json", int(available))
	must(t, e)
	released := false
	defer func() {
		if !released {
			must(t, finish(false))
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	observed := time.Now().Add(time.Second)
	_, e = shadow.cache.Current(bounded, observed)
	if !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("command cache bypassed exhausted quota", e)
	}
	after, e := w.budget.Status(ctx)
	must(t, e)
	if len(after.Pending) != 1 || second.budget != nil {
		t.Fatal("command session stole execution reservation or ownership")
	}
	file, e := w.root.Create("state/foreign-backup.json")
	must(t, e)
	_, e = file.Write([]byte("{}"))
	must(t, e)
	must(t, file.Sync())
	must(t, file.Close())
	dir, e := w.root.Open("state")
	must(t, e)
	must(t, dir.Sync())
	must(t, dir.Close())
	must(t, finish(true))
	released = true
	_, e = shadow.cache.Current(ctx, observed)
	must(t, e)
	_, e = shadow.cache.Current(ctx, observed.Add(-time.Second))
	if !errors.Is(e, control.ErrRollback) {
		t.Fatal("successful cache write did not persist observation", e)
	}
}
