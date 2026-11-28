package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/diskbudget"
)

func TestWorkerCommandStartupAccountsPendingControlBeforeAck(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.cfg.Limits.SpoolBytes = 4 << 20
	cfg, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	raw := makeCommand("pause", "", 1)
	w.Fault = func(point string) error {
		if point == "worker-command-intent-durable" {
			return errors.New("process lost before application")
		}
		return nil
	}
	if _, e := w.ExecuteCommand(ctx, raw); e == nil {
		t.Fatal("fault absent")
	}
	w.Fault = nil
	before, e := w.Status(ctx)
	must(t, e)
	if before.Controls.Applied == before.Controls.Revision {
		t.Fatal("fixture already applied")
	}
	// Simulate retained journal growth beyond a previously admitted spool budget.
	// This is four MiB of synthetic metadata, never a backup payload or host disk.
	must(t, os.WriteFile(filepath.Join(w.dir, "state", "retained-capacity.bin"), make([]byte, 4<<20), 0600))
	limits := diskbudget.Limits{Capacity: cfg.Limits.CapacityBytes, Reserve: cfg.Limits.ReserveBytes, Spool: cfg.Limits.SpoolBytes, Telemetry: cfg.Limits.TelemetryBytes}
	must(t, w.budget.Reconcile(ctx, limits))
	other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer other.Close()
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	e = other.Run(bounded)
	if !errors.Is(e, diskbudget.ErrCapacity) {
		t.Fatal("over-budget startup did not fail", e)
	}
	after, e := other.Status(ctx)
	must(t, e)
	if after.Controls.Applied != before.Controls.Applied || !after.Controls.Domains[f.domain.Trust.Domain] {
		t.Fatal("startup bypassed quota or lost hold", before.Controls.Applied, after.Controls.Applied)
	}
	for _, op := range after.Controls.Operations {
		if len(op.Ack) != 0 {
			t.Fatal("quota failure acknowledged a pending command")
		}
	}
}
