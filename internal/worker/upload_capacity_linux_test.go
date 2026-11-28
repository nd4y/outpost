package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/nd4y/outpost/internal/diskbudget"
)

func TestWorkerPreparedUploadCapacityRechecksGuardAfterBudget(t *testing.T) {
	ctx := t.Context()
	limits := diskbudget.Limits{Capacity: 64 << 20, Reserve: 2 << 20, Spool: 8 << 20, Telemetry: 1 << 20}
	budget, err := diskbudget.Open(ctx, t.TempDir(), limits, true)
	must(t, err)
	t.Cleanup(func() { must(t, budget.Close()) })
	before, err := budget.Status(ctx)
	must(t, err)

	// Use a production-relative upload journal path. The retained spool
	// budget excludes its ledger reserve even for a read-only check.
	const name = "domains/domain/repository/1/uploads/operation/jobs/operation/state.json"
	volumeChanged := errors.New("worker volume changed")
	var guardCalls int
	w := &Worker{budget: budget, guard: func(context.Context) error {
		guardCalls++
		if guardCalls == 2 {
			return volumeChanged
		}
		return nil
	}}
	if err := w.checkUploadWrite(ctx, name, 4096); !errors.Is(err, volumeChanged) || guardCalls != 2 {
		t.Fatalf("admitted write must recheck the live guard, got %v after %d guard calls", err, guardCalls)
	}

	guardCalls = 0
	if err := w.checkUploadWrite(ctx, name, int(limits.Spool)); !errors.Is(err, diskbudget.ErrCapacity) || guardCalls != 1 {
		t.Fatalf("capacity refusal must precede the final guard, got %v after %d guard calls", err, guardCalls)
	}
	after, err := budget.Status(ctx)
	must(t, err)
	if before.Revision != after.Revision || before.Used["spool"] != after.Used["spool"] || len(after.Pending) != 0 {
		t.Fatal("read-only upload admission modified the budget")
	}
}
