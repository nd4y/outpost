package upload

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const TargetAuditWindowFormat = "outpost-target-audit-window-1"

type TargetAuditWindow struct {
	ID            string
	MaxAgeSeconds int64
	Store         *statefile.Store
}

type TargetAuditReceipt struct {
	Format       string `json:"format"`
	Window       string `json:"window"`
	Plan         string `json:"plan"`
	Generation   string `json:"generation"`
	Target       string `json:"target"`
	ObservedUnix int64  `json:"observedUnix"`
	FinishedUnix int64  `json:"finishedUnix"`
}

// AuditTargetPlan verifies a plan's exact remote closure without writing to the
// target. The caller retains one window ID and an admitted local store across
// retries. Older proof is reusable only within that exact plan/window binding.
func AuditTargetPlan(ctx context.Context, raw []byte, authority Authority, worker string, backend *storage.Backend, window TargetAuditWindow) (TargetAuditReceipt, error) {
	var receipt TargetAuditReceipt
	if backend == nil || !storage.ID(window.ID) || window.Store == nil || window.MaxAgeSeconds < 1 || window.MaxAgeSeconds > readback.MaxAgeSeconds {
		return receipt, ErrDenied
	}
	plan, err := Verify(raw, authority)
	if err != nil || plan.Profile != backend.Profile() {
		return receipt, ErrDenied
	}
	if _, ok := plan.worker(worker); !ok {
		return receipt, ErrDenied
	}
	journal := Journal{
		plan: plan, planID: storage.Hash(raw), worker: worker, authority: authority,
		Readback: ReadbackOptions{MaxAgeSeconds: window.MaxAgeSeconds, Store: window.Store},
	}
	audit, err := journal.newScopedAudit(ctx, backend, window.ID)
	if err != nil {
		return receipt, err
	}
	defer audit.close()
	if err = journal.readTargetClosure(ctx, backend, audit); err != nil {
		return receipt, err
	}
	_, observed, err := audit.evidence(ctx)
	if err != nil {
		return receipt, err
	}
	if err = ctx.Err(); err != nil {
		return receipt, err
	}
	finished := time.Now().Unix()
	if observed > finished || finished-observed > window.MaxAgeSeconds {
		return receipt, storage.ErrUnavailable
	}
	return TargetAuditReceipt{
		Format: TargetAuditWindowFormat, Window: window.ID, Plan: journal.planID, Generation: plan.Generation,
		Target: plan.Profile.ID(), ObservedUnix: observed, FinishedUnix: finished,
	}, nil
}
