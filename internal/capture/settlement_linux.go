package capture

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

func (j *Job) settlementState(s State) error {
	g, e := ingress.VerifySettlement(j.options.Settlement, j.options.Authority, j.options.Intent, j.options.Owner, time.Now())
	if e != nil {
		return e
	}
	if phase(s.Phase) < phase("SEALED") || s.Generation != g.Generation {
		return ErrInvalid
	}
	return nil
}

// Reconcile only an already completed original receipt. Even with a durable
// local receipt, require the explicitly provisioned receiver to admit this
// fresh capability before promoting an uncheckpointed job.
func (j *Job) settleReceipt(ctx context.Context, s *State) error {
	reader, ok := j.options.Sink.(interface {
		SettlementReceipt(context.Context) (ingress.Receipt, error)
	})
	if !ok {
		return ErrInvalid
	}
	raw, e := j.state.Read("catalog.json")
	if e != nil {
		return e
	}
	c, e := generation.VerifyCatalog(raw, j.authority.Trust)
	i := j.intent
	if e != nil || storage.Hash(raw) != s.Generation || c.Domain != i.Domain || c.Repository != i.Repository || c.Epoch != i.Epoch || c.Sequence != i.Sequence || c.Parent != i.Parent || c.SnapshotUnix != i.SnapshotUnix || c.Policy != i.Policy {
		return ErrInvalid
	}
	r, e := reader.SettlementReceipt(ctx)
	if e != nil {
		return e
	}
	if e = j.guard(ctx); e != nil {
		return e
	}
	if r.Operation != i.Operation || r.Ingress != i.Ingress || r.Tenant != i.Tenant || r.Domain != i.Domain || r.Generation != s.Generation || r.NewBytes < 0 || r.NewBytes > i.MaxBytes || r.NewObjects < 0 || r.NewObjects > i.MaxObjects || r.VerifiedAt < i.NotBefore || r.VerifiedAt >= i.ExpiresUnix || r.VerifiedAt > time.Now().Unix() {
		return ErrInvalid
	}
	if s.Receipt != nil && *s.Receipt != r {
		return ErrInvalid
	}
	if e = j.point("source-settlement-receipt-observed"); e != nil {
		return e
	}
	if s.Phase == "SEALED" {
		s.Receipt, s.Phase = &r, "WAITING_COPIES"
		if e = j.save(s); e != nil {
			return e
		}
		return j.point("source-receipt-durable")
	}
	return nil
}
