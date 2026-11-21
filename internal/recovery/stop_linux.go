package recovery

import (
	"context"
	"errors"
	"github.com/nd4y/outpost/internal/generation"
	"os"
)

// Stop is local terminal reconciliation. It cannot remove or replace output,
// and can release only a pin bound to this exact request and replica scope.
func (x *Executor) Stop(ctx context.Context, r Request, source *generation.Replica) error {
	p, e := x.validate(r)
	if e != nil || source == nil {
		return ErrInvalid
	}
	t := source.Trust()
	if t.Domain != p.Domain || t.Repository != p.Repository || t.Epoch != p.Epoch {
		return ErrConflict
	}
	e = x.admission.state.WithLock(ctx, func() error {
		if e := x.guard(ctx); e != nil {
			return e
		}
		op, e := x.load(r)
		if errors.Is(e, os.ErrNotExist) {
			if _, e = x.root.Lstat("results/" + r.Operation); !errors.Is(e, os.ErrNotExist) {
				return ErrConflict
			}
			return x.releaseCompletedReservation(ctx, r)
		}
		if e != nil {
			return e
		}
		done, e := x.completed(ctx, &op)
		if e != nil {
			return e
		}
		if done == nil {
			op.Phase = "STOPPED"
			op.Result = nil
			op.PreparedDigest = ""
			if e = x.save(op); e != nil {
				return e
			}
			if e = x.point("recovery-stopped-durable"); e != nil {
				return e
			}
		}
		return x.releaseCompletedReservation(ctx, r)
	})
	if e != nil {
		return e
	}
	return source.ReleasePin(ctx, pin(r))
}
