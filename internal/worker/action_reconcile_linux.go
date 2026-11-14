package worker

import (
	"context"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
)

// The caller owns the execution lease and has no active view. No actual work
// can race these transitions; a paused or expired policy need not start a view
// merely to reconcile interrupted work or report a command that never ran.
func (w *Worker) reconcileActions(ctx context.Context) error {
	s, e := w.Status(ctx)
	if e != nil {
		return e
	}
	if s.Controls == nil {
		return nil
	}
	for id, op := range s.Controls.Operations {
		if op.Work == nil || len(op.Ack) > 0 {
			continue
		}
		raw, env, e := w.actionEnvelope(ctx, id, op)
		if e != nil {
			return e
		}
		expired := env.Active(time.Now()) != nil
		denied := false
		if !expired {
			e = w.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, policy []byte) error { return w.commandPolicy(ctx, cfg, policy, env) })
			if errors.Is(e, generation.ErrMaintenanceWindow) {
				expired = true
			} else if e != nil {
				if !errors.Is(e, ErrDenied) && !errors.Is(e, control.ErrDenied) && !errors.Is(e, control.ErrInactive) && !errors.Is(e, control.ErrRollback) {
					return e
				}
				denied = true
			}
		}
		if !expired && !denied && op.Work.Phase != "RUNNING" {
			continue
		}
		e = w.update(ctx, func(current *Status) error {
			saved, ok := current.Controls.Operations[id]
			if !ok || saved.Envelope != op.Envelope || saved.Work == nil {
				return ErrDenied
			}
			if len(saved.Ack) > 0 {
				return nil
			}
			if !expired && !denied {
				saved.Work.Phase = "QUEUED"
				saved.Work.NextMillis = 0
				saved.Work.ErrorCode = ""
				current.Controls.Operations[id] = saved
				return nil
			}
			code := "POLICY_BLOCKED"
			if expired {
				code = "COMMAND_EXPIRED"
			}
			if saved.Work.Attempts > 0 {
				code = "EFFECT_UNCONFIRMED"
			}
			ack, e := w.commandResult(raw, env, saved, "FAILED", code)
			if e != nil {
				return e
			}
			saved.Work.Phase = "FAILED"
			saved.Work.NextMillis = 0
			saved.Work.ErrorCode = code
			saved.Result = nil
			saved.Ack = ack
			current.Controls.Operations[id] = saved
			return nil
		})
		if e != nil {
			return e
		}
		if e = w.point("worker-command-reconciled-durable"); e != nil {
			return e
		}
	}
	return nil
}
