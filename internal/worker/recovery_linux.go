package worker

import (
	"context"
	"encoding/json"
	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/storage"
	"time"
)

func recoveryRequest(env command.Envelope, raw []byte) recovery.Request {
	return recovery.Request{Operation: env.Request.Operation, Binding: storage.Hash(raw), Preset: env.Request.Preset, Generation: env.Request.Generation, Versions: env.Request.Versions}
}
func (w *Worker) executeRestore(ctx context.Context, v *view, env command.Envelope, raw []byte) ([]byte, error) {
	if w.recovery == nil || !w.recovery.PresetDomain(env.Request.Preset, env.Request.Domain) {
		return nil, ErrDenied
	}
	local := v.domains[env.Request.Domain]
	if local == nil {
		return nil, ErrDenied
	}
	authorize := func(ctx context.Context) error { return w.actionPolicy(ctx, v, env) }
	// Keep the accepted policy locked through the final rename. A concurrent
	// withdrawal cannot slip between the last check and publication.
	commit := func(ctx context.Context, publish func() error) error {
		return w.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, policy []byte) error {
			if e := w.commandPolicy(ctx, cfg, policy, env); e != nil {
				return e
			}
			if cfg.Revision != v.cfg.Revision {
				return ErrDenied
			}
			if e := ctx.Err(); e != nil {
				return e
			}
			// Cache -> state is the same lock order used by command admission.
			// Pause cannot become durable between this check and the rename.
			return w.state.WithLock(ctx, func() error {
				current, e := w.load()
				if e != nil {
					return e
				}
				if controlRevision(current.Controls) != controlRevision(v.controls) || current.Controls.paused(env.Request.Domain, "") {
					v.cancel()
					return context.Canceled
				}
				if e = ctx.Err(); e != nil {
					return e
				}
				return publish()
			})
		})
	}
	result, e := w.recovery.RestoreCommitted(ctx, recoveryRequest(env, raw), local.replica, authorize, commit)
	if e != nil {
		return nil, e
	}
	return json.Marshal(result)
}

// Terminal cleanup never deletes restored or staged data. It fences further
// attempts and releases only this command's reservation and source pin.
func (w *Worker) cleanupRecoveries(v *view, s Status) error {
	if w.recovery == nil || s.Controls == nil {
		return nil
	}
	for id, op := range s.Controls.Operations {
		if op.Kind != "restore" || op.Work == nil || !op.Work.CleanupPending || len(op.Ack) == 0 {
			continue
		}
		local := v.domains[op.Domain]
		if local == nil {
			continue
		}
		raw, env, e := w.actionEnvelope(v.ctx, id, op)
		if e != nil {
			return e
		}
		if !w.recovery.PresetDomain(env.Request.Preset, op.Domain) {
			continue
		}
		if e = w.recovery.Stop(v.ctx, recoveryRequest(env, raw), local.replica); e != nil {
			continue
		}
		if e = w.update(v.ctx, func(s *Status) error {
			old := s.Controls.Operations[id]
			if old.Envelope != op.Envelope || old.Work == nil || len(old.Ack) == 0 {
				return ErrDenied
			}
			old.Work.CleanupPending = false
			s.Controls.Operations[id] = old
			return nil
		}); e != nil {
			return e
		}
	}
	return nil
}
