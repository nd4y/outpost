package worker

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

type actionResult struct {
	raw      []byte
	envelope command.Envelope
	result   []byte
	err      error
}
type ScrubReceipt struct {
	Kind            string `json:"kind"`
	Generation      string `json:"generation"`
	Verification    string `json:"verification"`
	VerifiedObjects int    `json:"verifiedObjects"`
	VerifiedAt      int64  `json:"verifiedAt"`
}

func (w *Worker) actionEnvelope(ctx context.Context, id string, op CommandRecord) ([]byte, command.Envelope, error) {
	var env command.Envelope
	if e := w.check(ctx); e != nil {
		return nil, env, e
	}
	journal, e := statefile.OpenAt(w.root, "commands", command.MaxEnvelope, false)
	if e != nil {
		return nil, env, e
	}
	defer journal.Close()
	raw, e := journal.Read("command-" + op.Envelope + ".json")
	if e != nil {
		return nil, env, e
	}
	env, _, e = command.VerifyEnvelope(raw, w.owner)
	if e != nil || storage.Hash(raw) != op.Envelope || env.Request.Operation != id || env.Node != w.node || env.Service != op.Service || env.Sequence != op.Sequence || env.Request.Domain != op.Domain || env.Request.Kind != op.Kind || env.Request.Generation != op.Generation {
		return nil, env, ErrDenied
	}
	return raw, env, nil
}

func (w *Worker) actionPolicy(ctx context.Context, v *view, env command.Envelope) error {
	return w.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, raw []byte) error {
		if e := w.commandPolicy(ctx, cfg, raw, env); e != nil {
			return e
		}
		if cfg.Revision != v.cfg.Revision {
			return errors.New("policy not applied yet")
		}
		return nil
	})
}

// Long commands use the same running set and concurrency ceiling as backup
// jobs. The view's cancellation/join boundary therefore also covers their I/O.
func (w *Worker) scheduleActions(v *view, s Status, running map[string]bool, results chan<- result) error {
	if s.Controls == nil {
		return nil
	}
	ids := []string{}
	for id, op := range s.Controls.Operations {
		if op.Work != nil && len(op.Ack) == 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		return s.Controls.Operations[ids[i]].Sequence < s.Controls.Operations[ids[j]].Sequence
	})
	for _, id := range ids {
		if len(running) >= v.cfg.Limits.Parallel {
			break
		}
		op := s.Controls.Operations[id]
		key := "command/" + id
		if running[key] {
			continue
		}
		raw, env, e := w.actionEnvelope(v.ctx, id, op)
		if e != nil {
			return e
		}
		policyErr := w.actionPolicy(v.ctx, v, env)
		if policyErr == nil && (v.paused(op.Domain, "") || s.Controls.paused(op.Domain, "") || op.Work.NextMillis > time.Now().UnixMilli()) {
			continue
		}
		reserved := false
		e = w.update(v.ctx, func(current *Status) error {
			if controlRevision(current.Controls) != controlRevision(v.controls) {
				v.cancel()
				return context.Canceled
			}
			old, ok := current.Controls.Operations[id]
			if !ok || old.Envelope != op.Envelope || old.Work == nil {
				return ErrDenied
			}
			if len(old.Ack) > 0 {
				return nil
			}
			if old.Work.Attempts >= command.MaxSafeInteger {
				return ErrCapacity
			}
			old.Work.Phase = "RUNNING"
			old.Work.Attempts++
			old.Work.NextMillis = 0
			old.Work.ErrorCode = ""
			current.Controls.Operations[id] = old
			reserved = true
			return nil
		})
		if e != nil {
			return e
		}
		if !reserved {
			continue
		}
		running[key] = true
		go func(raw []byte, env command.Envelope, policyErr error) {
			out := &actionResult{raw: raw, envelope: env, err: policyErr}
			if policyErr == nil {
				deadline := min(time.Now().Add(time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond).UnixMilli(), env.Request.ExpiresUnix*1000)
				ctx, cancel := context.WithDeadline(v.ctx, time.UnixMilli(deadline))
				out.result, out.err = w.executeAction(ctx, v, env)
				cancel()
			}
			results <- result{action: out}
		}(raw, env, policyErr)
	}
	return nil
}

func (w *Worker) executeAction(ctx context.Context, v *view, env command.Envelope) ([]byte, error) {
	if env.Request.Kind == "maintenance" {
		return w.executeMaintenance(ctx, v, env)
	}
	if env.Request.Kind != "scrub" {
		return nil, ErrDenied
	}
	local := v.domains[env.Request.Domain]
	if local == nil {
		return nil, ErrDenied
	}
	// Scrubbing must not turn an uncommitted reception into a published backup.
	status, e := local.replica.Status(ctx)
	if e != nil {
		return nil, e
	}
	if !slices.Contains(status.Complete, env.Request.Generation) {
		return nil, generation.ErrIncomplete
	}
	encoded, _ := json.Marshal(env)
	window := storage.Hash([]byte("outpost-command-scrub-1/" + storage.Hash(encoded)))
	for {
		if e = w.actionPolicy(ctx, v, env); e != nil {
			return nil, e
		}
		checked, e := local.replica.VerifyWindow(ctx, env.Request.Generation, window, 16, 64<<20)
		if e != nil {
			return nil, e
		}
		if e = w.update(ctx, func(s *Status) error {
			op := s.Controls.Operations[env.Request.Operation]
			if op.Work == nil || len(op.Ack) > 0 {
				return ErrDenied
			}
			op.Work.VerifiedObjects = checked.VerifiedObjects
			op.Work.TotalObjects = checked.TotalObjects
			s.Controls.Operations[env.Request.Operation] = op
			return nil
		}); e != nil {
			return nil, e
		}
		if e = w.point("worker-command-scrub-batch-durable"); e != nil {
			return nil, e
		}
		if checked.Complete {
			if e = w.actionPolicy(ctx, v, env); e != nil {
				return nil, e
			}
			return json.Marshal(ScrubReceipt{Kind: "scrub", Generation: env.Request.Generation, Verification: "sha256-ciphertext", VerifiedObjects: checked.VerifiedObjects, VerifiedAt: checked.VerifiedAt})
		}
	}
}

func (w *Worker) finishAction(ctx context.Context, v *view, out *actionResult) error {
	e := w.update(ctx, func(s *Status) error {
		id := out.envelope.Request.Operation
		op, ok := s.Controls.Operations[id]
		if !ok || op.Envelope != storage.Hash(out.raw) || op.Work == nil || len(op.Ack) > 0 {
			return ErrDenied
		}
		code := errorCode(out.err)
		switch {
		case out.err == nil:
			op.Result = out.result
			op.Work.Phase = "COMPLETE"
		case v.ctx.Err() != nil && (errors.Is(out.err, context.Canceled) || errors.Is(out.err, context.DeadlineExceeded)):
			op.Work.Phase = "QUEUED"
			op.Work.NextMillis = 0
			op.Work.ErrorCode = "CANCELED"
			s.Controls.Operations[id] = op
			return nil
		case out.envelope.Active(time.Now()) != nil:
			op.Work.Phase = "FAILED"
			code = "COMMAND_EXPIRED"
			if out.envelope.Request.Kind == "maintenance" {
				code = "EFFECT_UNCONFIRMED"
			}
		case errors.Is(out.err, generation.ErrProtected), errors.Is(out.err, generation.ErrRollback), errors.Is(out.err, generation.ErrConflict), errors.Is(out.err, generation.ErrMigrationRequired):
			op.Work.Phase = "FAILED"
			code = "MAINTENANCE_BLOCKED"
		case errors.Is(out.err, generation.ErrInvalid), errors.Is(out.err, generation.ErrIncomplete), errors.Is(out.err, storage.ErrIntegrity):
			op.Work.Phase = "FAILED"
			code = "DATA_INCOMPLETE"
		case errors.Is(out.err, ErrDenied), errors.Is(out.err, control.ErrDenied), errors.Is(out.err, control.ErrInactive), errors.Is(out.err, control.ErrRollback):
			op.Work.Phase = "FAILED"
			code = "POLICY_BLOCKED"
		default:
			shift := min(op.Work.Attempts, uint64(6))
			op.Work.Phase = "RETRY_WAIT"
			op.Work.NextMillis = min(time.Now().Add(time.Duration(1<<shift)*time.Second).UnixMilli(), out.envelope.Request.ExpiresUnix*1000)
			op.Work.ErrorCode = code
			s.Controls.Operations[id] = op
			return nil
		}
		ack, e := w.commandResult(out.raw, out.envelope, op, op.Work.Phase, code)
		if e != nil {
			return e
		}
		// Completion observed past the deadline is explicitly unconfirmed.
		var receipt command.Ack
		if e = json.Unmarshal(ack, &receipt); e != nil {
			return e
		}
		op.Work.Phase = receipt.State
		op.Work.ErrorCode = receipt.ErrorCode
		op.Work.NextMillis = 0
		if receipt.State != "COMPLETE" {
			op.Result = nil
		}
		op.Ack = ack
		s.Controls.Operations[id] = op
		return nil
	})
	if e != nil {
		return e
	}
	return w.point("worker-command-work-result-durable")
}
