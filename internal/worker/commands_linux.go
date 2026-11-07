package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
)

func (w *Worker) commandPolicy(ctx context.Context, cfg control.Config, raw []byte, env command.Envelope) error {
	if env.Node != w.node || cfg.Revision != env.Request.ExpectedRevision || storage.Hash(raw) != env.ConfigurationDigest || env.Active(time.Now()) != nil {
		return ErrDenied
	}
	if _, e := cfg.CommandAuthority(env.Request.Authority, w.owner, time.Now()); e != nil {
		return e
	}
	if env.Request.Kind == "maintenance" {
		if _, e := cfg.MaintenancePermit(env.Request); e != nil {
			return e
		}
	}
	if env.Request.Job != "" {
		for _, job := range cfg.Jobs {
			if job.Operation == env.Request.Job && job.Domain == env.Request.Domain && (job.Executor == w.node || job.Peer == w.node) {
				return nil
			}
		}
		s, e := w.Status(ctx)
		if e != nil {
			return e
		}
		job, ok := s.Jobs[env.Request.Job]
		if !ok || job.Job.Domain != env.Request.Domain || !cfg.Autonomous(job.Job) {
			return ErrDenied
		}
	}
	return nil
}

// ExecuteCommand returns only a durable signed result. Pause/resume admission
// changes the desired holds atomically; completion waits for the execution
// lease owner to cancel and join every old task and incoming request.
func (w *Worker) ExecuteCommand(ctx context.Context, raw []byte) ([]byte, error) {
	env, _, e := command.VerifyEnvelope(raw, w.owner)
	if e != nil || env.Node != w.node {
		return nil, ErrDenied
	}
	if env.Request.Kind != "pause" && env.Request.Kind != "resume" && env.Request.Kind != "retry" && env.Request.Kind != "scrub" && env.Request.Kind != "maintenance" {
		return nil, ErrDenied
	}
	if e = w.check(ctx); e != nil {
		return nil, e
	}
	state, journal, close, e := w.commandSession(ctx)
	if e != nil {
		return nil, e
	}
	defer close()
	var out []byte
	e = journal.WithLock(ctx, func() error {
		s, e := state.Status(ctx)
		if e != nil {
			return e
		}
		if s.Format != Format || s.Controls == nil {
			return ErrDenied
		}
		scope := command.SequenceScope(env.Service, env.Request.Kind)
		op, exists := s.Controls.Operations[env.Request.Operation]
		digest := storage.Hash(raw)
		name := "command-" + digest + ".json"
		if exists {
			if op.Envelope != digest {
				return ErrDenied
			}
			saved, e := journal.Read(name)
			if e != nil {
				return e
			}
			if !bytes.Equal(raw, saved) {
				return ErrDenied
			}
			if len(op.Ack) > 0 {
				if _, e = command.VerifyAck(op.Ack, raw, w.owner, w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), time.Now()); e != nil {
					return e
				}
				out = append([]byte(nil), op.Ack...)
				return nil
			}
		} else {
			if len(s.Controls.Operations) >= maxCommands {
				return ErrCapacity
			}
			if env.Sequence <= s.Controls.Sequences[scope] {
				return ErrDenied
			}
			if _, ok := s.Controls.Sequences[scope]; !ok && len(s.Controls.Sequences) >= 256 {
				return ErrCapacity
			}
			pending := 0
			for _, old := range s.Controls.Operations {
				if len(old.Ack) == 0 && command.Control(old.Kind) == command.Control(env.Request.Kind) {
					pending++
				}
			}
			if command.Control(env.Request.Kind) && pending > 0 {
				return ErrDenied
			}
			if !command.Control(env.Request.Kind) && pending >= 32 {
				return ErrCapacity
			}
			previous, e := journal.Read(name)
			if e == nil && !bytes.Equal(previous, raw) {
				return ErrDenied
			}
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if e != nil {
				if e = journal.Write(name, raw); e != nil {
					return e
				}
			}
			if e = w.point("worker-command-envelope-durable"); e != nil {
				return e
			}
			op = CommandRecord{Tenant: env.Request.Tenant, Envelope: digest, Service: env.Service, Sequence: env.Sequence, Domain: env.Request.Domain, Kind: env.Request.Kind, Job: env.Request.Job}
			// Lock order is cache, then worker state. Policy cannot be replaced between
			// checking the owner grant and committing its short local desired-state change.
			e = state.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, policy []byte) error {
				if e = w.commandPolicy(ctx, cfg, policy, env); e != nil {
					return e
				}
				return state.update(ctx, func(s *Status) error {
					if s.Controls == nil || s.Controls.Revision >= command.MaxSafeInteger || cfg.Active(time.Now()) != nil || env.Active(time.Now()) != nil {
						return ErrDenied
					}
					if env.Request.Kind == "scrub" || env.Request.Kind == "maintenance" {
						op.Generation = env.Request.Generation
						op.Work = &CommandWork{Phase: "QUEUED"}
						op.StartedUnix = time.Now().Unix()
						s.Controls.Operations[env.Request.Operation] = op
						s.Controls.Sequences[scope] = env.Sequence
						return nil
					}
					if env.Request.Kind == "retry" {
						job, e := w.retryJob(cfg, s, env.Request.Job)
						if e != nil {
							return e
						}
						op.JobBinding = job.Binding
						op.StartedUnix = time.Now().Unix()
						s.Controls.Operations[env.Request.Operation] = op
						s.Controls.Sequences[scope] = env.Sequence
						return nil
					}
					if env.Request.Job == "" {
						if env.Request.Kind == "pause" {
							s.Controls.Domains[env.Request.Domain] = true
						} else {
							delete(s.Controls.Domains, env.Request.Domain)
						}
					} else {
						if env.Request.Kind == "pause" {
							s.Controls.Jobs[env.Request.Job] = env.Request.Domain
						} else {
							delete(s.Controls.Jobs, env.Request.Job)
						}
					}
					if len(s.Controls.Domains) > 128 || len(s.Controls.Jobs) > MaxJobs {
						return ErrCapacity
					}
					s.Controls.Revision++
					op.Revision = s.Controls.Revision
					op.StartedUnix = time.Now().Unix()
					s.Controls.Operations[env.Request.Operation] = op
					s.Controls.Sequences[scope] = env.Sequence
					return nil
				})
			})
			if e != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Policy denial has no effect. Infrastructure errors remain retryable and
				// cannot turn an unknown write outcome into a false failure receipt.
				if !errors.Is(e, ErrDenied) && !errors.Is(e, control.ErrDenied) && !errors.Is(e, control.ErrInactive) && !errors.Is(e, control.ErrRollback) {
					return e
				}
				code := "POLICY_BLOCKED"
				if env.Active(time.Now()) != nil {
					code = "COMMAND_EXPIRED"
				}
				ack, e := w.commandResult(raw, env, op, "FAILED", code)
				if e != nil {
					return e
				}
				op.Ack = ack
				if e = state.update(ctx, func(s *Status) error {
					s.Controls.Operations[env.Request.Operation] = op
					s.Controls.Sequences[scope] = env.Sequence
					return nil
				}); e != nil {
					return e
				}
				out = ack
				return w.point("worker-command-ack-durable")
			}
			if e = w.point("worker-command-intent-durable"); e != nil {
				return e
			}
		}
		if env.Request.Kind == "scrub" || env.Request.Kind == "maintenance" {
			if exists {
				acquire, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
				err := w.lease.WithLock(acquire, func() error { return state.reconcileActions(ctx) })
				cancel()
				if err != nil && !errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				current, err := state.Status(ctx)
				if err != nil {
					return err
				}
				out = current.Controls.Operations[env.Request.Operation].Ack
			}
			return nil
		}
		if env.Request.Kind == "retry" {
			out, e = w.finishRetryCommand(ctx, state, raw, env, op)
			return e
		}
		wait, done := context.WithDeadline(ctx, time.Unix(env.Request.ExpiresUnix, 0))
		defer done()
		e = w.waitControls(wait, state, op.Revision)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		status, code := "COMPLETE", ""
		if e != nil {
			if !errors.Is(e, context.DeadlineExceeded) {
				return e
			}
			status, code = "FAILED", "EFFECT_UNCONFIRMED"
		}
		if e = w.point("worker-command-applied-durable"); e != nil {
			return e
		}
		ack, e := w.commandResult(raw, env, op, status, code)
		if e != nil {
			return e
		}
		if e = state.update(ctx, func(s *Status) error {
			current := s.Controls.Operations[env.Request.Operation]
			if current.Envelope != op.Envelope {
				return ErrDenied
			}
			current.Ack = ack
			s.Controls.Operations[env.Request.Operation] = current
			return nil
		}); e != nil {
			return e
		}
		if e = w.point("worker-command-ack-durable"); e != nil {
			return e
		}
		out = ack
		return nil
	})
	return out, e
}
func (w *Worker) commandResult(raw []byte, env command.Envelope, op CommandRecord, status, code string) ([]byte, error) {
	now := time.Now()
	if status == "COMPLETE" && now.Unix() >= env.Request.ExpiresUnix {
		status, code = "FAILED", "EFFECT_UNCONFIRMED"
	}
	ack := command.Ack{Format: command.AckFormat, Node: w.node, Operation: env.Request.Operation, EnvelopeDigest: storage.Hash(raw), State: status, StartedUnix: op.StartedUnix, ObservedUnix: now.Unix(), ControlRevision: op.Revision, ErrorCode: code}
	if status == "COMPLETE" {
		ack.ResultDigest = storage.Hash([]byte(op.Envelope + "/applied"))
		if len(op.Result) > 0 {
			ack.ResultDigest = storage.Hash(op.Result)
		}
	}
	return command.SignAck(ack, raw, w.owner, w.cert.PrivateKey.(ed25519.PrivateKey), now)
}
func (w *Worker) waitControls(ctx context.Context, state *Worker, revision uint64) error {
	for {
		s, e := state.Status(ctx)
		if e != nil {
			return e
		}
		if s.Controls == nil {
			return ErrDenied
		}
		if s.Controls.Applied >= revision {
			return nil
		}
		acquire, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
		// If Run is absent, exclusive ownership proves quiescence. A future Run
		// reads the persisted holds before admitting any task.
		e = w.lease.WithLock(acquire, func() error { return state.markControlsApplied(ctx) })
		cancel()
		if e != nil && !errors.Is(e, context.DeadlineExceeded) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
