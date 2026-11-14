package worker

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

// retryJob is called under the worker-state lock and current-policy lock.
// A retry cannot create work, change its immutable binding or clear a hold.
func (w *Worker) retryJob(cfg control.Config, s *Status, operation string) (JobState, error) {
	j, ok := s.Jobs[operation]
	if !ok || j.Job.Executor != w.node || s.Rejected[operation] != "" || j.Phase != "BLOCKED" || cfg.Active(time.Now()) != nil {
		return j, ErrDenied
	}
	for _, want := range cfg.Jobs {
		if want.Operation == operation {
			if want.Executor != w.node || j.Binding != binding(want) {
				return j, ErrDenied
			}
			return j, nil
		}
	}
	if !cfg.Autonomous(j.Job) || j.Binding != binding(j.Job) {
		return j, ErrDenied
	}
	return j, nil
}

func (w *Worker) retryUpload(ctx context.Context, cfg control.Config, j JobState, token string) error {
	if j.Job.Kind != "upload" {
		return nil
	}
	d, ok := cfg.DomainByID(j.Job.Domain)
	if !ok {
		return ErrDenied
	}
	dir := filepath.Join(DomainDirectory(w.dir, d.Trust), "uploads", j.Job.Operation)
	relative := w.relative(dir)
	q, e := upload.OpenQueueAt(w.root, relative, w.node, upload.Authority{Generation: d.Trust, Planner: d.Planner}, upload.QueueLimits{MaxJobs: 1, Parallel: 1, AttemptMillis: 300000, RetryBaseMillis: 1000, RetryMaxMillis: 60000}, false, w.admission(filepath.ToSlash(relative)))
	if e != nil {
		return e
	}
	defer q.Close()
	return q.RetryCommand(ctx, j.Job.Operation, token)
}

func (w *Worker) finishRetryCommand(ctx context.Context, state *Worker, raw []byte, env command.Envelope, op CommandRecord) ([]byte, error) {
	var out []byte
	e := state.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, policy []byte) error {
		if e := w.commandPolicy(ctx, cfg, policy, env); e != nil {
			return e
		}
		return state.update(ctx, func(s *Status) error {
			current, ok := s.Controls.Operations[env.Request.Operation]
			if !ok || current.Envelope != op.Envelope || len(current.Ack) != 0 {
				return ErrDenied
			}
			j, e := w.retryJob(cfg, s, env.Request.Job)
			if e != nil || j.Binding != op.JobBinding || env.Active(time.Now()) != nil {
				return ErrDenied
			}
			if e = state.retryUpload(ctx, cfg, j, op.Envelope); e != nil {
				return e
			}
			if e = w.point("worker-command-retry-queue-durable"); e != nil {
				return e
			}
			if e = ctx.Err(); e != nil {
				return e
			}
			ack, e := w.commandResult(raw, env, op, "COMPLETE", "")
			if e != nil {
				return e
			}
			j.Phase, j.NextMillis, j.ErrorCode = "QUEUED", 0, ""
			j.UpdatedUnix = time.Now().Unix()
			s.Jobs[env.Request.Job] = j
			current.Ack = ack
			s.Controls.Operations[env.Request.Operation] = current
			out = ack
			return nil
		})
	})
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !errors.Is(e, ErrDenied) && !errors.Is(e, control.ErrDenied) && !errors.Is(e, control.ErrInactive) && !errors.Is(e, control.ErrRollback) && !errors.Is(e, upload.ErrDenied) {
			return nil, e
		}
		code := "POLICY_BLOCKED"
		if env.Active(time.Now()) != nil {
			code = "COMMAND_EXPIRED"
		}
		ack, err := w.commandResult(raw, env, op, "FAILED", code)
		if err != nil {
			return nil, err
		}
		if err = state.update(ctx, func(s *Status) error {
			current, ok := s.Controls.Operations[env.Request.Operation]
			if !ok || current.Envelope != op.Envelope || len(current.Ack) != 0 {
				return ErrDenied
			}
			current.Ack = ack
			s.Controls.Operations[env.Request.Operation] = current
			return nil
		}); err != nil {
			return nil, err
		}
		out = ack
	}
	if e = w.point("worker-command-ack-durable"); e != nil {
		return nil, e
	}
	return out, nil
}

// Retry performs the same two-journal transaction for a local operator. The
// blocked attempt is its token: interruption cannot make that retry a new one.
func (w *Worker) Retry(ctx context.Context, operation string) error {
	state, journal, close, e := w.commandSession(ctx)
	if e != nil {
		return e
	}
	defer close()
	return journal.WithLock(ctx, func() error {
		return state.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, _ []byte) error {
			return state.update(ctx, func(s *Status) error {
				if s.Controls != nil {
					for _, command := range s.Controls.Operations {
						if len(command.Ack) == 0 && command.Job == operation {
							return ErrDenied
						}
					}
				}
				j, e := w.retryJob(cfg, s, operation)
				if e != nil {
					return e
				}
				token, _ := json.Marshal(struct {
					Node, Operation, Binding string
					Attempt                  uint64
				}{w.node, operation, j.Binding, j.Attempts})
				if e = state.retryUpload(ctx, cfg, j, storage.Hash(append([]byte("outpost-local-retry-1\x00"), token...))); e != nil {
					return e
				}
				if e = w.point("worker-local-retry-queue-durable"); e != nil {
					return e
				}
				j.Phase, j.NextMillis, j.ErrorCode = "QUEUED", 0, ""
				j.UpdatedUnix = time.Now().Unix()
				s.Jobs[operation] = j
				return nil
			})
		})
	})
}
