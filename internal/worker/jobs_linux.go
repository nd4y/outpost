package worker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/control"
)

type result struct {
	job           control.Job
	receipt       json.RawMessage
	err           error
	action        *actionResult
	scrub         *scrubResult
	externalAudit string
	coverage      string
	advanced      bool
}

func (w *Worker) jobs(v *view) error {
	results := make(chan result, v.cfg.Limits.Parallel)
	running := map[string]bool{}
	coverageNext := map[string]time.Time{}
	finish := func(r result) error {
		if r.coverage != "" {
			delete(running, "capture-coverage/"+r.coverage)
			delay := time.Second
			if r.err != nil {
				delay = 5 * time.Second
			} else if r.advanced {
				delay = 0
			}
			coverageNext[r.coverage] = time.Now().Add(delay)
			return nil
		}
		if r.externalAudit != "" {
			delete(running, r.externalAudit)
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if r.scrub != nil {
			delete(running, "scrub/"+r.scrub.key)
			return w.finishScrub(ctx, v, r.scrub)
		}
		if r.action != nil {
			delete(running, "command/"+r.action.envelope.Request.Operation)
			return w.finishAction(ctx, v, r.action)
		}
		delete(running, r.job.Operation)
		return w.update(ctx, func(s *Status) error {
			j, ok := s.Jobs[r.job.Operation]
			if !ok || j.Binding != binding(r.job) {
				return ErrDenied
			}
			j.UpdatedUnix = time.Now().Unix()
			j.ErrorCode = errorCode(r.err)
			if r.err == nil {
				j.Phase = "COMPLETE"
				j.Receipt = r.receipt
				j.NextMillis = 0
			} else if v.ctx.Err() != nil && (errors.Is(r.err, context.Canceled) || errors.Is(r.err, context.DeadlineExceeded)) {
				j.Phase = "QUEUED"
				j.NextMillis = 0
			} else if blocked(j.ErrorCode) {
				j.Phase = "BLOCKED"
			} else {
				j.Phase = "RETRY_WAIT"
				shift := j.Attempts
				if shift > 6 {
					shift = 6
				}
				j.NextMillis = time.Now().Add(time.Duration(1<<shift) * time.Second).UnixMilli()
			}
			s.Jobs[r.job.Operation] = j
			return nil
		})
	}
	drain := func() error {
		var first error
		for len(running) > 0 {
			if e := finish(<-results); e != nil && first == nil {
				first = e
			}
		}
		return first
	}
	for {
		if v.ctx.Err() != nil {
			return drain()
		}
		s, e := w.Status(v.ctx)
		if e != nil {
			v.cancel()
			joined := drain()
			if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				return joined
			}
			return errors.Join(e, joined)
		}
		desired := append([]control.Job(nil), v.cfg.Jobs...)
		if e = w.scheduleActions(v, s, running, results); e != nil {
			v.cancel()
			joined := drain()
			if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
				return joined
			}
			return errors.Join(e, joined)
		}
		known := map[string]bool{}
		for _, j := range desired {
			known[j.Operation] = true
		}
		for _, old := range s.Jobs {
			if !known[old.Job.Operation] && v.autonomy.Permits(old.Job) {
				desired = append(desired, old.Job)
			}
		}
		for _, j := range desired {
			if j.Executor != w.node || s.Rejected[j.Operation] != "" || running[j.Operation] || len(running) >= v.cfg.Limits.Parallel || v.paused(j.Domain, j.Operation) || s.Controls.paused(j.Domain, j.Operation) {
				continue
			}
			old := s.Jobs[j.Operation]
			if old.Phase != "QUEUED" && old.Phase != "RETRY_WAIT" || old.NextMillis > time.Now().UnixMilli() {
				continue
			}
			e = w.update(v.ctx, func(s *Status) error {
				if controlRevision(s.Controls) != controlRevision(v.controls) {
					v.cancel()
					return context.Canceled
				}
				state := s.Jobs[j.Operation]
				state.Phase = "RUNNING"
				state.Attempts++
				state.UpdatedUnix = time.Now().Unix()
				s.Jobs[j.Operation] = state
				return nil
			})
			if e != nil {
				v.cancel()
				joined := drain()
				if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
					return joined
				}
				return errors.Join(e, joined)
			}
			running[j.Operation] = true
			go func(job control.Job) {
				ctx, cancel := context.WithTimeout(v.ctx, time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond)
				defer cancel()
				receipt, e := w.attempt(ctx, v, job)
				results <- result{job: job, receipt: receipt, err: e}
			}(j)
		}
		if len(running) < v.cfg.Limits.Parallel {
			if e = w.scheduleScrub(v, running, results); e != nil {
				v.cancel()
				return errors.Join(e, drain())
			}
		}
		if len(running) < v.cfg.Limits.Parallel {
			w.scheduleExternalAudit(v, s, running, results)
		}
		for domain, local := range v.domains {
			if len(running) >= v.cfg.Limits.Parallel {
				break
			}
			key := "capture-coverage/" + domain
			if local.ingress == nil || running[key] || v.paused(domain, "") || time.Now().Before(coverageNext[domain]) {
				continue
			}
			running[key] = true
			go func() {
				ctx, cancel := context.WithTimeout(v.ctx, time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond)
				defer cancel()
				paused := func(op string) bool { return v.paused(domain, op) }
				advanced, err := local.ingress.AdvanceCoverage(ctx, paused)
				if err == nil && !advanced {
					advanced, err = local.ingress.AdvanceStagedImport(ctx, paused)
				}
				results <- result{coverage: domain, advanced: advanced, err: err}
			}()
		}
		select {
		case r := <-results:
			if e = finish(r); e != nil {
				v.cancel()
				_ = drain()
				return e
			}
		case <-v.ctx.Done():
			return drain()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
