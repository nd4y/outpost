package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const DispatchFormat = "outpost-report-dispatch-1"
const dispatchStateFormat = "outpost-report-dispatch-state-1"

type DispatchConfig struct {
	Format          string `json:"format"`
	Revision        uint64 `json:"revision"`
	Enabled         bool   `json:"enabled"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	RetrySeconds    int64  `json:"retrySeconds"`
	AttemptSeconds  int64  `json:"attemptSeconds"`
}

func (c DispatchConfig) Validate() error {
	if c.Format != DispatchFormat || c.Revision == 0 || !safe(c.Revision) || c.IntervalSeconds < 1 || c.IntervalSeconds > 86400 || c.RetrySeconds < 1 || c.RetrySeconds > 3600 || c.AttemptSeconds < 1 || c.AttemptSeconds > 60 {
		return ErrInvalid
	}
	return nil
}

type DispatchStatus struct {
	Format          string         `json:"format"`
	Binding         string         `json:"binding"`
	Config          DispatchConfig `json:"config"`
	Phase           string         `json:"phase"`
	ObservedUnix    int64          `json:"observedUnix"`
	NextUnix        int64          `json:"nextUnix"`
	LastAttemptUnix int64          `json:"lastAttemptUnix"`
	ErrorCode       string         `json:"errorCode,omitempty"`
	Signature       []byte         `json:"signature,omitempty"`
}

func (r *Reporter) dispatchBinding() string {
	return storage.Hash([]byte(r.node + "/" + r.target + "/" + r.domain + "/" + storage.Hash(r.owner)))
}
func (r *Reporter) loadDispatch() (DispatchStatus, error) {
	var s DispatchStatus
	raw, e := r.store.Read("dispatch.json")
	if e != nil {
		return s, e
	}
	if canonical(raw, &s, 65536) != nil || s.Format != dispatchStateFormat || s.Binding != r.dispatchBinding() || s.Config.Validate() != nil || !oneOf(s.Phase, "READY", "PAUSED", "RUNNING", "RETRY_WAIT") || !validTime(s.ObservedUnix) || s.ObservedUnix > time.Now().Unix() || !validTime(s.NextUnix) || s.NextUnix > s.ObservedUnix+86400 || s.LastAttemptUnix < 0 || s.LastAttemptUnix > s.ObservedUnix || !stableCode(s.ErrorCode) || (s.Phase == "PAUSED") == s.Config.Enabled {
		return s, ErrInvalid
	}
	sig := s.Signature
	s.Signature = nil
	payload, _ := json.Marshal(s)
	s.Signature = sig
	if !ed25519.Verify(r.signer.Public().(ed25519.PublicKey), append([]byte(dispatchStateFormat+"\x00"), payload...), sig) {
		return s, ErrInvalid
	}
	return s, nil
}
func (r *Reporter) saveDispatch(s DispatchStatus) error {
	if e := r.check(context.Background()); e != nil {
		return e
	}
	now := time.Now().Unix()
	if now < s.ObservedUnix {
		return ErrInvalid
	}
	s.ObservedUnix = now
	s.Signature = nil
	raw, _ := json.Marshal(s)
	s.Signature = ed25519.Sign(r.signer, append([]byte(dispatchStateFormat+"\x00"), raw...))
	raw, _ = json.Marshal(s)
	return errors.Join(r.store.Write("dispatch.json", raw), r.check(context.Background()))
}

// SetDispatch is a local explicit schedule change. It grants no reporting or
// backup authority, and cannot initialize a missing reporting counter journal.
func (r *Reporter) SetDispatch(ctx context.Context, c DispatchConfig) error {
	if c.Validate() != nil {
		return ErrInvalid
	}
	return r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		if _, _, e := r.load(); e != nil {
			return e
		}
		s, e := r.loadDispatch()
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e == nil {
			if c == s.Config {
				return nil
			}
			if c.Revision <= s.Config.Revision {
				return ErrConflict
			}
		}
		phase := "READY"
		if !c.Enabled {
			phase = "PAUSED"
		}
		return r.saveDispatch(DispatchStatus{Format: dispatchStateFormat, Binding: r.dispatchBinding(), Config: c, Phase: phase, NextUnix: time.Now().Unix()})
	})
}
func (r *Reporter) DispatchStatus(ctx context.Context) (DispatchStatus, error) {
	var out DispatchStatus
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		if _, _, e := r.load(); e != nil {
			return e
		}
		var e error
		out, e = r.loadDispatch()
		return e
	})
	return out, e
}
func (r *Reporter) Enrollment(ctx context.Context) ([]byte, error) {
	var out []byte
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, _, e := r.load()
		if e == nil {
			out = append([]byte(nil), s.Enrollment...)
		}
		return e
	})
	return out, e
}
func dispatchError(e error) string {
	switch {
	case e == nil:
		return ""
	case errors.Is(e, context.Canceled):
		return "CANCELED"
	case errors.Is(e, context.DeadlineExceeded):
		return "DEADLINE"
	case errors.Is(e, ErrCapacity), errors.Is(e, statefile.ErrCapacity):
		return "CAPACITY"
	case errors.Is(e, ErrDenied):
		return "DENIED"
	case errors.Is(e, ErrConflict):
		return "CONFLICT"
	case errors.Is(e, ErrInvalid):
		return "INVALID"
	default:
		return "UNAVAILABLE"
	}
}
func waitDispatch(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RunDispatch is foreground and joins cancellation before returning. Its caller
// runs it independently of backup execution: telemetry failure is not a stop
// condition for backup jobs. The producer must honor its bounded context.
func (r *Reporter) RunDispatch(ctx context.Context, client *ReportClient, produce func(context.Context, []byte, string) (Snapshot, error)) error {
	if client == nil || client.target != r.target || client.node != r.node || produce == nil {
		return ErrInvalid
	}
	return r.dispatch.WithLock(ctx, func() error {
		for {
			if e := ctx.Err(); e != nil {
				return e
			}
			s, e := r.DispatchStatus(ctx)
			if e != nil {
				return e
			}
			if !s.Config.Enabled || time.Now().Unix() < s.NextUnix {
				if e = waitDispatch(ctx); e != nil {
					return e
				}
				continue
			}
			admittedEnrollment, e := r.Enrollment(ctx)
			if e != nil {
				return e
			}
			e = r.store.WithLock(ctx, func() error {
				current, e := r.loadDispatch()
				if e != nil {
					return e
				}
				if current.Config != s.Config {
					return ErrConflict
				}
				current.Phase = "RUNNING"
				current.LastAttemptUnix = time.Now().Unix()
				current.NextUnix = current.LastAttemptUnix + current.Config.RetrySeconds
				current.ErrorCode = ""
				return r.saveDispatch(current)
			})
			if errors.Is(e, ErrConflict) {
				continue
			}
			if e != nil {
				return e
			}
			// Persist the retry deadline before any I/O, so restart cannot create a
			// tight retry loop. Configuration changes cancel even a blocked HTTPS call.
			attempt, cancel := context.WithTimeout(ctx, time.Duration(s.Config.AttemptSeconds)*time.Second)
			watched := make(chan struct{})
			go func() {
				defer close(watched)
				for {
					if waitDispatch(attempt) != nil {
						return
					}
					current, e := r.DispatchStatus(attempt)
					enrollment, grantErr := r.Enrollment(attempt)
					if e != nil || grantErr != nil || !bytes.Equal(enrollment, admittedEnrollment) || current.Config != s.Config {
						cancel()
						return
					}
				}
			}()
			e = func() error {
				pending, e := r.Pending(attempt)
				if e != nil {
					return e
				}
				if pending == nil {
					enrollment, e := r.Enrollment(attempt)
					if e != nil {
						return e
					}
					snapshot, e := produce(attempt, enrollment, r.domain)
					if e != nil {
						return e
					}
					if _, e = r.Enqueue(attempt, snapshot); e != nil {
						return e
					}
				}
				_, e = r.Deliver(attempt, client)
				return e
			}()
			cancel()
			<-watched
			if ctx.Err() != nil {
				return ctx.Err()
			}
			finishErr := r.store.WithLock(ctx, func() error {
				current, err := r.loadDispatch()
				if err != nil {
					return err
				}
				if current.Config != s.Config {
					return nil
				}
				current.Phase = "READY"
				delay := current.Config.IntervalSeconds
				if e != nil {
					current.Phase = "RETRY_WAIT"
					delay = current.Config.RetrySeconds
				}
				current.ErrorCode = dispatchError(e)
				current.NextUnix = time.Now().Unix() + delay
				return r.saveDispatch(current)
			})
			if finishErr != nil {
				return finishErr
			}
		}
	})
}
