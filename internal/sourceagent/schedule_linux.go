package sourceagent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

const ScheduleFormat = "outpost-source-schedule-1"
const scheduleStateFormat = "outpost-source-schedule-state-1"

var ErrScheduleChanged = errors.New("source schedule revision changed")

// ScheduleControl exposes only short private configuration operations. It
// cannot start capture without execution admission and budget reconciliation.
type ScheduleControl struct{ agent *Agent }

func OpenScheduleControl(ctx context.Context, b Bootstrap) (*ScheduleControl, error) {
	a, e := open(ctx, b, false, true)
	if e != nil {
		return nil, e
	}
	return &ScheduleControl{a}, nil
}
func (c *ScheduleControl) Close() error { return c.agent.Close() }
func (c *ScheduleControl) Status(ctx context.Context) (ScheduleStatus, error) {
	return c.agent.ScheduleStatus(ctx)
}
func (c *ScheduleControl) Configure(ctx context.Context, s Schedule) error {
	return c.agent.ConfigureSchedule(ctx, s)
}

type Schedule struct {
	Format               string `json:"format"`
	Revision             uint64 `json:"revision"`
	Enabled              bool   `json:"enabled"`
	IntervalSeconds      int64  `json:"intervalSeconds"`
	RetrySeconds         int64  `json:"retrySeconds"`
	AttemptSeconds       int64  `json:"attemptSeconds"`
	StartUnix            int64  `json:"startUnix"`
	RelayAuthorityFile   string `json:"relayAuthorityFile,omitempty"`
	RelayAuthoritySHA256 string `json:"relayAuthoritySHA256,omitempty"`
}

func (s Schedule) valid() bool {
	return s.Format == ScheduleFormat && s.Revision > 0 && s.IntervalSeconds >= 1 && s.IntervalSeconds <= 31622400 && s.RetrySeconds >= 1 && s.RetrySeconds <= 3600 && s.AttemptSeconds >= 1 && s.AttemptSeconds <= 86400 && s.StartUnix >= 1 && s.StartUnix <= 1<<40 &&
		(s.RelayAuthorityFile == "" && s.RelayAuthoritySHA256 == "" || filepath.IsAbs(s.RelayAuthorityFile) && storage.ID(s.RelayAuthoritySHA256))
}

func (a *Agent) scheduledRelayAuthority(c Schedule) ([]byte, error) {
	if c.RelayAuthorityFile == "" {
		return nil, nil
	}
	raw, err := worker.ReadPrivate(c.RelayAuthorityFile, ingress.MaxDocument)
	if err != nil {
		return nil, err
	}
	if storage.Hash(raw) != c.RelayAuthoritySHA256 {
		return nil, ingress.ErrDenied
	}
	recipient, err := ingress.VerifyAuthorityDocument(raw, a.b.Local.Owner)
	if err != nil || recipient.Ingress == a.anchor.Ingress || recipient.Ingress == a.companion.Ingress || recipient.Ingress == a.reserve.Ingress {
		return nil, ingress.ErrDenied
	}
	recipient.Ingress = a.anchor.Ingress
	if !ingress.SameAuthorityScope(recipient, a.anchor) {
		return nil, ingress.ErrDenied
	}
	return raw, nil
}

type ScheduleStatus struct {
	Format            string   `json:"format"`
	Profile           string   `json:"profile"`
	Config            Schedule `json:"config"`
	Phase             string   `json:"phase"`
	NextUnix          int64    `json:"nextUnix"`
	RetryUnix         int64    `json:"retryUnix,omitempty"`
	LastSequence      uint64   `json:"lastSequence"`
	LastGeneration    string   `json:"lastGeneration,omitempty"`
	LastCompletedUnix int64    `json:"lastCompletedUnix,omitempty"`
	Operation         string   `json:"operation,omitempty"`
	Attempts          uint64   `json:"attempts"`
	ErrorCode         string   `json:"errorCode,omitempty"`
	UpdatedUnix       int64    `json:"updatedUnix"`
}
type scheduleState struct {
	ScheduleStatus
	Binding   string `json:"binding"`
	Signature []byte `json:"signature,omitempty"`
}

func (a *Agent) loadSchedule() (scheduleState, error) {
	var s scheduleState
	raw, e := a.store.Read("schedule.json")
	if e != nil {
		return s, e
	}
	now := time.Now().Unix()
	if storage.Decode(raw, &s, 16384) != nil || s.Format != scheduleStateFormat || s.Binding != a.binding || s.Profile != a.b.Profile.ID || !s.Config.valid() || s.NextUnix < 1 || s.NextUnix > 1<<40 || s.RetryUnix < 0 || s.RetryUnix > 1<<40 || s.LastCompletedUnix < 0 || s.LastCompletedUnix > now || s.UpdatedUnix < 1 || s.UpdatedUnix > now || s.Operation != "" && !storage.ID(s.Operation) {
		return s, ErrInvalid
	}
	if s.Phase != "PAUSED" && s.Phase != "READY" && s.Phase != "RUNNING" && s.Phase != "RETRY_WAIT" {
		return s, ErrInvalid
	}
	if (s.LastSequence == 0) != (s.LastGeneration == "") || s.LastGeneration != "" && !storage.ID(s.LastGeneration) || (s.LastSequence == 0) != (s.LastCompletedUnix == 0) {
		return s, ErrInvalid
	}
	if !scheduleCode(s.ErrorCode) {
		return s, ErrInvalid
	}
	sig := s.Signature
	s.Signature = nil
	payload, e := json.Marshal(s)
	s.Signature = sig
	if e != nil || !ed25519.Verify(a.grant.Trust.Writer, append([]byte(scheduleStateFormat+"\x00"), payload...), sig) {
		return s, ErrInvalid
	}
	return s, nil
}
func (a *Agent) saveSchedule(s scheduleState) error {
	if e := a.guard(context.Background()); e != nil {
		return e
	}
	now := time.Now().Unix()
	if now < s.UpdatedUnix {
		return ErrInvalid
	}
	s.UpdatedUnix = now
	s.Signature = nil
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	s.Signature = ed25519.Sign(a.writer, append([]byte(scheduleStateFormat+"\x00"), raw...))
	raw, e = json.Marshal(s)
	if e != nil {
		return e
	}
	return a.store.Write("schedule.json", raw)
}
func (a *Agent) ScheduleStatus(ctx context.Context) (ScheduleStatus, error) {
	var out ScheduleStatus
	e := a.store.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		s, e := a.loadSchedule()
		out = s.ScheduleStatus
		return e
	})
	return out, e
}
func (a *Agent) ConfigureSchedule(ctx context.Context, c Schedule) error {
	if !c.valid() {
		return ErrInvalid
	}
	if e := a.guard(ctx); e != nil {
		return e
	}
	lease, e := statefile.OpenAt(a.root, "scheduler", 4096, true)
	if e != nil {
		return e
	}
	defer lease.Close()
	return a.store.WithLock(ctx, func() error {
		s, e := a.loadSchedule()
		if errors.Is(e, os.ErrNotExist) {
			head, e := a.load()
			if e != nil {
				return e
			}
			s = scheduleState{ScheduleStatus: ScheduleStatus{Format: scheduleStateFormat, Profile: a.b.Profile.ID, LastSequence: head.Sequence, LastGeneration: head.Generation}, Binding: a.binding}
			if head.Sequence > 0 {
				// PREPARING/ACTIVE updates ObservedUnix for the next operation.
				// Seed from the retained signed copy evidence, never that new time.
				checkpoint, err := capture.VerifyCheckpoint(head.Checkpoint, a.grant.Trust)
				if err != nil {
					return err
				}
				s.LastCompletedUnix = checkpoint.Receipt.VerifiedAt
				for _, copy := range checkpoint.Copies {
					s.LastCompletedUnix = max(s.LastCompletedUnix, copy.ObservedUnix)
				}
				if head.Phase == "COMPLETE" {
					s.LastCompletedUnix = head.ObservedUnix
				}
			}
		} else if e != nil {
			return e
		} else {
			if c.Revision < s.Config.Revision {
				return ingress.ErrConflict
			}
			if c.Revision == s.Config.Revision {
				if c != s.Config {
					return ingress.ErrConflict
				}
				return nil
			}
		}
		if _, e = a.scheduledRelayAuthority(c); e != nil {
			return e
		}
		s.Config = c
		s.NextUnix = max(c.StartUnix, time.Now().Unix())
		s.RetryUnix = 0
		s.ErrorCode = ""
		s.Phase = "READY"
		if !c.Enabled {
			s.Phase = "PAUSED"
		}
		return a.saveSchedule(s)
	})
}
func scheduleCode(s string) bool {
	switch s {
	case "", "CANCELLED", "TIMEOUT", "COPY_THRESHOLD_PENDING", "AUTHORITY_UNAVAILABLE", "CAPACITY", "SOURCE_CHANGED", "IO_UNAVAILABLE", "SCHEDULE_CHANGED", "EXPORT_NOT_ADVANCED":
		return true
	}
	return false
}
func scheduleError(e error) string {
	switch {
	case errors.Is(e, ErrPreparedUnchanged):
		return "EXPORT_NOT_ADVANCED"
	case errors.Is(e, ErrScheduleChanged):
		return "SCHEDULE_CHANGED"
	case errors.Is(e, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.Is(e, context.Canceled):
		return "CANCELLED"
	case errors.Is(e, capture.ErrCopies), errors.Is(e, observation.ErrPending):
		return "COPY_THRESHOLD_PENDING"
	case errors.Is(e, ingress.ErrDenied):
		return "AUTHORITY_UNAVAILABLE"
	case errors.Is(e, statefile.ErrCapacity), errors.Is(e, diskbudget.ErrCapacity):
		return "CAPACITY"
	case errors.Is(e, ErrInvalid), errors.Is(e, capture.ErrInvalid):
		return "SOURCE_CHANGED"
	default:
		return "IO_UNAVAILABLE"
	}
}

// completeSchedule is called with the source capture lease held. The head is
// already durable; a failed schedule write cannot undo or duplicate that head.
func (a *Agent) completeSchedule(ctx context.Context, head state) error {
	return a.store.WithLock(ctx, func() error {
		s, e := a.loadSchedule()
		if e != nil {
			return e
		}
		if head.Phase != "COMPLETE" || head.Sequence < s.LastSequence {
			return ErrInvalid
		}
		s.LastSequence = head.Sequence
		s.LastGeneration = head.Generation
		s.LastCompletedUnix = head.ObservedUnix
		s.NextUnix = head.ObservedUnix + s.Config.IntervalSeconds
		s.RetryUnix = 0
		s.ErrorCode = ""
		s.Operation = ""
		s.Phase = "READY"
		if !s.Config.Enabled {
			s.Phase = "PAUSED"
		}
		return a.saveSchedule(s)
	})
}
func (a *Agent) attemptSchedule(ctx context.Context, expected Schedule) error {
	return a.lease.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		head, e := a.load()
		if e != nil {
			return e
		}
		if len(head.WriterFence) != 0 {
			return ErrWriterFenced
		}
		status, e := a.ScheduleStatus(ctx)
		if e != nil {
			return e
		}
		if status.Config != expected || !expected.Enabled {
			return ErrScheduleChanged
		}
		if head.Sequence < status.LastSequence {
			return ErrInvalid
		}
		if head.Phase == "COMPLETE" && head.Sequence > status.LastSequence {
			return a.completeSchedule(ctx, head)
		}
		now := time.Now().Unix()
		if now < status.RetryUnix || (head.Phase == "IDLE" || head.Phase == "COMPLETE" || head.Phase == "ABANDONED") && now < status.NextUnix {
			return nil
		}
		relay, e := a.scheduledRelayAuthority(expected)
		if e != nil {
			return e
		}
		e = a.store.WithLock(ctx, func() error {
			s, e := a.loadSchedule()
			if e != nil {
				return e
			}
			if s.Config != expected {
				return ErrScheduleChanged
			}
			if s.Attempts == ^uint64(0) {
				return ErrInvalid
			}
			s.Attempts++
			s.Phase = "RUNNING"
			s.ErrorCode = ""
			return a.saveSchedule(s)
		})
		if e != nil {
			return e
		}
		if e = a.next(ctx); e != nil {
			return e
		}
		head, e = a.load()
		if e != nil {
			return e
		}
		intent, e := a.stateIntent(head)
		if e != nil {
			return e
		}
		e = a.store.WithLock(ctx, func() error {
			s, e := a.loadSchedule()
			if e != nil {
				return e
			}
			if s.Config != expected {
				return ErrScheduleChanged
			}
			s.Operation = intent.Operation
			return a.saveSchedule(s)
		})
		if e != nil {
			return e
		}
		if e = a.runCapture(ctx, nil, nil, relay); e != nil {
			return e
		}
		head, e = a.load()
		if e != nil {
			return e
		}
		if e = a.point("source-schedule-head-observed"); e != nil {
			return e
		}
		return a.completeSchedule(ctx, head)
	})
}

// scheduleStep requires the scheduler execution lease. Configuration/status
// use another lock and remain responsive while an attempt reads source data.
func (a *Agent) scheduleStep(ctx context.Context) error {
	status, e := a.ScheduleStatus(ctx)
	if e != nil {
		return e
	}
	if !status.Config.Enabled {
		return nil
	}
	bounded, cancelDeadline := context.WithTimeout(ctx, time.Duration(status.Config.AttemptSeconds)*time.Second)
	defer cancelDeadline()
	attempt, cancel := context.WithCancelCause(bounded)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-attempt.Done():
				return
			case <-ticker.C:
				current, e := a.ScheduleStatus(attempt)
				if e != nil {
					cancel(e)
					return
				}
				if current.Config != status.Config {
					cancel(ErrScheduleChanged)
					return
				}
			}
		}
	}()
	e = a.attemptSchedule(attempt, status.Config)
	cause := context.Cause(attempt)
	cancel(nil)
	<-joined
	if e == nil {
		return nil
	}
	e = errors.Join(e, cause)
	if errors.Is(e, ErrWriterFenced) {
		return e
	}
	// Cancellation can follow a committed source head. The next pass reconciles
	// that signed head before preparing another operation. Do not erase progress.
	save, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer stop()
	if guard := a.guard(save); guard != nil {
		return errors.Join(e, guard)
	}
	writeErr := a.store.WithLock(save, func() error {
		s, err := a.loadSchedule()
		if err != nil {
			return err
		}
		if s.Config != status.Config {
			return nil
		}
		s.Phase = "RETRY_WAIT"
		s.RetryUnix = time.Now().Unix() + s.Config.RetrySeconds
		s.ErrorCode = scheduleError(e)
		return a.saveSchedule(s)
	})
	if writeErr != nil {
		return errors.Join(e, writeErr)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// A signed, well-formed schedule can retry operational failures. Corrupt
	// local state or a lost volume never becomes an unattended reset/retry loop.
	if errors.Is(e, ErrInvalid) || errors.Is(e, statefile.ErrInvalid) {
		return e
	}
	return nil
}
func (a *Agent) RunSchedule(ctx context.Context) error {
	if e := a.guard(ctx); e != nil {
		return e
	}
	if head, e := a.load(); e != nil {
		return e
	} else if len(head.WriterFence) != 0 {
		return ErrWriterFenced
	}
	if _, e := a.ScheduleStatus(ctx); e != nil {
		return e
	}
	lease, e := statefile.OpenAt(a.root, "scheduler", 4096, false)
	if e != nil {
		return e
	}
	defer lease.Close()
	return lease.WithLock(ctx, func() error {
		var nextReclaim time.Time
		for {
			if e := a.scheduleStep(ctx); e != nil {
				return e
			}
			if !time.Now().Before(nextReclaim) {
				if e := a.reclaimScheduled(ctx); e != nil {
					return e
				}
				nextReclaim = time.Now().Add(30 * time.Second)
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	})
}
