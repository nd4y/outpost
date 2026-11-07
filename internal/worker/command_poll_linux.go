package worker

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/command"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const CommandProfileFormat = "outpost-command-profile-1"

type CommandProfile struct {
	Format         string `json:"format"`
	Endpoint       string `json:"endpoint"`
	Identity       string `json:"identity"`
	EnrollmentFile string `json:"enrollmentFile"`
	PollSeconds    int64  `json:"pollSeconds"`
	RetrySeconds   int64  `json:"retrySeconds"`
	AttemptSeconds int64  `json:"attemptSeconds"`
}

func (p CommandProfile) Validate() error {
	if p.Format != CommandProfileFormat || !policy.Endpoint(p.Endpoint) || !storage.ID(p.Identity) || !filepath.IsAbs(p.EnrollmentFile) || p.PollSeconds < 1 || p.PollSeconds > 3600 || p.RetrySeconds < 1 || p.RetrySeconds > 3600 || p.AttemptSeconds < 1 || p.AttemptSeconds > 300 {
		return ErrDenied
	}
	return nil
}
func LoadCommandProfile(path string) (CommandProfile, error) {
	var p CommandProfile
	raw, e := ReadPrivate(path, 65536)
	if e != nil {
		return p, e
	}
	if DecodeInput(raw, &p, 65536) != nil || p.Validate() != nil {
		return p, ErrDenied
	}
	return p, nil
}

type CommandDelivery struct {
	Phase        string `json:"phase"`
	Target       string `json:"target"`
	Tenant       string `json:"tenant"`
	Operation    string `json:"operation,omitempty"`
	AttemptUnix  int64  `json:"attemptUnix"`
	ObservedUnix int64  `json:"observedUnix"`
	NextUnix     int64  `json:"nextUnix"`
	ErrorCode    string `json:"errorCode,omitempty"`
}

func (d CommandDelivery) validate() error {
	if !storage.ID(d.Target) || !storage.ID(d.Tenant) || d.Operation != "" && !storage.ID(d.Operation) || d.AttemptUnix <= 0 || d.ObservedUnix < d.AttemptUnix || d.NextUnix < d.AttemptUnix || d.ObservedUnix > time.Now().Unix() {
		return ErrDenied
	}
	switch d.Phase {
	case "RUNNING", "IDLE", "ACKNOWLEDGED", "EXECUTING":
		if d.ErrorCode != "" {
			return ErrDenied
		}
	case "RETRY_WAIT":
		if d.ErrorCode == "" {
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	return nil
}

type CommandResult struct {
	Operation string `json:"operation,omitempty"`
	State     string `json:"state"`
	ErrorCode string `json:"errorCode,omitempty"`
}

// CommandOnce always starts at the first unacknowledged command. A lost reply
// reuses the worker's durable acknowledgement rather than executing again.
func (w *Worker) CommandOnce(ctx context.Context, client *management.ReportClient, enrollment []byte) (CommandResult, error) {
	out := CommandResult{State: "IDLE"}
	grant, e := management.VerifyEnrollment(enrollment, w.owner)
	if e != nil || grant.Node != w.node || !grant.Active(time.Now()) {
		return out, ErrDenied
	}
	page, e := client.Commands(ctx, grant, w.owner, 32, "")
	if e != nil {
		return out, e
	}
	if len(page.Commands) == 0 {
		return out, nil
	}
	var pending *CommandResult
	for _, queued := range page.Commands {
		raw := queued.Document
		envelope, _, e := command.VerifyEnvelope(raw, w.owner)
		if e != nil {
			return out, e
		}
		out = CommandResult{Operation: envelope.Request.Operation, State: "EXECUTING"}
		ack, e := w.ExecuteCommand(ctx, raw)
		if e != nil {
			return out, e
		}
		if len(ack) == 0 {
			if pending == nil {
				copy := out
				pending = &copy
			}
			continue
		}
		receipt, e := client.AcknowledgeCommand(ctx, grant, w.owner, raw, ack)
		if e != nil {
			out.State = "ACK_PENDING"
			return out, e
		}
		out.State, out.ErrorCode = receipt.State, receipt.ErrorCode
	}
	if pending != nil {
		return *pending, nil
	}
	return out, nil
}

// RunCommands is a separate foreground process from backup execution. Its
// retry deadline is persisted before each attempt; errors never drop intent.
func (w *Worker) RunCommands(ctx context.Context, profile CommandProfile, enrollment []byte, client *management.ReportClient) error {
	if profile.Validate() != nil || !client.Matches(profile.Identity, w.node) {
		return ErrDenied
	}
	grant, e := management.VerifyEnrollment(enrollment, w.owner)
	if e != nil || grant.Node != w.node {
		return ErrDenied
	}
	lease, e := statefile.OpenAt(w.root, "commands/poll", 4096, false)
	if e != nil {
		return e
	}
	defer lease.Close()
	return lease.WithLock(ctx, func() error {
		state, _, close, e := w.commandSession(ctx)
		if e != nil {
			return e
		}
		defer close()
		for {
			if ctx.Err() != nil {
				return nil
			}
			if e = w.check(ctx); e != nil {
				return e
			}
			s, e := state.Status(ctx)
			if e != nil {
				return e
			}
			if s.Controls == nil {
				return ErrDenied
			}
			if d := s.Controls.Delivery; d != nil {
				if d.Target != profile.Identity || d.Tenant != grant.Tenant || d.AttemptUnix > time.Now().Unix() {
					return ErrDenied
				}
				if d.NextUnix > time.Now().Unix() {
					timer := time.NewTimer(time.Until(time.Unix(d.NextUnix, 0)))
					select {
					case <-ctx.Done():
						timer.Stop()
						return nil
					case <-timer.C:
					}
				}
			}
			now := time.Now().Unix()
			d := CommandDelivery{Phase: "RUNNING", Target: profile.Identity, Tenant: grant.Tenant, AttemptUnix: now, ObservedUnix: now, NextUnix: now + profile.RetrySeconds}
			if e = state.update(ctx, func(s *Status) error {
				if s.Controls == nil {
					return ErrDenied
				}
				s.Controls.Delivery = &d
				return nil
			}); e != nil {
				return e
			}
			attempt, cancel := context.WithTimeout(ctx, time.Duration(profile.AttemptSeconds)*time.Second)
			result, runErr := w.CommandOnce(attempt, client, enrollment)
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			d.ObservedUnix = time.Now().Unix()
			d.Operation = result.Operation
			if runErr != nil {
				d.Phase = "RETRY_WAIT"
				d.ErrorCode = "RETRY_REQUIRED"
				if errors.Is(runErr, ErrDenied) || errors.Is(runErr, management.ErrDenied) {
					d.ErrorCode = "POLICY_BLOCKED"
				}
				d.NextUnix = d.ObservedUnix + profile.RetrySeconds
			} else {
				d.Phase = "ACKNOWLEDGED"
				if result.State == "IDLE" || result.State == "EXECUTING" {
					d.Phase = result.State
				}
				d.NextUnix = d.ObservedUnix + profile.PollSeconds
			}
			if e = state.update(ctx, func(s *Status) error {
				if s.Controls == nil {
					return ErrDenied
				}
				s.Controls.Delivery = &d
				return nil
			}); e != nil {
				return e
			}
		}
	})
}
