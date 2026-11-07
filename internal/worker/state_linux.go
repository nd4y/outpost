// Package worker joins signed configuration, peer replication and durable cloud
// upload into a cancellable, keyless Linux worker.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

const LegacyFormat = "outpost-worker-1"
const Format = "outpost-worker-2"
const MaxJobs = 4096

var ErrDenied = errors.New("worker operation denied")
var ErrCapacity = errors.New("worker state capacity reached")

type JobState struct {
	Job         control.Job     `json:"job"`
	Binding     string          `json:"binding"`
	Phase       string          `json:"phase"`
	Attempts    uint64          `json:"attempts"`
	NextMillis  int64           `json:"nextMillis"`
	UpdatedUnix int64           `json:"updatedUnix"`
	ErrorCode   string          `json:"errorCode,omitempty"`
	Receipt     json.RawMessage `json:"receipt,omitempty"`
}
type Status struct {
	Format      string              `json:"format"`
	Node        string              `json:"node"`
	Revision    uint64              `json:"configurationRevision"`
	Phase       string              `json:"phase"`
	UpdatedUnix int64               `json:"updatedUnix"`
	Jobs        map[string]JobState `json:"jobs"`
	Rejected    map[string]string   `json:"rejectedJobs,omitempty"`
	Controls    *Controls           `json:"controls,omitempty"`
}

func binding(j control.Job) string        { b, _ := json.Marshal(j); return storage.Hash(b) }
func publicJob(j control.Job) control.Job { j.Plan = nil; return j }
func (w *Worker) load() (Status, error) {
	var s Status
	raw, e := w.state.Read("worker.json")
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, 32<<20) != nil || (s.Format != Format && s.Format != LegacyFormat) || s.Node != w.node || s.Jobs == nil || len(s.Jobs) > MaxJobs {
		return s, ErrDenied
	}
	if s.Format == LegacyFormat && s.Controls != nil || s.Format == Format && w.validateControls(s.Controls) != nil {
		return s, ErrDenied
	}
	if len(s.Rejected) > 64 {
		return s, ErrDenied
	}
	for op, code := range s.Rejected {
		if !storage.ID(op) || code != "OPERATION_CONFLICT" {
			return s, ErrDenied
		}
	}
	for id, j := range s.Jobs {
		if id != j.Job.Operation || !storage.ID(id) || !storage.ID(j.Binding) || !storage.ID(j.Job.Generation) || !storage.ID(j.Job.Domain) || j.Job.Executor != w.node || len(j.Job.Plan) != 0 || len(j.Receipt) > 1<<20 {
			return s, ErrDenied
		}
		switch j.Phase {
		case "QUEUED", "RUNNING", "RETRY_WAIT", "BLOCKED", "COMPLETE", "WITHDRAWN":
		default:
			return s, ErrDenied
		}
	}
	return s, nil
}
func (w *Worker) save(s Status) error {
	if s.Format == Format {
		if e := w.signControls(s.Controls); e != nil {
			return e
		}
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return w.state.Write("worker.json", b)
}
func (w *Worker) update(ctx context.Context, fn func(*Status) error) error {
	return w.state.WithLock(ctx, func() error {
		s, e := w.load()
		if e != nil {
			return e
		}
		if e = fn(&s); e != nil {
			return e
		}
		s.UpdatedUnix = time.Now().Unix()
		return w.save(s)
	})
}
func (w *Worker) Status(ctx context.Context) (Status, error) {
	var s Status
	e := w.state.WithLock(ctx, func() error { var e error; s, e = w.load(); return e })
	return s, e
}
func (w *Worker) admit(ctx context.Context, c control.Config) error {
	autonomy, e := c.CompileAutonomy()
	if e != nil {
		return e
	}
	return w.update(ctx, func(s *Status) error {
		s.Rejected = map[string]string{}
		current := map[string]bool{}
		for _, j := range c.Jobs {
			if j.Executor != w.node {
				continue
			}
			current[j.Operation] = true
			old, ok := s.Jobs[j.Operation]
			if ok && old.Binding != binding(j) {
				s.Rejected[j.Operation] = "OPERATION_CONFLICT"
				continue
			}
			if !ok {
				if len(s.Jobs) >= MaxJobs {
					return ErrCapacity
				}
				old = JobState{Job: publicJob(j), Binding: binding(j), Phase: "QUEUED"}
			}
			if old.Phase == "RUNNING" || old.Phase == "WITHDRAWN" {
				old.Phase = "QUEUED"
				old.NextMillis = 0
			}
			s.Jobs[j.Operation] = old
		}
		for op, j := range s.Jobs {
			if autonomy.Permits(j.Job) && j.Binding == binding(j.Job) {
				current[op] = true
				if j.Phase == "RUNNING" || j.Phase == "WITHDRAWN" {
					j.Phase = "QUEUED"
					j.NextMillis = 0
					j.ErrorCode = ""
					s.Jobs[op] = j
				}
			}
			if !current[op] && j.Phase != "COMPLETE" {
				j.Phase = "WITHDRAWN"
				j.ErrorCode = "POLICY_WITHDRAWN"
				s.Jobs[op] = j
			}
		}
		s.Revision = c.Revision
		s.Phase = "ACTIVE"
		return nil
	})
}

func errorCode(e error) string {
	switch {
	case e == nil:
		return ""
	case errors.Is(e, context.Canceled):
		return "CANCELED"
	case errors.Is(e, context.DeadlineExceeded):
		return "DEADLINE"
	case errors.Is(e, ErrCapacity), errors.Is(e, statefile.ErrCapacity):
		return "CAPACITY_BLOCKED"
	case errors.Is(e, control.ErrInactive):
		return "POLICY_EXPIRED"
	case errors.Is(e, peer.ErrDenied), errors.Is(e, upload.ErrDenied), errors.Is(e, storage.ErrDenied), errors.Is(e, ErrDenied), errors.Is(e, observation.ErrDenied):
		return "POLICY_BLOCKED"
	case errors.Is(e, peer.ErrConflict), errors.Is(e, upload.ErrConflict), errors.Is(e, generation.ErrConflict), errors.Is(e, generation.ErrRollback):
		return "CONFLICT"
	case errors.Is(e, upload.ErrBlocked):
		return "TARGET_BLOCKED"
	case errors.Is(e, generation.ErrIncomplete):
		return "DATA_INCOMPLETE"
	default:
		return "RETRY_REQUIRED"
	}
}
func blocked(code string) bool {
	return code == "CAPACITY_BLOCKED" || code == "POLICY_BLOCKED" || code == "CONFLICT" || code == "TARGET_BLOCKED" || code == "DATA_INCOMPLETE"
}
func (w *Worker) initState(initialize bool) error {
	return w.state.WithLock(context.Background(), func() error {
		_, e := w.state.Read("worker.json")
		if !errors.Is(e, os.ErrNotExist) || !initialize {
			return e
		}
		commands, e := statefile.OpenAt(w.root, "commands/poll", 4096, true)
		if e != nil {
			return e
		}
		if e = commands.Close(); e != nil {
			return e
		}
		return w.save(Status{Format: Format, Node: w.node, Phase: "NO_CONFIGURATION", Jobs: map[string]JobState{}, Controls: newControls(w.node)})
	})
}
