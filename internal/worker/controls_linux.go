package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const controlsFormat = "outpost-worker-controls-1"
const maxCommands = 2048

type CommandRecord struct {
	Tenant      string       `json:"tenant,omitempty"`
	Envelope    string       `json:"envelope"`
	Service     string       `json:"service"`
	Sequence    uint64       `json:"sequence"`
	Domain      string       `json:"domain"`
	Kind        string       `json:"kind"`
	Job         string       `json:"job,omitempty"`
	JobBinding  string       `json:"jobBinding,omitempty"`
	Generation  string       `json:"generation,omitempty"`
	Work        *CommandWork `json:"work,omitempty"`
	Result      []byte       `json:"result,omitempty"`
	StartedUnix int64        `json:"startedUnix"`
	Revision    uint64       `json:"revision"`
	Ack         []byte       `json:"ack,omitempty"`
}
type CommandWork struct {
	Phase           string `json:"phase"`
	Attempts        uint64 `json:"attempts"`
	NextMillis      int64  `json:"nextMillis"`
	VerifiedObjects int    `json:"verifiedObjects"`
	TotalObjects    int    `json:"totalObjects"`
	ErrorCode       string `json:"errorCode,omitempty"`
}
type Controls struct {
	Format     string                   `json:"format"`
	Node       string                   `json:"node"`
	Revision   uint64                   `json:"revision"`
	Applied    uint64                   `json:"appliedRevision"`
	Domains    map[string]bool          `json:"pausedDomains"`
	Jobs       map[string]string        `json:"pausedJobs"`
	Sequences  map[string]uint64        `json:"sequences"`
	Operations map[string]CommandRecord `json:"operations"`
	Delivery   *CommandDelivery         `json:"delivery,omitempty"`
	Signature  []byte                   `json:"signature,omitempty"`
}

func newControls(node string) *Controls {
	return &Controls{Format: controlsFormat, Node: node, Revision: 1, Applied: 1, Domains: map[string]bool{}, Jobs: map[string]string{}, Sequences: map[string]uint64{}, Operations: map[string]CommandRecord{}}
}
func controlRevision(c *Controls) uint64 {
	if c == nil {
		return 0
	}
	return c.Revision
}
func (c *Controls) paused(domain, job string) bool {
	return c != nil && (c.Domains[domain] || job != "" && c.Jobs[job] == domain)
}
func (v *view) paused(domain, job string) bool { return v.controls.paused(domain, job) }
func (w *Worker) signControls(c *Controls) error {
	if c == nil {
		return ErrDenied
	}
	c.Signature = nil
	raw, e := json.Marshal(c)
	if e != nil {
		return e
	}
	c.Signature = ed25519.Sign(w.cert.PrivateKey.(ed25519.PrivateKey), append([]byte(controlsFormat+"\x00"), raw...))
	return nil
}
func (w *Worker) validateControls(c *Controls) error {
	if c == nil || c.Format != controlsFormat || c.Node != w.node || c.Revision == 0 || c.Revision > command.MaxSafeInteger || c.Applied > c.Revision || c.Domains == nil || len(c.Domains) > 128 || c.Jobs == nil || len(c.Jobs) > MaxJobs || c.Sequences == nil || len(c.Sequences) > 256 || c.Operations == nil || len(c.Operations) > maxCommands {
		return ErrDenied
	}
	for id, pause := range c.Domains {
		if !storage.ID(id) || !pause {
			return ErrDenied
		}
	}
	for id, domain := range c.Jobs {
		if !storage.ID(id) || !storage.ID(domain) {
			return ErrDenied
		}
	}
	for id, seq := range c.Sequences {
		if !storage.ID(id) || seq == 0 || seq > command.MaxSafeInteger {
			return ErrDenied
		}
	}
	pendingControl, pendingWork := 0, 0
	for id, op := range c.Operations {
		if !storage.ID(id) || !storage.ID(op.Envelope) || !storage.ID(op.Service) || op.Sequence == 0 || op.Sequence > c.Sequences[command.SequenceScope(op.Service, op.Kind)] || !storage.ID(op.Domain) || !command.Kind(op.Kind) || op.Job != "" && !storage.ID(op.Job) || op.StartedUnix < 0 || op.StartedUnix > time.Now().Unix() || op.Revision > c.Revision || len(op.Ack) > command.MaxAck {
			return ErrDenied
		}
		if op.JobBinding != "" && (op.Kind != "retry" || !storage.ID(op.JobBinding)) || op.Kind == "retry" && op.StartedUnix > 0 && op.JobBinding == "" {
			return ErrDenied
		}
		if len(op.Result) > 16<<10 || op.Generation != "" && !storage.ID(op.Generation) {
			return ErrDenied
		}
		if op.Kind == "scrub" && op.StartedUnix > 0 && (op.Generation == "" || op.Work == nil) {
			return ErrDenied
		}
		if op.Kind == "maintenance" && (op.Generation != "" || op.StartedUnix > 0 && op.Work == nil) {
			return ErrDenied
		}
		if op.Work != nil {
			if !storage.ID(op.Tenant) {
				return ErrDenied
			}
			if (op.Kind != "scrub" && op.Kind != "maintenance") || op.Work.Attempts > command.MaxSafeInteger || op.Work.NextMillis < 0 || op.Work.VerifiedObjects < 0 || op.Work.TotalObjects < op.Work.VerifiedObjects {
				return ErrDenied
			}
			switch op.Work.Phase {
			case "QUEUED", "RUNNING", "RETRY_WAIT":
				if len(op.Ack) > 0 {
					return ErrDenied
				}
			case "COMPLETE", "FAILED":
				if len(op.Ack) == 0 {
					return ErrDenied
				}
			default:
				return ErrDenied
			}
		}
		if len(op.Ack) == 0 {
			if command.Control(op.Kind) {
				pendingControl++
			} else {
				pendingWork++
			}
		}
	}
	if pendingControl > 1 || pendingWork > 32 {
		return ErrDenied
	}
	if c.Delivery != nil && c.Delivery.validate() != nil {
		return ErrDenied
	}
	copy := *c
	copy.Signature = nil
	raw, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	if !ed25519.Verify(w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), append([]byte(controlsFormat+"\x00"), raw...), c.Signature) {
		return ErrDenied
	}
	return nil
}

// MigrateControls excludes the running worker, preserves a byte-exact backup,
// and atomically changes the state format. Legacy binaries reject format 2.
// Rollback preserves current jobs but is refused after any command or hold.
func (w *Worker) MigrateControls(ctx context.Context, rollback bool) error {
	if e := w.check(ctx); e != nil {
		return e
	}
	acquire, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	e := w.lease.WithLock(acquire, func() error {
		raw, e := w.cache.Raw(ctx)
		if e != nil {
			return e
		}
		cfg, e := w.cache.Verify(raw)
		if e != nil {
			return e
		}
		if _, e = w.budgetFor(ctx, cfg, false); e != nil {
			return e
		}
		return w.state.WithLock(ctx, func() error {
			s, e := w.load()
			if e != nil {
				return e
			}
			if rollback {
				if s.Format == LegacyFormat {
					return nil
				}
				if len(s.Controls.Operations) != 0 || len(s.Controls.Domains) != 0 || len(s.Controls.Jobs) != 0 || s.Controls.Applied != s.Controls.Revision {
					return ErrDenied
				}
			} else if s.Format == Format {
				return nil
			}
			previous, e := w.state.Read("worker.json")
			if e != nil {
				return e
			}
			if e = w.state.Write("worker-backup-"+storage.Hash(previous)+".json", previous); e != nil {
				return e
			}
			if e = w.point("worker-controls-backup-durable"); e != nil {
				return e
			}
			if rollback {
				s.Format = LegacyFormat
				s.Controls = nil
			} else {
				commands, e := statefile.OpenAt(w.root, "commands/poll", 4096, true)
				if e != nil {
					return e
				}
				if e = commands.Close(); e != nil {
					return e
				}
				if e = w.point("worker-controls-directory-durable"); e != nil {
					return e
				}
				s.Format = Format
				s.Controls = newControls(w.node)
			}
			if e = w.save(s); e != nil {
				return e
			}
			return w.point("worker-controls-format-durable")
		})
	})
	if errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil {
		return ErrDenied
	}
	return e
}

// A command process owns separate handles and never reconciles or steals the
// execution process's disk reservations. Its state mutations use the same lock.
func (w *Worker) commandSession(ctx context.Context) (*Worker, *statefile.Store, func(), error) {
	raw, e := w.cache.Raw(ctx)
	if e != nil {
		return nil, nil, nil, e
	}
	cfg, e := w.cache.Verify(raw)
	if e != nil {
		return nil, nil, nil, e
	}
	budget, owned, e := w.reportingBudget(ctx, cfg)
	if e != nil {
		return nil, nil, nil, e
	}
	cleanup := func() {
		if owned {
			budget.Close()
		}
	}
	state, e := statefile.OpenAt(w.root, "state", 32<<20, false)
	if e != nil {
		cleanup()
		return nil, nil, nil, e
	}
	commands, e := statefile.OpenAt(w.root, "commands", command.MaxEnvelope, false)
	if e != nil {
		state.Close()
		cleanup()
		return nil, nil, nil, e
	}
	guardAdmission := func(prefix string) statefile.Admission {
		return func(name string, n int) (func(bool) error, error) {
			if e := w.check(ctx); e != nil {
				return nil, e
			}
			done, e := budget.Admission(prefix)(name, n)
			if e != nil {
				return nil, e
			}
			return func(written bool) error { return errors.Join(done(written), w.check(ctx)) }, nil
		}
	}
	state.Admit = guardAdmission("state")
	commands.Admit = guardAdmission("commands")
	cache, e := control.OpenCacheAdmittedAt(w.root, "control", w.node, w.owner, false, guardAdmission("control"))
	if e != nil {
		commands.Close()
		state.Close()
		cleanup()
		return nil, nil, nil, e
	}
	shadow := &Worker{state: state, cache: cache, node: w.node, cert: w.cert, owner: w.owner, root: w.root, dir: w.dir, budget: budget, guard: w.guard}
	return shadow, commands, func() { cache.Close(); commands.Close(); state.Close(); cleanup() }, nil
}

// The caller holds the execution lease and has joined the previous view.
func (w *Worker) markControlsApplied(ctx context.Context) error {
	s, e := w.Status(ctx)
	if e != nil {
		return e
	}
	if s.Controls == nil || s.Controls.Applied == s.Controls.Revision {
		return nil
	}
	return w.update(ctx, func(s *Status) error {
		if s.Controls != nil {
			s.Controls.Applied = s.Controls.Revision
		}
		return nil
	})
}
