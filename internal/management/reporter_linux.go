package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const reporterFormat = "outpost-management-reporter-1"
const maxReporter = 12 << 20

// Snapshot contains only observations. Reporter supplies identity and counters.
type Snapshot struct {
	EnrollmentRevision    uint64
	ConfigurationRevision uint64
	ObservedUnix          int64
	InventoryState        string
	Generations           []Generation
	Jobs                  []Job
	Commands              []CommandObservation
	Space                 Space
}
type ReporterOptions struct {
	Root           *os.Root
	Directory      string
	Owner          ed25519.PublicKey
	Signer         ed25519.PrivateKey
	Target, Domain string
	// Enrollment is required only for explicit first initialization. Reopen reads
	// its existing owner-signed grant; Renew is the only grant transition.
	Enrollment []byte
	Initialize bool
	Guard      func(context.Context) error
	Admission  statefile.Admission
}
type reporterState struct {
	Format       string            `json:"format"`
	Owner        ed25519.PublicKey `json:"owner"`
	Node         string            `json:"node"`
	Target       string            `json:"target"`
	Domain       string            `json:"domain"`
	Enrollment   []byte            `json:"enrollment"`
	Sequence     uint64            `json:"sequence"`
	ObservedUnix int64             `json:"observedUnix"`
	WrittenUnix  int64             `json:"writtenUnix"`
	Pending      []byte            `json:"pending"`
	Acknowledged *Receipt          `json:"acknowledged"`
	Signature    []byte            `json:"signature,omitempty"`
}
type Reporter struct {
	store, delivery, dispatch *statefile.Store
	owner                     ed25519.PublicKey
	signer                    ed25519.PrivateKey
	target, domain, node      string
	guard                     func(context.Context) error
	Fault                     func(string) error
}

func OpenReporter(o ReporterOptions) (*Reporter, error) {
	if len(o.Owner) != 32 || len(o.Signer) != 64 || !storage.ID(o.Target) || !storage.ID(o.Domain) || bytes.Equal(o.Owner, o.Signer.Public().(ed25519.PublicKey)) || !o.Initialize && o.Enrollment != nil {
		return nil, ErrInvalid
	}
	r := &Reporter{owner: append(ed25519.PublicKey(nil), o.Owner...), signer: append(ed25519.PrivateKey(nil), o.Signer...), target: o.Target, domain: o.Domain, node: identity(o.Signer.Public().(ed25519.PublicKey)), guard: o.Guard}
	if e := r.check(context.Background()); e != nil {
		return nil, e
	}
	if o.Initialize {
		var e error
		if o.Root != nil {
			_, e = o.Root.Lstat(o.Directory)
		} else {
			_, e = os.Lstat(o.Directory)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return nil, ErrConflict
		}
	}
	root, e := localfs.Directory(o.Root, o.Directory, o.Initialize)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	r.store, e = statefile.OpenAt(root, ".", maxReporter, false)
	if e != nil {
		return nil, e
	}
	r.store.Admit = o.Admission
	r.delivery, e = statefile.OpenAt(root, "delivery", 1, o.Initialize)
	if e != nil {
		r.store.Close()
		return nil, e
	}
	r.dispatch, e = statefile.OpenAt(root, "dispatch", 1, o.Initialize)
	if e != nil {
		r.store.Close()
		r.delivery.Close()
		return nil, e
	}
	e = r.store.WithLock(context.Background(), func() error {
		_, _, e := r.load()
		if !o.Initialize {
			return e
		}
		if !errors.Is(e, os.ErrNotExist) {
			return ErrConflict
		}
		grant, e := r.grant(o.Enrollment)
		if e != nil || !grant.Active(time.Now()) {
			return ErrDenied
		}
		return r.save(reporterState{Format: reporterFormat, Owner: r.owner, Node: r.node, Target: r.target, Domain: r.domain, Enrollment: append([]byte(nil), o.Enrollment...)})
	})
	if e != nil {
		r.Close()
		return nil, e
	}
	return r, nil
}
func (r *Reporter) Close() error {
	return errors.Join(r.store.Close(), r.delivery.Close(), r.dispatch.Close())
}
func (r *Reporter) check(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if r.guard != nil {
		return r.guard(ctx)
	}
	return nil
}
func (r *Reporter) point(name string) error {
	if r.Fault != nil {
		return r.Fault(name)
	}
	return nil
}
func (r *Reporter) grant(raw []byte) (Enrollment, error) {
	e, err := VerifyEnrollment(raw, r.owner)
	if err != nil {
		return e, err
	}
	if e.Node != r.node {
		return e, ErrDenied
	}
	if _, ok := e.Domain(r.domain); !ok {
		return e, ErrDenied
	}
	return e, nil
}
func (r *Reporter) load() (reporterState, Enrollment, error) {
	var s reporterState
	raw, e := r.store.Read("reporter.json")
	if e != nil {
		return s, Enrollment{}, e
	}
	if canonical(raw, &s, maxReporter) != nil || s.Format != reporterFormat || !bytes.Equal(s.Owner, r.owner) || s.Node != r.node || s.Target != r.target || s.Domain != r.domain || !safe(s.Sequence) || !validTime(s.WrittenUnix) || s.WrittenUnix > time.Now().Unix() || s.ObservedUnix < 0 || s.ObservedUnix > s.WrittenUnix || (s.Sequence == 0) != (s.ObservedUnix == 0) {
		return s, Enrollment{}, ErrInvalid
	}
	sig := s.Signature
	s.Signature = nil
	payload, _ := json.Marshal(s)
	s.Signature = sig
	if !ed25519.Verify(r.signer.Public().(ed25519.PublicKey), append([]byte(reporterFormat+"\x00"), payload...), sig) {
		return s, Enrollment{}, ErrInvalid
	}
	grant, e := r.grant(s.Enrollment)
	if e != nil {
		return s, grant, e
	}
	if s.Pending != nil {
		report, e := VerifyReport(s.Pending, grant, time.Now())
		if e != nil || report.Sequence != s.Sequence || report.ObservedUnix != s.ObservedUnix || report.Domain != r.domain {
			return s, grant, ErrInvalid
		}
	}
	if a := s.Acknowledged; a != nil {
		if a.Format != "outpost-management-receipt-1" || a.State != "COMPLETE" || a.ErrorCode != "" || !storage.ID(a.RequestDigest) || a.ResultDigest != a.RequestDigest || a.Operation != storage.Hash([]byte("report-receipt\x00"+a.RequestDigest)) || !validTime(a.ObservedUnix) || a.ObservedUnix > s.ObservedUnix {
			return s, grant, ErrInvalid
		}
	}
	return s, grant, nil
}
func (r *Reporter) save(s reporterState) error {
	if e := r.check(context.Background()); e != nil {
		return e
	}
	now := time.Now().Unix()
	if now < s.WrittenUnix {
		return ErrInvalid
	}
	s.WrittenUnix = now
	s.Signature = nil
	raw, _ := json.Marshal(s)
	s.Signature = ed25519.Sign(r.signer, append([]byte(reporterFormat+"\x00"), raw...))
	raw, _ = json.Marshal(s)
	if len(raw) > maxReporter {
		return ErrCapacity
	}
	return errors.Join(r.store.Write("reporter.json", raw), r.check(context.Background()))
}

// Enqueue refuses to overwrite a pending observation. Network I/O never holds
// the queue lock, so a slow management service cannot block local status/renewal.
func (r *Reporter) Enqueue(ctx context.Context, in Snapshot) ([]byte, error) {
	var out []byte
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, grant, e := r.load()
		if e != nil {
			return e
		}
		if !grant.Active(time.Now()) {
			return ErrDenied
		}
		if in.EnrollmentRevision != grant.Revision {
			return ErrConflict
		}
		if s.Pending != nil {
			return ErrConflict
		}
		if s.Sequence == MaxSafeInteger {
			return ErrCapacity
		}
		if in.ObservedUnix < s.ObservedUnix {
			return ErrConflict
		}
		report := Report{Format: ReportFormat, Node: r.node, Tenant: grant.Tenant, Domain: r.domain, EnrollmentRevision: grant.Revision, Sequence: s.Sequence + 1, ConfigurationRevision: in.ConfigurationRevision, ObservedUnix: in.ObservedUnix, InventoryState: in.InventoryState, Generations: in.Generations, Jobs: in.Jobs, Commands: in.Commands, Space: in.Space}
		if len(in.Commands) > 0 {
			report.Format = CommandReportFormat
			for _, c := range in.Commands {
				if c.Kind == "restore" {
					report.Format = RecoveryReportFormat
					break
				}
			}
		}
		raw, e := SignReport(report, grant, r.signer, time.Now())
		if e != nil {
			return e
		}
		s.Sequence = report.Sequence
		s.ObservedUnix = report.ObservedUnix
		s.Pending = raw
		if e = r.save(s); e != nil {
			return e
		}
		if e = r.point("management-reporter-pending-durable"); e != nil {
			return e
		}
		out = raw
		return nil
	})
	return out, e
}
func (r *Reporter) Pending(ctx context.Context) ([]byte, error) {
	var out []byte
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, _, e := r.load()
		if e == nil {
			out = append([]byte(nil), s.Pending...)
		}
		return e
	})
	return out, e
}

type ReportQueueStatus struct {
	Format             string   `json:"format"`
	Node               string   `json:"node"`
	Target             string   `json:"target"`
	Domain             string   `json:"domain"`
	EnrollmentRevision uint64   `json:"enrollmentRevision"`
	EnrollmentActive   bool     `json:"enrollmentActive"`
	Sequence           uint64   `json:"sequence"`
	ObservedUnix       int64    `json:"observedUnix"`
	PendingDigest      string   `json:"pendingDigest,omitempty"`
	Acknowledged       *Receipt `json:"acknowledged"`
}

func (r *Reporter) Status(ctx context.Context) (ReportQueueStatus, error) {
	var out ReportQueueStatus
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, g, e := r.load()
		if e != nil {
			return e
		}
		out = ReportQueueStatus{Format: "outpost-report-queue-status-1", Node: r.node, Target: r.target, Domain: r.domain, EnrollmentRevision: g.Revision, EnrollmentActive: g.Active(time.Now()), Sequence: s.Sequence, ObservedUnix: s.ObservedUnix, Acknowledged: s.Acknowledged}
		if s.Pending != nil {
			out.PendingDigest = storage.Hash(s.Pending)
		}
		return nil
	})
	return out, e
}
func (r *Reporter) Deliver(ctx context.Context, c *ReportClient) (Receipt, error) {
	var out Receipt
	if c == nil || c.target != r.target || c.node != r.node {
		return out, ErrDenied
	}
	e := r.delivery.WithLock(ctx, func() error {
		var pending []byte
		var grant Enrollment
		e := r.store.WithLock(ctx, func() error {
			if e := r.check(ctx); e != nil {
				return e
			}
			s, g, e := r.load()
			if e != nil {
				return e
			}
			grant = g
			pending = s.Pending
			return nil
		})
		if e != nil {
			return e
		}
		if pending == nil {
			return ErrUnavailable
		}
		receipt, e := c.Publish(ctx, grant, pending)
		if e != nil {
			return e
		}
		if e = r.point("management-reporter-remote-acknowledged"); e != nil {
			return e
		}
		return r.store.WithLock(ctx, func() error {
			if e := r.check(ctx); e != nil {
				return e
			}
			s, _, e := r.load()
			if e != nil {
				return e
			}
			// An explicit owner grant renewal may have superseded this telemetry while
			// the request was in flight. Its new counter/observation must be preserved.
			if !bytes.Equal(s.Pending, pending) {
				return ErrConflict
			}
			s.Pending = nil
			s.Acknowledged = &receipt
			if e = r.save(s); e != nil {
				return e
			}
			if e = r.point("management-reporter-ack-durable"); e != nil {
				return e
			}
			out = receipt
			return nil
		})
	})
	return out, e
}

// Renew is an explicit owner-signed transition, including revocation. Dropping
// obsolete pending telemetry never drops backup work; the counter is retained.
func (r *Reporter) Renew(ctx context.Context, raw []byte) error {
	next, e := r.grant(raw)
	if e != nil {
		return e
	}
	return r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, old, e := r.load()
		if e != nil {
			return e
		}
		if bytes.Equal(s.Enrollment, raw) {
			return nil
		}
		before, _ := old.Domain(r.domain)
		after, _ := next.Domain(r.domain)
		if next.Tenant != old.Tenant || next.Revision <= old.Revision || before.Repository != after.Repository || after.Epoch < before.Epoch || time.Now().Unix() < next.NotBefore || time.Now().Unix() >= next.ExpiresUnix {
			return ErrDenied
		}
		s.Enrollment = append([]byte(nil), raw...)
		s.Pending = nil
		return r.save(s)
	})
}
