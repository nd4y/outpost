package worker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

// reportConfiguration checks independent reporting enrollment against the
// existing owner policy. Reporting cannot enroll a domain or change placement.
func (w *Worker) reportConfiguration(ctx context.Context, grant management.Enrollment, domain string) (control.Config, error) {
	var out control.Config
	if e := w.check(ctx); e != nil {
		return out, e
	}
	if grant.Node != w.node || !grant.Active(time.Now()) {
		return out, management.ErrDenied
	}
	admission, ok := grant.Domain(domain)
	if !ok {
		return out, management.ErrDenied
	}
	raw, e := w.cache.Raw(ctx)
	if e != nil {
		return out, e
	}
	out, e = w.cache.Verify(raw)
	if e != nil {
		return out, e
	}
	d, ok := out.DomainByID(domain)
	node, exists := out.NodeByID(w.node)
	if !ok || !exists || node.Class != grant.Class || d.Trust.Repository != admission.Repository || d.Trust.Epoch != admission.Epoch {
		return out, management.ErrDenied
	}
	return out, nil
}

// OpenReporter puts its bounded journal in the telemetry budget, never backup
// spool/data capacity. It uses an existing budget; it never reconciles live jobs.
type Reporter struct {
	*management.Reporter
	ownedBudget *diskbudget.Budget
}

func (r *Reporter) Close() error {
	e := r.Reporter.Close()
	if r.ownedBudget != nil {
		e = errors.Join(e, r.ownedBudget.Close())
	}
	return e
}

func (w *Worker) reportingBudget(ctx context.Context, cfg control.Config) (*diskbudget.Budget, bool, error) {
	w.budgetMu.Lock()
	budget := w.budget
	w.budgetMu.Unlock()
	if budget != nil {
		return budget, false, nil
	}
	// A read/control process never steals or reconciles the execution process's
	// live reservations. It owns a separate existing-ledger handle only.
	b, e := diskbudget.OpenAt(w.root, ctx, ".", diskbudget.Limits{Capacity: cfg.Limits.CapacityBytes, Reserve: cfg.Limits.ReserveBytes, Spool: cfg.Limits.SpoolBytes, Telemetry: cfg.Limits.TelemetryBytes}, false)
	return b, true, e
}
func (w *Worker) OpenReporter(ctx context.Context, target, domain string, enrollment []byte, initialize bool) (*Reporter, error) {
	grant, e := management.VerifyEnrollment(enrollment, w.owner)
	if e != nil {
		return nil, e
	}
	if grant.Node != w.node {
		return nil, management.ErrDenied
	}
	if _, ok := grant.Domain(domain); !ok {
		return nil, management.ErrDenied
	}
	if initialize {
		if _, e = w.reportConfiguration(ctx, grant, domain); e != nil {
			return nil, e
		}
	}
	cached, e := w.cache.Raw(ctx)
	if e != nil {
		return nil, e
	}
	cfg, e := w.cache.Verify(cached)
	if e != nil {
		return nil, e
	}
	budget, owned, e := w.reportingBudget(ctx, cfg)
	if e != nil {
		return nil, e
	}
	relative := "telemetry/management/" + storage.Hash([]byte(target+"/"+domain))
	raw := enrollment
	if !initialize {
		raw = nil
	}
	r, e := management.OpenReporter(management.ReporterOptions{Root: w.root, Directory: relative, Owner: w.owner, Signer: w.cert.PrivateKey.(ed25519.PrivateKey), Target: target, Domain: domain, Enrollment: raw, Initialize: initialize, Guard: w.check, Admission: budget.Admission(relative)})
	if e != nil {
		if owned {
			budget.Close()
		}
		return nil, e
	}
	out := &Reporter{Reporter: r}
	if owned {
		out.ownedBudget = budget
	}
	return out, nil
}

// ManagementSnapshot reads bounded metadata, not payloads. Inventory absence
// is explicit; it cannot turn a missing mount/journal into an empty healthy copy.
func (w *Worker) ManagementSnapshot(ctx context.Context, enrollment []byte, domain string) (management.Snapshot, error) {
	out := management.Snapshot{Generations: []management.Generation{}, Jobs: []management.Job{}, Space: management.Space{State: "UNKNOWN"}, InventoryState: "UNAVAILABLE"}
	grant, e := management.VerifyEnrollment(enrollment, w.owner)
	if e != nil {
		return out, e
	}
	cfg, e := w.reportConfiguration(ctx, grant, domain)
	if e != nil {
		return out, e
	}
	status, e := w.Status(ctx)
	if e != nil {
		return out, e
	}
	if status.Revision != cfg.Revision {
		return out, management.ErrConflict
	}
	out.ConfigurationRevision = status.Revision
	out.EnrollmentRevision = grant.Revision
	for _, j := range status.Jobs {
		if j.Job.Domain != domain {
			continue
		}
		kind := "PEER"
		switch j.Job.Kind {
		case "push", "pull":
		case "upload":
			kind = "UPLOAD"
		default:
			return out, management.ErrInvalid
		}
		out.Jobs = append(out.Jobs, management.Job{Operation: j.Job.Operation, Domain: domain, Generation: j.Job.Generation, Kind: kind, Phase: j.Phase, UpdatedUnix: j.UpdatedUnix, ErrorCode: j.ErrorCode})
	}
	if len(out.Jobs) > 4096 {
		return out, management.ErrCapacity
	}
	sort.Slice(out.Jobs, func(i, j int) bool { return out.Jobs[i].Operation < out.Jobs[j].Operation })
	d, _ := cfg.DomainByID(domain)
	replica, e := generation.OpenAt(w.root, w.relative(filepath.Join(DomainDirectory(w.dir, d.Trust), "replica")), d.Trust, false)
	if e == nil {
		recorded, re := replica.Recorded(ctx)
		ce := replica.Close()
		if re != nil || ce != nil {
			return out, errors.Join(re, ce)
		}
		out.InventoryState = "OBSERVED"
		for _, g := range recorded {
			state := "INCOMPLETE"
			if g.Complete {
				state = "COMPLETE"
			}
			out.Generations = append(out.Generations, management.Generation{Generation: g.Generation, Sequence: g.Sequence, CreatedUnix: g.CreatedUnix, Status: state, Target: w.node, Verification: "NONE", Objects: uint64(g.Objects), Pinned: g.Pinned})
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return out, e
	}
	// Read physical usage from the admitted held filesystem, independently of
	// Outpost's conservative accounting ledger. Other applications may share it.
	directory, e := w.root.Open(".")
	if e != nil {
		return out, e
	}
	var fs syscall.Statfs_t
	e = syscall.Fstatfs(int(directory.Fd()), &fs)
	ce := directory.Close()
	if e != nil || ce != nil {
		return out, errors.Join(e, ce)
	}
	if fs.Bsize <= 0 || fs.Bfree > fs.Blocks || fs.Bavail > fs.Blocks || fs.Blocks > management.MaxSafeInteger/uint64(fs.Bsize) {
		return out, management.ErrInvalid
	}
	used, free := int64(fs.Blocks-fs.Bfree)*fs.Bsize, int64(fs.Bavail)*fs.Bsize
	budget, owned, e := w.reportingBudget(ctx, cfg)
	if e != nil {
		return out, e
	}
	if owned {
		defer budget.Close()
	}
	var accounted, reserved *int64
	if budget != nil {
		ledger, e := budget.Status(ctx)
		if e != nil {
			return out, e
		}
		a, b := int64(0), int64(0)
		for _, n := range ledger.Used {
			if n < 0 || n > management.MaxSafeInteger-a {
				return out, management.ErrInvalid
			}
			a += n
		}
		for _, r := range ledger.Pending {
			if r.Bytes < 0 || r.Bytes > management.MaxSafeInteger-b {
				return out, management.ErrInvalid
			}
			b += r.Bytes
		}
		accounted, reserved = &a, &b
	}
	latest, e := w.cache.Raw(ctx)
	if e != nil {
		return out, e
	}
	current, e := w.cache.Verify(latest)
	if e != nil {
		return out, e
	}
	if current.Revision != cfg.Revision {
		return out, management.ErrConflict
	}
	if e = w.check(ctx); e != nil {
		return out, e
	}
	out.ObservedUnix = time.Now().Unix()
	out.Space = management.Space{State: "OBSERVED", Scope: "VOLUME", PhysicalBytes: &used, FreeBytes: &free, AccountedBytes: accounted, ReservedBytes: reserved, ObservedUnix: out.ObservedUnix}
	return out, nil
}
