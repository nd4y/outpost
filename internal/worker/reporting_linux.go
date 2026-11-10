package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
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

// ManagementSnapshot reads bounded metadata and admits catalog-damage journal
// writes through the existing worker budget. It reads no payloads. Inventory absence
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
	budget, owned, e := w.reportingBudget(ctx, cfg)
	if e != nil {
		return out, e
	}
	if owned {
		defer budget.Close()
	}
	out.ConfigurationRevision = status.Revision
	out.EnrollmentRevision = grant.Revision
	out.Commands, e = commandObservations(status, grant.Tenant, domain)
	if e != nil {
		return out, e
	}
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
	out.ExternalState = "OBSERVED"
	out.ExternalCopies, e = externalCopyObservations(status, domain, w.node)
	if e != nil {
		return out, e
	}
	if len(out.Jobs) > 4096 {
		return out, management.ErrCapacity
	}
	sort.Slice(out.Jobs, func(i, j int) bool { return out.Jobs[i].Operation < out.Jobs[j].Operation })
	d, _ := cfg.DomainByID(domain)
	replica, e := w.openReplicaAt(w.relative(filepath.Join(DomainDirectory(w.dir, d.Trust), "replica")), d.Trust, false)
	if e == nil {
		prefix := filepath.ToSlash(w.relative(filepath.Join(DomainDirectory(w.dir, d.Trust), "replica")))
		replica.Admit = func(name string, size int) (func(bool) error, error) {
			if e := w.check(ctx); e != nil {
				return nil, e
			}
			done, e := budget.Admission(prefix)(name, size)
			if e != nil {
				return nil, e
			}
			return func(written bool) error { return errors.Join(done(written), w.check(ctx)) }, nil
		}
		recorded, re := replica.Recorded(ctx)
		ce := replica.Close()
		if re != nil || ce != nil {
			return out, errors.Join(re, ce)
		}
		out.InventoryState = "OBSERVED"
		w.addExternalAuditObservations(ctx, cfg, d, status, recentRecordedComplete(recorded, 1), out.ExternalCopies)
		for _, g := range recorded {
			state := "INCOMPLETE"
			if g.Complete {
				state = "COMPLETE"
			}
			if g.Damaged {
				state = "CORRUPT"
			}
			item := management.Generation{Generation: g.Generation, Sequence: g.Sequence, CreatedUnix: g.CreatedUnix, Status: state, Target: w.node, Verification: "NONE", Objects: uint64(g.Objects), Pinned: g.Pinned}
			if g.CatalogUnavailable {
				item.MetadataState = "UNAVAILABLE"
			}
			scrub := status.Scrubs[scrubKey(domain, d.Trust.Repository, d.Trust.Epoch, g.Generation)]
			if g.Complete && scrub.Phase == "COMPLETE" && scrub.VerifiedUnix > 0 && scrub.HealthToken == g.RepairToken {
				item.Verification = "CIPHERTEXT"
				item.VerifiedUnix = scrub.VerifiedUnix
			}
			out.Generations = append(out.Generations, item)
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

func commandObservations(status Status, tenant, domain string) ([]management.CommandObservation, error) {
	out := []management.CommandObservation{}
	if status.Controls == nil {
		return out, nil
	}
	for id, op := range status.Controls.Operations {
		if op.Work == nil || op.Tenant != tenant || op.Domain != domain {
			continue
		}
		work := op.Work
		c := management.CommandObservation{Operation: id, EnvelopeDigest: op.Envelope, Kind: op.Kind, Phase: work.Phase, CleanupPending: work.CleanupPending, Generation: op.Generation, StartedUnix: op.StartedUnix, Attempts: work.Attempts, NextAttemptMillis: work.NextMillis, VerifiedObjects: uint64(work.VerifiedObjects), TotalObjects: uint64(work.TotalObjects), ErrorCode: work.ErrorCode}
		if len(op.Ack) > 0 {
			var ack command.Ack
			if e := json.Unmarshal(op.Ack, &ack); e != nil {
				return nil, e
			}
			if ack.Operation != id || ack.EnvelopeDigest != op.Envelope || ack.State != work.Phase || ack.ErrorCode != work.ErrorCode {
				return nil, management.ErrInvalid
			}
			c.FinishedUnix = ack.ObservedUnix
			c.ResultDigest = ack.ResultDigest
			if ack.State == "COMPLETE" {
				if storage.Hash(op.Result) != ack.ResultDigest {
					return nil, management.ErrInvalid
				}
				switch op.Kind {
				case "scrub":
					var result ScrubReceipt
					if e := storage.Decode(op.Result, &result, 16<<10); e != nil {
						return nil, e
					}
					if result.Kind != "scrub" || result.Generation != op.Generation || result.Verification != "sha256-ciphertext" || result.VerifiedObjects != work.VerifiedObjects {
						return nil, management.ErrInvalid
					}
					c.Verification = "CIPHERTEXT"
					c.VerifiedUnix = result.VerifiedAt
				case "restore":
					var result recovery.Receipt
					if e := storage.Decode(op.Result, &result, 16<<10); e != nil {
						return nil, e
					}
					c.Restore = &result
					c.Verification = "DECRYPTED"
					c.VerifiedUnix = result.VerifiedUnix
				case "maintenance":
					var result MaintenanceReceipt
					if e := storage.Decode(op.Result, &result, 16<<10); e != nil {
						return nil, e
					}
					if result.Kind != "maintenance" {
						return nil, management.ErrInvalid
					}
					c.Maintenance = &result.Result
				default:
					return nil, management.ErrInvalid
				}
			}
		}
		if e := c.Validate(time.Now().Unix()); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	if len(out) > 2048 {
		return nil, management.ErrCapacity
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operation < out[j].Operation })
	return out, nil
}

// externalCopyObservations uses the immutable target identity and original
// receipt timestamp. It never probes storage or upgrades admission into proof.
func externalCopyObservations(status Status, domain, node string) ([]management.ExternalCopy, error) {
	out := []management.ExternalCopy{}
	for _, job := range status.Jobs {
		j := job.Job
		if j.Domain != domain || j.Kind != "upload" {
			continue
		}
		if !storage.ID(j.Target) || j.Executor != node {
			return nil, management.ErrInvalid
		}
		copy := management.ExternalCopy{Operation: j.Operation, Generation: j.Generation, Target: j.Target, State: "UNCONFIRMED", Verification: "NONE"}
		if len(job.Receipt) == 0 {
			if job.Phase == "COMPLETE" {
				copy.State = "UNAVAILABLE"
				copy.ErrorCode = "MISSING_RECEIPT"
			}
		} else {
			var receipt upload.Receipt
			if storage.Decode(job.Receipt, &receipt, 4096) != nil || receipt.Target != j.Target || receipt.Generation != j.Generation || receipt.Operation != j.Operation || receipt.Executor != node || (receipt.Verification != "full-target-readback" && receipt.Verification != "cached-target-readback") || receipt.ObservedUnix < 1 || receipt.ObservedUnix > job.UpdatedUnix {
				copy.State = "UNAVAILABLE"
				copy.ErrorCode = "INVALID_RECEIPT"
			} else {
				copy.State = "OBSERVED_COMPLETE"
				copy.Verification = receipt.Verification
				copy.VerifiedUnix = receipt.ObservedUnix
				copy.ReceiptDigest = storage.Hash(job.Receipt)
			}
		}
		out = append(out, copy)
	}
	if len(out) > 4096 {
		return nil, management.ErrCapacity
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operation < out[j].Operation })
	return out, nil
}

func (w *Worker) addExternalAuditObservations(ctx context.Context, cfg control.Config, d control.Domain, status Status, latest []string, copies []management.ExternalCopy) {
	interval := d.ExternalAuditIntervalSeconds
	if interval == 0 || len(latest) == 0 || cfg.Active(time.Now()) != nil || w.check(ctx) != nil {
		return
	}
	selected := scheduledExternalCopies(status, d, latest, w.node)
	if len(selected) == 0 {
		return
	}
	store, err := statefile.OpenAt(w.root, externalScheduleDirectory, 4096, false)
	if err != nil {
		return
	}
	defer store.Close()
	for i := range copies {
		copy := &copies[i]
		item := selected[externalAuditCopy{copy.Target, copy.Generation}]
		if item.Job.Operation != copy.Operation || copy.State != "OBSERVED_COMPLETE" {
			continue
		}
		if w.check(ctx) != nil {
			return
		}
		record, err := readScheduledExternalAudit(store, w.externalAuditScope(item.Job, interval))
		if err != nil || record.PolicyExpiresUnix == 0 || record.FinishedUnix > time.Now().Unix() {
			continue
		}
		observed := record.FinishedUnix
		if record.Receipt != nil {
			observed = record.Receipt.ObservedUnix
		}
		expires := min(cfg.ExpiresUnix, record.PolicyExpiresUnix, observed+interval)
		if observed >= copy.VerifiedUnix && expires > observed {
			copy.Audit = &management.ExternalAuditObservation{State: record.State, ObservedUnix: observed,
				FinishedUnix: record.FinishedUnix, ExpiresUnix: expires}
		}
	}
}
