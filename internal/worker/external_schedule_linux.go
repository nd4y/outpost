package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

const externalScheduleDirectory = "telemetry/external-schedule"
const ExternalAuditStatusFormat = "outpost-worker-external-audit-status-1"

type ExternalAuditStatus struct {
	Format            string                     `json:"format"`
	Node              string                     `json:"node"`
	Operation         string                     `json:"operation"`
	Window            string                     `json:"window"`
	Target            string                     `json:"target"`
	Generation        string                     `json:"generation"`
	Ready             bool                       `json:"ready"`
	State             string                     `json:"state"`
	FinishedUnix      int64                      `json:"finishedUnix,omitempty"`
	PolicyExpiresUnix int64                      `json:"policyExpiresUnix,omitempty"`
	Receipt           *upload.TargetAuditReceipt `json:"receipt,omitempty"`
	Repair            *upload.MissingRepair      `json:"repair,omitempty"`
}

func scheduledExternalProfile(operation string, interval int64) ExternalAuditProfile {
	return ExternalAuditProfile{
		Format: ExternalAuditProfileFormat, Window: storage.Hash([]byte("external-schedule/" + operation + "/" + strconv.FormatInt(interval, 10))),
		MaxAgeSeconds: interval - 1,
	}
}

func readScheduledExternalAudit(store *statefile.Store, scope ExternalAuditStatus) (ExternalAuditStatus, error) {
	var record ExternalAuditStatus
	raw, err := store.Read(scope.Window + ".json")
	if err != nil {
		return record, err
	}
	if storage.Decode(raw, &record, 4096) != nil || record.Format != scope.Format || record.Node != scope.Node ||
		record.Window != scope.Window || record.Operation != scope.Operation || record.Target != scope.Target ||
		record.Generation != scope.Generation || record.FinishedUnix < 0 {
		return record, ErrDenied
	}
	if r := record.Repair; r != nil && (record.State != "MISSING" || !record.Ready ||
		r.ObservedUnix != record.FinishedUnix || !r.Valid(1, 1<<40)) {
		return record, ErrDenied
	}
	if record.PolicyExpiresUnix != 0 && (record.FinishedUnix == 0 || record.PolicyExpiresUnix > 1<<40 ||
		record.PolicyExpiresUnix <= record.FinishedUnix) {
		return record, ErrDenied
	}
	switch record.State {
	case "PENDING":
		if record.Receipt == nil && record.FinishedUnix == 0 {
			return record, nil
		}
	case "VERIFIED_CIPHERTEXT":
		r := record.Receipt
		if record.Ready && r != nil && r.Format == upload.TargetAuditWindowFormat && r.Window == record.Window && r.Target == record.Target &&
			r.Generation == record.Generation && storage.ID(r.Plan) && r.ObservedUnix > 0 && r.ObservedUnix <= r.FinishedUnix &&
			r.FinishedUnix == record.FinishedUnix {
			return record, nil
		}
	case "MISSING", "INVALID_CONTENT", "UNAVAILABLE":
		if record.Receipt == nil && record.FinishedUnix > 0 {
			return record, nil
		}
	}
	return record, ErrDenied
}

func (w *Worker) externalAuditScope(job control.Job, interval int64) ExternalAuditStatus {
	p := scheduledExternalProfile(job.Operation, interval)
	return ExternalAuditStatus{
		Format: ExternalAuditStatusFormat, Node: w.node, Operation: job.Operation,
		Window: p.Window, Target: job.Target, Generation: job.Generation, State: "PENDING",
	}
}

// ScheduledExternalAuditStatus reads the bounded latest outcome for the
// requested retained operation in the current policy, without target I/O.
func (w *Worker) ScheduledExternalAuditStatus(ctx context.Context, operation string) (ExternalAuditStatus, error) {
	var result ExternalAuditStatus
	if !storage.ID(operation) {
		return result, ErrDenied
	}
	if err := w.check(ctx); err != nil {
		return result, err
	}
	cached, err := w.cache.Raw(ctx)
	if err != nil {
		return result, err
	}
	c, err := w.cache.Verify(cached)
	if err != nil {
		return result, err
	}
	if err = c.Active(time.Now()); err != nil {
		return result, err
	}
	status, err := w.Status(ctx)
	if err != nil {
		return result, err
	}
	record, ok := status.Jobs[operation]
	d, admitted := c.DomainByID(record.Job.Domain)
	if !ok || !admitted || record.Job.Kind != "upload" || record.Job.Executor != w.node || record.Phase != "COMPLETE" ||
		d.ExternalAuditIntervalSeconds == 0 || !d.Placement.PermitsCloud(w.node, record.Job.Target) {
		return result, ErrDenied
	}
	store, err := statefile.OpenAt(w.root, externalScheduleDirectory, 4096, false)
	if err != nil {
		return result, err
	}
	defer store.Close()
	result, err = readScheduledExternalAudit(store, w.externalAuditScope(record.Job, d.ExternalAuditIntervalSeconds))
	if err == nil && result.Receipt != nil {
		now := time.Now().Unix()
		if result.Receipt.ObservedUnix > now || now-result.Receipt.ObservedUnix >= d.ExternalAuditIntervalSeconds ||
			(result.PolicyExpiresUnix > 0 && now >= result.PolicyExpiresUnix) {
			result.State = "STALE"
		}
	}
	return result, err
}

type externalAuditCandidate struct {
	job      control.Job
	interval int64
	record   ExternalAuditStatus
	new      bool
	latest   bool
}

func recentRecordedComplete(entries []generation.RecordedGeneration, limit int) []string {
	recent := make([]string, 0, limit)
	for i := len(entries) - 1; i >= 0 && len(recent) < limit; i-- {
		if entries[i].Complete {
			recent = append(recent, entries[i].Generation)
		}
	}
	return recent
}

type externalAuditCopy struct{ target, generation string }

func scheduledExternalCopies(status Status, d control.Domain, recent []string, node string) map[externalAuditCopy]JobState {
	generations := map[string]bool{}
	for _, id := range recent {
		generations[id] = true
	}
	copies := map[externalAuditCopy]JobState{}
	for _, item := range status.Jobs {
		j := item.Job
		if item.Phase != "COMPLETE" || j.Kind != "upload" || j.MissingRepair != nil || j.Domain != d.Trust.Domain ||
			!generations[j.Generation] || j.Executor != node || !d.Placement.PermitsCloud(node, j.Target) {
			continue
		}
		key := externalAuditCopy{j.Target, j.Generation}
		old := copies[key]
		if item.UpdatedUnix > old.UpdatedUnix || (item.UpdatedUnix == old.UpdatedUnix && j.Operation > old.Job.Operation) {
			copies[key] = item
		}
	}
	return copies
}

func (w *Worker) scheduleExternalAudit(v *view, status Status, running map[string]bool, results chan<- result) {
	now := time.Now()
	if v.ctx.Err() != nil || w.resolve == nil || now.Before(v.nextExternalAuditScan) {
		return
	}
	v.nextExternalAuditScan = now.Add(time.Second)
	var store *statefile.Store
	var selected *externalAuditCandidate
	for _, d := range v.cfg.Domains {
		interval := d.ExternalAuditIntervalSeconds
		local := v.domains[d.Trust.Domain]
		if interval == 0 || local == nil || v.paused(d.Trust.Domain, "") || status.Controls.paused(d.Trust.Domain, "") {
			continue
		}
		entries, err := local.replica.Recorded(v.ctx)
		if err != nil {
			continue
		}
		recent := recentRecordedComplete(entries, max(1, d.ExternalAuditGenerations))
		if len(recent) == 0 {
			continue
		}
		copies := scheduledExternalCopies(status, d, recent, w.node)
		for _, copy := range copies {
			j := copy.Job
			latest := j.Generation == recent[0]
			if v.requestGates[j.Target] == nil || running["external-audit/"+j.Operation] || v.paused(j.Domain, j.Operation) || status.Controls.paused(j.Domain, j.Operation) {
				continue
			}
			if store == nil {
				if err = w.check(v.ctx); err != nil {
					return
				}
				store, err = statefile.OpenAt(w.root, externalScheduleDirectory, 4096, true)
				if err != nil {
					return
				}
				store.Admit = w.admission(externalScheduleDirectory)
			}
			scope := w.externalAuditScope(j, interval)
			record, err := readScheduledExternalAudit(store, scope)
			initialize := errors.Is(err, os.ErrNotExist)
			if initialize {
				record = scope
			} else if err != nil {
				continue
			}
			if record.FinishedUnix > 0 && now.Unix()-record.FinishedUnix < interval {
				if latest && record.Repair != nil && record.FinishedUnix <= now.Unix() {
					w.admitExternalRepair(v, status, j, *record.Repair)
				}
				continue
			}
			if selected == nil || record.FinishedUnix < selected.record.FinishedUnix ||
				(record.FinishedUnix == selected.record.FinishedUnix && j.Operation < selected.job.Operation) {
				selected = &externalAuditCandidate{job: j, interval: interval, record: record, new: initialize, latest: latest}
			}
		}
	}
	if selected == nil {
		if store != nil {
			store.Close()
		}
		return
	}
	key := "external-audit/" + selected.job.Operation
	running[key] = true
	go func() {
		w.runScheduledExternalAudit(v, store, *selected)
		_ = store.Close()
		results <- result{externalAudit: key}
	}()
}

func (w *Worker) externalRepairJob(v *view, original control.Job, repair upload.MissingRepair) (control.Job, bool) {
	raw, grant, ok := v.cfg.UploadDelegation(original.Delegation)
	if !ok || original.Domain != grant.Trust.Domain || original.Target != grant.Profile.ID() ||
		original.Operation != upload.DelegatedOperation(raw, original.Generation) {
		return control.Job{}, false
	}
	job := control.UploadRepairJob(raw, grant, original.Generation, w.node, repair)
	return job, v.autonomy.Permits(job)
}

func (w *Worker) admitExternalRepair(v *view, status Status, original control.Job, repair upload.MissingRepair) {
	job, ok := w.externalRepairJob(v, original, repair)
	if !ok || v.paused(job.Domain, job.Operation) || status.Controls.paused(job.Domain, job.Operation) {
		return
	}
	for _, item := range status.Jobs {
		old := item.Job
		if old.Operation != job.Operation && old.MissingRepair != nil && old.MissingRepair.Part == repair.Part &&
			old.Generation == job.Generation && old.Delegation == job.Delegation && item.Phase != "COMPLETE" && item.Phase != "WITHDRAWN" {
			return // keep one unresolved operation per exact part and delegation
		}
	}
	if _, exists := status.Jobs[job.Operation]; !exists && w.point("external-repair-before-admission") != nil {
		return
	}
	_ = w.admitDerived(v.ctx, v, []control.Job{job})
}

func (w *Worker) runScheduledExternalAudit(v *view, store *statefile.Store, selected externalAuditCandidate) {
	record := selected.record
	window := scheduledExternalProfile(record.Operation, selected.interval)
	relative := externalAuditDirectory(record.Operation, record.Window)
	write := func(ctx context.Context) error {
		if err := w.check(ctx); err != nil {
			return err
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return store.WithLock(ctx, func() error { return store.Write(record.Window+".json", raw) })
	}
	if selected.new {
		if _, err := w.root.Stat(relative); !errors.Is(err, os.ErrNotExist) {
			return // an existing window without a schedule record is unresolved
		}
		if err := write(v.ctx); err != nil {
			return
		}
	}
	_, directoryError := w.root.Stat(relative)
	initialize := !record.Ready && errors.Is(directoryError, os.ErrNotExist)
	ctx, cancel := context.WithTimeout(v.ctx, time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond)
	defer cancel()
	proof, err := w.auditRetainedUpload(ctx, record.Operation, window, initialize, v.requestGates[record.Target], v.cfg.Revision)
	if _, e := w.root.Stat(relative + "/scope.json"); e == nil {
		record.Ready = true
	}
	record.Receipt = nil
	record.Repair = nil
	record.PolicyExpiresUnix = 0
	record.FinishedUnix = time.Now().Unix()
	switch {
	case err == nil:
		record.State = "VERIFIED_CIPHERTEXT"
		record.FinishedUnix = proof.FinishedUnix
		record.Receipt = &proof
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), errors.Is(err, control.ErrInactive):
		if selected.record.FinishedUnix > 0 {
			return // interrupted reread cannot replace the last recorded outcome
		}
		record.State = "PENDING"
		record.FinishedUnix = 0
	case storage.Missing(err):
		record.State = "MISSING"
		var absent *storage.MissingPart
		if selected.latest && record.Ready && errors.As(err, &absent) {
			repair := upload.MissingRepair{Part: absent.Part.ID, ObservedUnix: record.FinishedUnix}
			if _, allowed := w.externalRepairJob(v, selected.job, repair); allowed {
				record.Repair = &repair
			}
		}
	case errors.Is(err, storage.ErrIntegrity), errors.Is(err, storage.ErrConflict):
		record.State = "INVALID_CONTENT"
	default:
		record.State = "UNAVAILABLE"
	}
	if record.FinishedUnix > 0 && record.FinishedUnix < v.cfg.ExpiresUnix {
		record.PolicyExpiresUnix = v.cfg.ExpiresUnix
	}
	bounded, stop := context.WithTimeout(context.WithoutCancel(v.ctx), 5*time.Second)
	defer stop()
	// Fence the result write against policy replacement, including missing and
	// integrity results. No network request is made while holding this lock.
	_ = w.cache.WithCurrent(bounded, time.Now(), func(current control.Config, _ []byte) error {
		if current.Revision != v.cfg.Revision {
			return control.ErrInactive
		}
		status, err := w.Status(bounded)
		if err != nil {
			return err
		}
		if status.Controls.paused(selected.job.Domain, record.Operation) {
			return ErrDenied
		}
		return write(bounded)
	})
}
