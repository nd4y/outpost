package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

const ExternalAuditProfileFormat = "outpost-worker-external-audit-1"

type ExternalAuditProfile struct {
	Format        string `json:"format"`
	Window        string `json:"window"`
	MaxAgeSeconds int64  `json:"maxAgeSeconds"`
}

// AuditExternal reopens the retained complete upload under the stopped
// worker's execution lease. It never renews that upload or changes its receipt.
func (w *Worker) AuditExternal(ctx context.Context, operation string, p ExternalAuditProfile, initialize bool) (upload.TargetAuditReceipt, error) {
	var result upload.TargetAuditReceipt
	if !storage.ID(operation) || !storage.ID(p.Window) || p.Format != ExternalAuditProfileFormat ||
		p.MaxAgeSeconds < 1 || p.MaxAgeSeconds > readback.MaxAgeSeconds || w.resolve == nil {
		return result, ErrDenied
	}
	acquire, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := w.lease.WithLock(acquire, func() error {
		cancel()
		var err error
		result, err = w.auditRetainedUpload(ctx, operation, p, initialize, nil)
		return err
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil && result.Format == "" && acquire.Err() == context.DeadlineExceeded {
		return upload.TargetAuditReceipt{}, storage.ErrConflict
	}
	return result, err
}

func (w *Worker) auditRetainedUpload(ctx context.Context, operation string, p ExternalAuditProfile, initialize bool, gate *storage.RequestGate) (upload.TargetAuditReceipt, error) {
	var result upload.TargetAuditReceipt
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
	active, expire := context.WithDeadline(ctx, time.Unix(c.ExpiresUnix, 0))
	defer expire()
	status, err := w.Status(active)
	if err != nil {
		return result, err
	}
	original, ok := status.Jobs[operation]
	job := original.Job
	d, admitted := c.DomainByID(job.Domain)
	target, allowed := c.TargetByID(job.Target)
	if !ok || !admitted || !allowed || original.Phase != "COMPLETE" || job.Kind != "upload" || job.Executor != w.node ||
		!d.Placement.PermitsCloud(w.node, job.Target) || status.Controls.paused(job.Domain, operation) {
		return result, ErrDenied
	}
	if gate != nil && (d.ExternalAuditIntervalSeconds == 0 || p != scheduledExternalProfile(operation, d.ExternalAuditIntervalSeconds)) {
		return result, ErrDenied
	}
	budget, err := w.budgetFor(active, c, false)
	if err != nil {
		return result, err
	}
	ledger, err := budget.Status(active)
	if err != nil {
		return result, err
	}
	limits := diskbudget.Limits{Capacity: c.Limits.CapacityBytes, Reserve: c.Limits.ReserveBytes, Spool: c.Limits.SpoolBytes, Telemetry: c.Limits.TelemetryBytes}
	if ledger.Limits != limits {
		return result, ErrDenied
	}
	authority := upload.Authority{Generation: d.Trust, Planner: d.Planner}
	queuePath := w.relative(filepath.Join(DomainDirectory(w.dir, d.Trust), "uploads", operation))
	queue, err := upload.OpenQueueAt(w.root, queuePath, w.node, authority, externalQueueLimits, false, nil)
	if err != nil {
		return result, err
	}
	defer queue.Close()
	queueState, err := queue.Status(active)
	if err != nil {
		return result, err
	}
	retained, ok := queueState.Jobs[operation]
	if !ok || retained.Phase != "COMPLETE" || retained.Receipt == nil {
		return result, ErrDenied
	}
	receipt, err := json.Marshal(retained.Receipt)
	if err != nil || !bytes.Equal(receipt, original.Receipt) {
		return result, storage.ErrConflict
	}
	plan, err := upload.Verify(retained.Plan, authority)
	if err != nil || plan.Operation != operation || plan.Generation != job.Generation || plan.Profile != target.Profile {
		return result, ErrDenied
	}
	current := func(ctx context.Context) error {
		if err := w.check(ctx); err != nil {
			return err
		}
		now, err := w.cache.Raw(ctx)
		if err != nil {
			return err
		}
		if !bytes.Equal(cached, now) {
			return control.ErrInactive
		}
		status, err := w.Status(ctx)
		if err != nil {
			return err
		}
		if status.Controls.paused(job.Domain, operation) {
			return ErrDenied
		}
		return nil
	}
	if err = current(active); err != nil {
		return result, err
	}
	binding, err := json.Marshal(struct {
		Profile   ExternalAuditProfile
		Node      string
		Operation string
		Plan      string
	}{p, w.node, operation, storage.Hash(retained.Plan)})
	if err != nil {
		return result, err
	}
	relative := externalAuditDirectory(operation, p.Window)
	store, err := w.openExternalAuditWindow(active, relative, binding, initialize)
	if err != nil {
		return result, err
	}
	defer store.Close()
	work, stop := context.WithCancelCause(active)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-tick.C:
				if err := current(work); err != nil {
					stop(err)
					return
				}
			}
		}
	}()
	defer func() { stop(context.Canceled); <-done }()
	backend, err := w.resolve(work, plan.Profile)
	if err != nil {
		return result, err
	}
	if backend == nil {
		return result, ErrDenied
	}
	defer backend.Close()
	if gate != nil {
		backend, err = backend.WithRequestGate(gate)
		if err != nil {
			return result, err
		}
	}
	result, err = upload.AuditTargetPlan(work, retained.Plan, authority, w.node, backend, upload.TargetAuditWindow{ID: p.Window, MaxAgeSeconds: p.MaxAgeSeconds, Store: store})
	if cause := context.Cause(work); cause != nil {
		return upload.TargetAuditReceipt{}, cause
	}
	if err != nil {
		return upload.TargetAuditReceipt{}, err
	}
	if err = current(work); err != nil {
		return upload.TargetAuditReceipt{}, err
	}
	return result, nil
}

func externalAuditDirectory(operation, window string) string {
	return filepath.ToSlash(filepath.Join("telemetry", "external-audit", operation, window))
}

func (w *Worker) openExternalAuditWindow(ctx context.Context, relative string, binding []byte, initialize bool) (*statefile.Store, error) {
	if initialize {
		parent, err := localfs.OpenAt(w.root, filepath.Dir(relative), true)
		if err != nil {
			return nil, err
		}
		defer parent.Close()
		if err = parent.Mkdir(filepath.Base(relative), 0700); err != nil {
			return nil, err
		}
		dir, err := parent.Open(".")
		if err != nil {
			return nil, err
		}
		if err = errors.Join(dir.Sync(), dir.Close()); err != nil {
			return nil, err
		}
	}
	store, err := statefile.OpenAt(w.root, relative, readback.MaxPage, false)
	if err != nil {
		return nil, err
	}
	store.Admit = w.admission(relative)
	err = store.WithLock(ctx, func() error {
		if initialize {
			return store.Write("scope.json", binding)
		}
		held, err := store.Read("scope.json")
		if err != nil {
			return err
		}
		if !bytes.Equal(held, binding) {
			return storage.ErrConflict
		}
		return nil
	})
	if err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}
