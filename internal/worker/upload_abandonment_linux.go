package worker

import (
	"context"
	"path/filepath"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

func (w *Worker) withUploadAbandonmentQueue(ctx context.Context, domain, operation string, write bool, action func(*upload.Queue) error) error {
	if !storage.ID(domain) || !storage.ID(operation) {
		return ErrDenied
	}
	if e := w.check(ctx); e != nil {
		return e
	}
	return w.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, _ []byte) error {
		d, ok := cfg.DomainByID(domain)
		if !ok || !slices.Contains(d.Placement.Holders, w.node) {
			return ErrDenied
		}
		path := w.relative(filepath.Join(DomainDirectory(w.dir, d.Trust), "uploads", operation))
		var admit statefile.Admission
		if write {
			admit = w.admission(filepath.ToSlash(path))
		}
		q, e := upload.OpenQueueAt(w.root, path, w.node, upload.Authority{Generation: d.Trust, Planner: d.Planner}, externalQueueLimits, false, admit)
		if e != nil {
			return e
		}
		defer q.Close()
		q.Guard = func(ctx context.Context) error {
			if e := cfg.Active(time.Now()); e != nil {
				return e
			}
			return w.check(ctx)
		}
		return action(q)
	})
}

func (w *Worker) PreviewUploadAbandonment(ctx context.Context, domain, operation string) (upload.AbandonmentGrant, error) {
	var out upload.AbandonmentGrant
	e := w.withUploadAbandonmentQueue(ctx, domain, operation, false, func(q *upload.Queue) error {
		var e error
		out, e = q.PreviewAbandonment(ctx, operation)
		return e
	})
	return out, e
}

func (w *Worker) AbandonUpload(ctx context.Context, domain, operation string, raw []byte) (upload.AbandonmentReceipt, error) {
	var out upload.AbandonmentReceipt
	if !storage.ID(domain) || !storage.ID(operation) {
		return out, ErrDenied
	}
	e := w.withExistingReplica(ctx, domain, func(replica *generation.Replica) error {
		return w.withUploadAbandonmentQueue(ctx, domain, operation, true, func(q *upload.Queue) error {
			var e error
			out, e = q.Abandon(ctx, replica, operation, raw)
			return e
		})
	})
	return out, e
}
