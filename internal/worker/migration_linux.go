package worker

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

// MigrateDomain is an explicit local operator action, never a remotely supplied
// job. It excludes the running worker and uses the cached domain authority and
// existing disk budget even when network policy has expired.
func (w *Worker) MigrateDomain(ctx context.Context, domain string, rollback bool) error {
	acquire, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	e := w.lease.WithLock(acquire, func() error {
		cancel()
		raw, e := w.cache.Raw(ctx)
		if e != nil {
			return e
		}
		c, e := w.cache.Verify(raw)
		if e != nil {
			return e
		}
		d, ok := c.DomainByID(domain)
		if !ok {
			return ErrDenied
		}
		budget, e := w.budgetFor(ctx, c, false)
		if e != nil {
			return e
		}
		dir := filepath.Join(DomainDirectory(w.dir, d.Trust), "replica")
		prefix, e := filepath.Rel(w.dir, dir)
		if e != nil {
			return e
		}
		if rollback {
			return generation.RollbackLocal(ctx, dir, d.Trust, budget.Admission(filepath.ToSlash(prefix)))
		}
		return generation.MigrateLocal(ctx, dir, d.Trust, budget.Admission(filepath.ToSlash(prefix)))
	})
	if errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil {
		return generation.ErrConflict
	}
	return e
}
