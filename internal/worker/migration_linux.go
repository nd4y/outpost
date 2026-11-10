package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
)

// MigrateDomain is an explicit local operator action, never a remotely supplied
// job. It excludes the running worker and uses the cached domain authority and
// existing disk budget even when network policy has expired.
func (w *Worker) MigrateDomain(ctx context.Context, domain string, rollback bool) error {
	return w.withStoppedReplica(ctx, domain, func(root *os.Root, path string, trust generation.Trust, admit statefile.Admission) error {
		if rollback {
			return generation.RollbackLocalAt(root, ctx, path, trust, admit)
		}
		return generation.MigrateLocalAt(root, ctx, path, trust, admit)
	})
}

func (w *Worker) withStoppedReplica(ctx context.Context, domain string, action func(*os.Root, string, generation.Trust, statefile.Admission) error) error {
	if e := w.check(ctx); e != nil {
		return e
	}
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
		_, e = w.budgetFor(ctx, c, false)
		if e != nil {
			return e
		}
		dir := filepath.Join(DomainDirectory(w.dir, d.Trust), "replica")
		prefix, e := filepath.Rel(w.dir, dir)
		if e != nil {
			return e
		}
		return action(w.root, prefix, d.Trust, w.admission(filepath.ToSlash(prefix)))
	})
	if errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil {
		return generation.ErrConflict
	}
	return e
}

func (w *Worker) RetentionCheckpoint(ctx context.Context, domain string) ([]byte, error) {
	var raw []byte
	e := w.withRetentionReplica(ctx, domain, func(replica *generation.Replica) error {
		var err error
		raw, err = replica.RetentionCheckpoint(ctx)
		return err
	})
	return raw, e
}

func (w *Worker) RestoreRetentionCheckpoint(ctx context.Context, domain string, raw []byte, expected string) error {
	return w.withRetentionReplica(ctx, domain, func(replica *generation.Replica) error {
		return replica.RestoreRetentionCheckpoint(ctx, raw, expected)
	})
}

func (w *Worker) withRetentionReplica(ctx context.Context, domain string, action func(*generation.Replica) error) error {
	return w.withStoppedReplica(ctx, domain, func(root *os.Root, path string, trust generation.Trust, admit statefile.Admission) error {
		replica, e := generation.OpenAt(root, path, trust, false)
		if e != nil {
			return e
		}
		defer replica.Close()
		replica.Admit = admit
		return action(replica)
	})
}
