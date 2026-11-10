package worker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
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
	e := w.withExistingReplica(ctx, domain, func(replica *generation.Replica) error {
		var err error
		raw, err = replica.RetentionCheckpoint(ctx)
		return err
	})
	return raw, e
}

func (w *Worker) RestoreRetentionCheckpoint(ctx context.Context, domain string, raw []byte, expected string) error {
	return w.withExistingReplica(ctx, domain, func(replica *generation.Replica) error {
		return replica.RestoreRetentionCheckpoint(ctx, raw, expected)
	})
}

func (w *Worker) withExistingReplica(ctx context.Context, domain string, action func(*generation.Replica) error) error {
	return w.withStoppedReplica(ctx, domain, func(_ *os.Root, path string, trust generation.Trust, admit statefile.Admission) error {
		replica, e := w.openReplicaAt(path, trust, false)
		if e != nil {
			return e
		}
		defer replica.Close()
		replica.Admit = admit
		return action(replica)
	})
}

func (w *Worker) EnableReplicaIndexCopy(ctx context.Context, domain string) error {
	return w.withExistingReplica(ctx, domain, func(replica *generation.Replica) error {
		return replica.EnableIndexCopy(ctx)
	})
}

func (w *Worker) RecoverReplicaIndexCopy(ctx context.Context, domain string) (bool, error) {
	var changed bool
	e := w.withStoppedReplica(ctx, domain, func(root *os.Root, path string, trust generation.Trust, admit statefile.Admission) error {
		var err error
		changed, err = generation.RecoverIndexCopyAt(root, ctx, path, trust, w.cert.PrivateKey.(ed25519.PrivateKey), admit)
		return err
	})
	return changed, e
}

func (w *Worker) PreviewRetention(ctx context.Context, domain string, selection generation.RetentionSelection) (*generation.Permit, error) {
	var permit *generation.Permit
	e := w.withExistingReplica(ctx, domain, func(replica *generation.Replica) error {
		var err error
		permit, err = replica.PreviewRetention(ctx, w.node, selection)
		return err
	})
	return permit, e
}

func (w *Worker) IngressJournalCopy(ctx context.Context, domain string, authority []byte, recover bool) (bool, error) {
	grant, e := ingress.VerifyAuthorityDocument(authority, w.owner)
	if e != nil || grant.Ingress != w.node || grant.Trust.Domain != domain {
		return false, ErrDenied
	}
	var reconstructed bool
	e = w.withStoppedReplica(ctx, domain, func(root *os.Root, path string, trust generation.Trust, admit statefile.Admission) error {
		r, e := w.openReplicaAt(path, trust, false)
		if e != nil {
			return e
		}
		defer r.Close()
		r.Admit = admit
		prefix := filepath.Join(filepath.Dir(path), "ingress")
		options := ingress.RegistryOptions{Parent: root, Directory: prefix, Authority: authority, Owner: w.owner, Replica: r,
			Certificate: w.cert, Roots: w.roots, Limits: peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1},
			Admission: func(part string) statefile.Admission {
				return w.admission(filepath.ToSlash(filepath.Join(prefix, part)))
			}}
		if !recover {
			return ingress.EnableRegistryJournalCopy(ctx, options)
		}
		reconstructed, e = ingress.RecoverRegistryJournalCopy(ctx, options)
		return e
	})
	return reconstructed, e
}
