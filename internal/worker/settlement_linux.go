package worker

import (
	"context"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
)

// Settlement inherits the current signed view, disk guard and request lifetime.
// It can reopen only the exact existing slot; it never initializes history.
func (w *Worker) openSettlements(v *view) error {
	for _, item := range v.cfg.Settlements {
		g, e := ingress.VerifySettlement(item.Grant, item.Authority, item.Intent, w.owner, time.Now())
		if e != nil || g.Ingress != w.node {
			return ErrDenied
		}
		a, e := ingress.VerifyAuthorityDocument(item.Authority, w.owner)
		if e != nil {
			return e
		}
		local := v.domains[g.Domain]
		if local == nil || local.ingress != nil {
			return ErrDenied
		}
		dir := filepath.Join(DomainDirectory(w.dir, a.Trust), "ingress")
		relative, e := filepath.Rel(w.dir, dir)
		if e != nil {
			return e
		}
		local.ingress, e = ingress.OpenRegistry(v.ctx, ingress.RegistryOptions{
			Parent: w.root, Directory: w.relative(dir), Authority: item.Authority,
			Settlement: item.Grant, SettlementIntent: item.Intent, Owner: w.owner,
			Staging: captureStagingRoutes(v.cfg, g.Domain),
			Replica: local.replica, Certificate: w.cert, Roots: w.roots, Initialize: false,
			Limits: peer.Limits{Concurrency: v.cfg.Limits.Parallel, Timeout: time.Duration(v.cfg.Limits.AttemptMillis) * time.Millisecond, Attempts: 2},
			Admission: func(prefix string) statefile.Admission {
				return w.admission(filepath.ToSlash(filepath.Join(relative, prefix)))
			},
			RemoveObject: func(ctx context.Context, name string, size int64) error {
				if e := w.check(ctx); e != nil {
					return e
				}
				return w.budget.Remove(ctx, filepath.ToSlash(filepath.Join(relative, "current/objects", name)), size)
			},
		})
		if e != nil {
			return e
		}
	}
	return nil
}
