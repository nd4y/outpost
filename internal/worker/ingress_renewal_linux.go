package worker

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
)

// RenewIngress is a local, quiescent metadata migration. It never starts a
// listener, creates a missing replica/registry, or changes the source scope.
func (w *Worker) RenewIngress(ctx context.Context, domain string, previous, fresh []byte) (ingress.RegistryRenewal, error) {
	var result ingress.RegistryRenewal
	if e := w.check(ctx); e != nil {
		return result, e
	}
	if len(previous) > ingress.MaxDocument || len(fresh) > ingress.MaxDocument {
		return result, ErrDenied
	}
	previous, fresh = bytes.Clone(previous), bytes.Clone(fresh)
	acquire, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	e := w.lease.WithLock(acquire, func() error {
		cancel()
		bounded, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		raw, e := w.cache.Raw(bounded)
		if e != nil {
			return e
		}
		known, e := w.cache.Verify(raw)
		if e != nil {
			return e
		}
		if _, e = w.budgetFor(bounded, known, false); e != nil {
			return e
		}
		// Admission initialization must precede the cache lock. This bounded
		// local callback serializes the commit with config replacement.
		return w.cache.WithCurrent(bounded, time.Now(), func(c control.Config, _ []byte) error {
			d, ok := c.DomainByID(domain)
			if !ok || !d.Placement.PermitsNode(w.node) {
				return ErrDenied
			}
			found := false
			for _, raw := range c.Ingress {
				if bytes.Equal(raw, fresh) {
					found = true
				}
			}
			a, e := ingress.VerifyAuthority(fresh, w.owner, time.Now())
			if !found || e != nil || a.Ingress != w.node || a.Trust.Domain != domain {
				return ErrDenied
			}
			guard := func(check context.Context) error {
				if e := bounded.Err(); e != nil {
					return e
				}
				if e := c.Active(time.Now()); e != nil {
					return e
				}
				return w.check(check)
			}
			if e = guard(bounded); e != nil {
				return e
			}
			budget, e := w.budget.Status(bounded)
			if e != nil {
				return e
			}
			limits := diskbudget.Limits{Capacity: c.Limits.CapacityBytes, Reserve: c.Limits.ReserveBytes, Spool: c.Limits.SpoolBytes, Telemetry: c.Limits.TelemetryBytes}
			if budget.Limits != limits || len(budget.Pending) != 0 {
				return ErrDenied
			}
			dir := DomainDirectory(w.dir, d.Trust)
			r, e := w.openReplicaAt(w.relative(filepath.Join(dir, "replica")), d.Trust, false)
			if e != nil {
				return e
			}
			defer r.Close()
			prefix := w.relative(filepath.Join(dir, "ingress"))
			admission := func(part string) statefile.Admission {
				admit := w.admission(filepath.ToSlash(filepath.Join(prefix, part)))
				return func(name string, size int) (func(bool) error, error) {
					if e := guard(bounded); e != nil {
						return nil, e
					}
					finish, e := admit(name, size)
					if e != nil {
						return nil, e
					}
					return func(written bool) error { return errors.Join(finish(written), guard(bounded)) }, nil
				}
			}
			result, e = ingress.RenewRegistry(bounded, ingress.RegistryOptions{
				Parent: w.root, Directory: prefix, Authority: previous, Owner: w.owner,
				Replica: r, Certificate: w.cert, Roots: w.roots, Initialize: false,
				Limits: peer.Limits{Concurrency: c.Limits.Parallel, Timeout: time.Duration(c.Limits.AttemptMillis) * time.Millisecond, Attempts: 2}, Admission: admission,
			}, fresh, guard, w.Fault)
			return e
		})
	})
	if errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil {
		e = ingress.ErrConflict
	}
	return result, e
}
