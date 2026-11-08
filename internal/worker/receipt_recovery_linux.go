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
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
)

// RecoverIngressReceipt is explicit local maintenance. A fresh owner-signed
// capability and current placement are required even though the underlying
// completed publication and its write intent are historical.
func (w *Worker) RecoverIngressReceipt(ctx context.Context, domain string, item ingress.ReceiptRecoveryAdmission) (ingress.Receipt, error) {
	var result ingress.Receipt
	if e := w.check(ctx); e != nil {
		return result, e
	}
	if len(item.Authority) > ingress.MaxDocument || len(item.Intent) > ingress.MaxDocument || len(item.Grant) > ingress.MaxSettlementDocument {
		return result, ErrDenied
	}
	item = ingress.ReceiptRecoveryAdmission{Authority: bytes.Clone(item.Authority), Intent: bytes.Clone(item.Intent), Grant: bytes.Clone(item.Grant)}
	claim, e := ingress.VerifyReceiptRecovery(item.Grant, item.Authority, item.Intent, w.owner, time.Now())
	if e != nil || claim.Domain != domain || claim.Ingress != w.node {
		return result, ErrDenied
	}
	a, e := ingress.VerifyAuthorityDocument(item.Authority, w.owner)
	if e != nil {
		return result, e
	}
	acquire, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	e = w.lease.WithLock(acquire, func() error {
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
		return w.cache.WithCurrent(bounded, time.Now(), func(c control.Config, _ []byte) error {
			d, ok := c.DomainByID(domain)
			if !ok || a.Revision > c.Revision || !d.Placement.PermitsNode(w.node) || !d.Placement.HasEdge(claim.Source, w.node, "push") {
				return ErrDenied
			}
			source, ok := c.NodeByID(claim.Source)
			if !ok || source.Class != "trusted" {
				return ErrDenied
			}
			holder := false
			for _, id := range d.Placement.Holders {
				holder = holder || id == w.node
			}
			x, _ := json.Marshal(d.Trust)
			y, _ := json.Marshal(a.Trust)
			if !holder || !bytes.Equal(x, y) {
				return ErrDenied
			}
			guard := func(check context.Context) error {
				if e := bounded.Err(); e != nil {
					return e
				}
				if e := c.Active(time.Now()); e != nil {
					return e
				}
				if _, e := ingress.VerifyReceiptRecovery(item.Grant, item.Authority, item.Intent, w.owner, time.Now()); e != nil {
					return e
				}
				return w.check(check)
			}
			if e := guard(bounded); e != nil {
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
			admission := func(prefix string) statefile.Admission {
				admit := w.admission(filepath.ToSlash(prefix))
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
			dir := DomainDirectory(w.dir, d.Trust)
			replicaPrefix := w.relative(filepath.Join(dir, "replica"))
			prefix := w.relative(filepath.Join(dir, "ingress"))
			r, e := generation.OpenAt(w.root, replicaPrefix, d.Trust, false)
			if e != nil {
				return e
			}
			defer r.Close()
			r.Admit = admission(replicaPrefix)
			result, e = ingress.RecoverReceipt(bounded, ingress.RegistryOptions{
				Parent: w.root, Directory: prefix, Authority: item.Authority, Owner: w.owner, Replica: r, Certificate: w.cert, Roots: w.roots, Initialize: false,
				Limits:    peer.Limits{Concurrency: c.Limits.Parallel, Timeout: time.Duration(c.Limits.AttemptMillis) * time.Millisecond, Attempts: 2},
				Admission: func(part string) statefile.Admission { return admission(filepath.Join(prefix, part)) },
			}, item, guard, w.Fault)
			return e
		})
	})
	if errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil {
		e = ingress.ErrConflict
	}
	return result, e
}
