package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func (a *Agent) observeReceiver(ctx context.Context, s state, item control.SettlementAdmission, purpose string, retire bool) (ingress.Reconciliation, error) {
	g, err := ingress.VerifySettlement(item.Grant, item.Authority, item.Intent, a.b.Local.Owner, time.Now())
	if err != nil || g.Purpose != purpose {
		return ingress.Reconciliation{}, ErrInvalid
	}
	_, authority, intent, endpoint, err := a.settlementReceiver(s, g.Ingress)
	if err != nil || !bytes.Equal(authority, item.Authority) || !bytes.Equal(intent, item.Intent) {
		return ingress.Reconciliation{}, ErrInvalid
	}
	limits := peer.Limits{Concurrency: 1, Timeout: 30 * time.Second, Attempts: 1}
	c, err := ingress.NewSettlementClient(endpoint, authority, intent, item.Grant, a.b.Local.Owner, a.cert, a.roots, limits)
	if err != nil {
		return ingress.Reconciliation{}, err
	}
	defer c.Close()
	var out ingress.Reconciliation
	if retire {
		out, err = c.RetireUnsealed(ctx)
	} else {
		out, err = c.Reconcile(ctx)
	}
	if err != nil {
		return ingress.Reconciliation{}, err
	}
	return out, a.guard(ctx)
}

// Reconcile records an authenticated observation without advancing the source
// head, releasing its view or changing the receiver admission fence.
func (a *Agent) Reconcile(ctx context.Context, item control.SettlementAdmission) (ingress.Reconciliation, error) {
	var out ingress.Reconciliation
	err := a.lease.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		s, err := a.load()
		if err != nil {
			return err
		}
		if s.Phase != "ACTIVE" {
			return ErrInvalid
		}
		out, err = a.observeReceiver(ctx, s, item, ingress.SettlementInspect, false)
		if err != nil {
			return err
		}
		record := struct {
			Binding     string
			Grant       string
			Observation ingress.Reconciliation
			Signature   []byte
		}{Binding: a.binding, Grant: storage.Hash(item.Grant), Observation: out}
		raw, _ := json.Marshal(record)
		record.Signature = ed25519.Sign(a.writer, append([]byte("outpost-reconciliation-1\x00"), raw...))
		raw, _ = json.Marshal(record)
		return a.store.Write("reconciled-"+out.Grant+".json", raw)
	})
	return out, err
}
