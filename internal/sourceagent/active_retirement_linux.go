package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

type activeRetirement struct {
	Binding      string
	Operation    string
	Checkpoint   string
	RecordedUnix int64
	Admissions   []control.SettlementAdmission
	Observations []ingress.Reconciliation
	Signature    []byte
}

func (r activeRetirement) unsigned() []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("outpost-active-retirement-1\x00"), raw...)
}

func retirementID(items []control.SettlementAdmission) string {
	raw, _ := json.Marshal(items)
	return storage.Hash(raw)
}

func (a *Agent) activeReceivers(s state, i ingress.Intent) []string {
	if a.routed() {
		return s.Route
	}
	if a.b.Companion != nil && !a.b.Standby {
		return []string{i.Ingress, a.companion.Ingress}
	}
	return []string{i.Ingress}
}

func (a *Agent) verifyActiveRetirement(s state, i ingress.Intent, record activeRetirement, now int64) error {
	targets := a.activeReceivers(s, i)
	if record.Binding != a.binding || record.Operation != i.Operation || record.Checkpoint != storage.Hash(s.Checkpoint) ||
		record.RecordedUnix < i.ExpiresUnix || record.RecordedUnix > now ||
		len(record.Admissions) != len(targets) || len(record.Observations) != len(targets) {
		return ErrInvalid
	}
	for k, target := range targets {
		item, proof := record.Admissions[k], record.Observations[k]
		_, authority, intent, _, err := a.settlementReceiver(s, target)
		if err != nil || !bytes.Equal(authority, item.Authority) || !bytes.Equal(intent, item.Intent) {
			return ErrInvalid
		}
		grant, err := ingress.VerifySettlement(item.Grant, authority, intent, a.b.Local.Owner, time.Unix(record.RecordedUnix, 0))
		if err != nil || grant.Purpose != ingress.SettlementRetire || proof.Receiver != target || proof.Intent != grant.Intent ||
			proof.Grant != grant.ID || proof.Phase != "NOT_ADMITTED" || proof.ObservedUnix < grant.NotBefore ||
			proof.ObservedUnix > record.RecordedUnix || proof.Generation != "" || proof.Receipt != nil || proof.Publication != nil {
			return ErrInvalid
		}
	}
	return nil
}

func (a *Agent) readActiveRetirement(s state, i ingress.Intent, id string) (activeRetirement, error) {
	var record activeRetirement
	if !storage.ID(id) {
		return record, ErrInvalid
	}
	raw, err := a.store.Read("active-retirement-" + id + ".json")
	if err != nil {
		return record, err
	}
	if storage.Decode(raw, &record, maxState) != nil || retirementID(record.Admissions) != id ||
		!ed25519.Verify(a.anchor.Trust.Writer, record.unsigned(), record.Signature) {
		return record, ErrInvalid
	}
	return record, a.verifyActiveRetirement(s, i, record, time.Now().Unix())
}

// RetireActive can advance only a local PLANNED job with current explicit
// owner grants and a negative admission proof from every possible receiver.
func (a *Agent) RetireActive(ctx context.Context, primary control.SettlementAdmission, companion *control.SettlementAdmission) error {
	return a.lease.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		s, err := a.load()
		if err != nil {
			return err
		}
		if len(s.Superseded) != 0 {
			// A superseded receiver may have accepted data. An absence proof
			// from the replacement pair cannot retire that admission.
			return ingress.ErrConflict
		}
		i, err := a.stateIntent(s)
		if err != nil {
			return err
		}
		items := []control.SettlementAdmission{primary}
		if companion != nil {
			items = append(items, *companion)
		}
		id := retirementID(items)
		if s.Phase == "ABANDONED" && s.RetirementKind == ingress.SettlementRetire && s.Retirement == id {
			return nil
		}
		targets := a.activeReceivers(s, i)
		if s.Phase != "ACTIVE" || len(items) != len(targets) || time.Now().Unix() < i.ExpiresUnix {
			return ErrInvalid
		}
		job, closeJob, err := a.openJobMode(ctx, s, true, nil)
		if err != nil {
			return err
		}
		status, err := job.Status(ctx)
		closeJob()
		if err != nil {
			return err
		}
		if status.Phase != "PLANNED" || status.CompletedFiles != 0 || status.Generation != "" {
			return ingress.ErrConflict
		}
		record := activeRetirement{Binding: a.binding, Operation: i.Operation, Checkpoint: storage.Hash(s.Checkpoint), Admissions: items}
		for k, item := range items {
			proof, err := a.observeReceiver(ctx, s, item, ingress.SettlementRetire)
			if err != nil {
				return err
			}
			if proof.Receiver != targets[k] || proof.Phase != "NOT_ADMITTED" {
				return ingress.ErrConflict
			}
			record.Observations = append(record.Observations, proof)
		}
		record.RecordedUnix = time.Now().Unix()
		if err = a.verifyActiveRetirement(s, i, record, record.RecordedUnix); err != nil {
			return err
		}
		record.Signature = ed25519.Sign(a.writer, record.unsigned())
		raw, _ := json.Marshal(record)
		if err = a.store.Write("active-retirement-"+id+".json", raw); err != nil {
			return err
		}
		if err = a.point("source-active-retirement-durable"); err != nil {
			return err
		}
		if err = a.guard(ctx); err != nil {
			return err
		}
		for _, item := range items {
			if _, err = ingress.VerifySettlement(item.Grant, item.Authority, item.Intent, a.b.Local.Owner, time.Now()); err != nil {
				return err
			}
		}
		s.Phase, s.Retirement, s.RetirementKind = "ABANDONED", id, ingress.SettlementRetire
		return a.save(s)
	})
}
