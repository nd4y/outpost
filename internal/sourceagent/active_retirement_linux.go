package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path"
	"slices"
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

func (a *Agent) retirementReceivers(s state, i ingress.Intent, purpose string) []string {
	targets := a.activeReceivers(s, i)
	if purpose == ingress.SettlementRetireUnsealed {
		targets = slices.Clone(targets)
		for _, receiver := range s.Superseded {
			if !slices.Contains(targets, receiver) {
				targets = append(targets, receiver)
			}
		}
	}
	return targets
}

func retiredPhase(phase, purpose string) bool {
	return phase == "NOT_ADMITTED" || purpose == ingress.SettlementRetireUnsealed && phase == ingress.UnsealedRetired
}

func (a *Agent) verifyActiveRetirement(s state, i ingress.Intent, record activeRetirement, purpose string, now int64) error {
	targets := a.retirementReceivers(s, i, purpose)
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
		if err != nil || grant.Purpose != purpose || proof.Receiver != target || proof.Intent != grant.Intent ||
			proof.Grant != grant.ID || !retiredPhase(proof.Phase, purpose) || proof.ObservedUnix < grant.NotBefore ||
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
	return record, a.verifyActiveRetirement(s, i, record, s.RetirementKind, time.Now().Unix())
}

func (a *Agent) RetireActive(ctx context.Context, primary control.SettlementAdmission, companion *control.SettlementAdmission) error {
	items := []control.SettlementAdmission{primary}
	if companion != nil {
		items = append(items, *companion)
	}
	return a.RetireActiveWithAdmissions(ctx, items)
}

// RetireActiveWithAdmissions leaves the prior generation intact. Every holder
// must either prove non-admission or durably fence an unsealed session.
func (a *Agent) RetireActiveWithAdmissions(ctx context.Context, items []control.SettlementAdmission) error {
	var first ingress.Settlement
	if len(items) == 0 || len(items) > 3 || storage.Decode(items[0].Grant, &first, ingress.MaxSettlementDocument) != nil ||
		first.Purpose != ingress.SettlementRetire && first.Purpose != ingress.SettlementRetireUnsealed {
		return ErrInvalid
	}
	purpose := first.Purpose
	unsealed := purpose == ingress.SettlementRetireUnsealed
	return a.lease.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		s, err := a.load()
		if err != nil {
			return err
		}
		if !unsealed && len(s.Superseded) != 0 {
			// A superseded receiver may have accepted data. An absence proof
			// from the replacement pair cannot retire that admission.
			return ingress.ErrConflict
		}
		i, err := a.stateIntent(s)
		if err != nil {
			return err
		}
		id := retirementID(items)
		if s.Phase == "ABANDONED" && s.RetirementKind == purpose && s.Retirement == id {
			return nil
		}
		targets := a.retirementReceivers(s, i, purpose)
		if s.Phase != "ACTIVE" || len(items) != len(targets) || time.Now().Unix() < i.ExpiresUnix {
			return ErrInvalid
		}
		if s.RouteCatalog != "" {
			return ingress.ErrConflict
		}
		local := s
		if local.RoutePreparing {
			local.Route, local.Superseded, local.RoutePreparing = local.Superseded, nil, false
		}
		job, closeJob, err := a.openJobMode(ctx, local, true, nil)
		if err != nil {
			return err
		}
		status, err := job.Status(ctx)
		closeJob()
		if err != nil {
			return err
		}
		if status.Generation != "" || (status.Phase != "PLANNED" && (!unsealed || status.Phase != "CAPTURING")) ||
			!unsealed && status.CompletedFiles != 0 {
			return ingress.ErrConflict
		}
		auditErr := os.ErrNotExist
		if unsealed {
			pending := s
			pending.RetirementKind = purpose
			_, auditErr = a.readActiveRetirement(pending, i, id)
		}
		if errors.Is(auditErr, os.ErrNotExist) {
			auditErr = a.recordActiveRetirement(ctx, s, i, items, targets, id, purpose)
		}
		if auditErr != nil {
			return auditErr
		}
		check := func() error {
			if err := a.guard(ctx); err != nil {
				return err
			}
			now := time.Now()
			for _, item := range items {
				if _, err := ingress.VerifySettlement(item.Grant, item.Authority, item.Intent, a.b.Local.Owner, now); err != nil {
					return err
				}
			}
			return nil
		}
		if err = check(); err != nil {
			return err
		}
		if unsealed {
			provider, err := a.openProvider(ctx, path.Join("operations", i.Operation), i, false)
			if err != nil {
				return err
			}
			defer provider.Close()
			if err = provider.Release(ctx, i.Operation, i.Operation); err != nil {
				return err
			}
			if err = check(); err != nil {
				return err
			}
		}
		s.Phase, s.Retirement, s.RetirementKind, s.RoutePreparing = "ABANDONED", id, purpose, false
		return a.save(s)
	})
}

func (a *Agent) recordActiveRetirement(ctx context.Context, s state, i ingress.Intent, items []control.SettlementAdmission, targets []string, id, purpose string) error {
	unsealed := purpose == ingress.SettlementRetireUnsealed
	record := activeRetirement{Binding: a.binding, Operation: i.Operation, Checkpoint: storage.Hash(s.Checkpoint), Admissions: items}
	for k, item := range items {
		proof, err := a.observeReceiver(ctx, s, item, purpose, false)
		if err != nil {
			return err
		}
		if proof.Receiver != targets[k] || !retiredPhase(proof.Phase, purpose) && (!unsealed || proof.Phase != "ADMITTED") {
			return ingress.ErrConflict
		}
		record.Observations = append(record.Observations, proof)
	}
	if unsealed {
		// Inspect all possible holders before fencing any.
		for k, item := range items {
			proof, err := a.observeReceiver(ctx, s, item, purpose, true)
			if err != nil {
				return err
			}
			record.Observations[k] = proof
		}
	}
	record.RecordedUnix = time.Now().Unix()
	if err := a.verifyActiveRetirement(s, i, record, purpose, record.RecordedUnix); err != nil {
		return err
	}
	record.Signature = ed25519.Sign(a.writer, record.unsigned())
	raw, _ := json.Marshal(record)
	if err := a.store.Write("active-retirement-"+id+".json", raw); err != nil {
		return err
	}
	return a.point("source-active-retirement-durable")
}
