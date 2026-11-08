package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const receiptRecoveryRecordFormat = "outpost-ingress-receipt-recovery-1"

// One bounded record per immutable intent survives slot reuse. Original and
// last execution permission are retained; retries never overwrite the intent,
// original evidence, receipt or initial authorization.
type receiptRecoveryRecord struct {
	Format         string                         `json:"format"`
	Authority      string                         `json:"authority"`
	Intent         string                         `json:"intent"`
	Before         string                         `json:"before"`
	Evidence       generation.PublicationEvidence `json:"evidence"`
	Receipt        Receipt                        `json:"receipt"`
	OriginalGrant  json.RawMessage                `json:"originalGrant"`
	ExecutionGrant json.RawMessage                `json:"executionGrant"`
	CreatedUnix    int64                          `json:"createdUnix"`
	AuthorizedUnix int64                          `json:"authorizedUnix"`
	Signature      []byte                         `json:"signature,omitempty"`
}

func (g *Registry) readReceiptRecovery(name string, item ReceiptRecoveryAdmission, selected ReceiptRecovery) (receiptRecoveryRecord, bool, error) {
	var record receiptRecoveryRecord
	raw, e := g.store.Read(name)
	if errors.Is(e, os.ErrNotExist) {
		return record, false, nil
	}
	if e != nil {
		return record, false, e
	}
	if storage.Decode(raw, &record, maxRegistryState) != nil {
		return record, false, ErrConflict
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(raw, canonical) || record.Format != receiptRecoveryRecordFormat || record.Authority != selected.Authority || record.Intent != selected.Intent || !storage.ID(record.Before) || record.Evidence.Generation != selected.Generation || !storage.ID(record.Evidence.Verification) || record.Evidence.Objects < 0 || record.Evidence.Bytes < 0 || record.Receipt.Generation != selected.Generation || record.Receipt.VerifiedAt != record.Evidence.VerifiedAt || record.CreatedUnix < 1 || record.AuthorizedUnix < record.CreatedUnix || record.AuthorizedUnix > time.Now().Unix() {
		return record, false, ErrConflict
	}
	key, ok := g.leaf.PublicKey.(ed25519.PublicKey)
	unsigned := record
	unsigned.Signature = nil
	if !ok || !verify(receiptRecoveryRecordFormat, unsigned, record.Signature, key) {
		return record, false, ErrConflict
	}
	var intent Intent
	if canonicalIntent(item.Intent, item.Authority, g.options.Owner, &intent) != nil || !record.Receipt.matches(intent) {
		return record, false, ErrConflict
	}
	for _, grant := range []struct {
		raw []byte
		at  int64
	}{{record.OriginalGrant, record.CreatedUnix}, {record.ExecutionGrant, record.AuthorizedUnix}} {
		claim, e := VerifyReceiptRecovery(grant.raw, item.Authority, item.Intent, g.options.Owner, time.Unix(grant.at, 0))
		if e != nil || claim.Generation != selected.Generation {
			return record, false, ErrConflict
		}
	}
	return record, true, nil
}

func (g *Registry) writeReceiptRecovery(name string, record *receiptRecoveryRecord) error {
	key, ok := g.options.Certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return ErrDenied
	}
	record.Signature = nil
	sig, e := sign(receiptRecoveryRecordFormat, *record, key)
	if e != nil {
		return e
	}
	record.Signature = sig
	raw, e := json.Marshal(record)
	if e != nil {
		return e
	}
	return g.store.Write(name, raw)
}

// RecoverReceipt never receives payload, publishes a generation or clears a
// slot. The caller must exclude the worker, hold current policy and install the
// existing volume/quota guard for both registry metadata and replica pins.
func RecoverReceipt(ctx context.Context, o RegistryOptions, item ReceiptRecoveryAdmission, guard func(context.Context) error, fault func(string) error) (Receipt, error) {
	var result Receipt
	if o.Initialize || len(o.Settlement)+len(o.SettlementIntent) != 0 || len(item.Authority) > MaxDocument || len(item.Intent) > MaxDocument || len(item.Grant) > MaxSettlementDocument || !bytes.Equal(o.Authority, item.Authority) {
		return result, ErrDenied
	}
	selected, e := VerifyReceiptRecovery(item.Grant, item.Authority, item.Intent, o.Owner, time.Now())
	if e != nil {
		return result, e
	}
	item = ReceiptRecoveryAdmission{Authority: bytes.Clone(item.Authority), Intent: bytes.Clone(item.Intent), Grant: bytes.Clone(item.Grant)}
	o.Authority = item.Authority
	o.Owner = bytes.Clone(o.Owner)
	ctx, cancel := context.WithDeadline(ctx, time.Unix(selected.ExpiresUnix, 0))
	defer cancel()
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if guard != nil {
			if e := guard(ctx); e != nil {
				return e
			}
		}
		_, e := VerifyReceiptRecovery(item.Grant, item.Authority, item.Intent, o.Owner, time.Now())
		return e
	}
	if e = check(); e != nil {
		return result, e
	}
	g, e := openRegistry(ctx, o, true)
	if e != nil {
		return result, e
	}
	defer g.Close()
	g.Fault = fault
	if !bytes.Equal(g.state.Intent, item.Intent) {
		return result, ErrConflict
	}
	sessionOptions := g.sessionOptions(item.Intent)
	sessionOptions.Initialize = false
	s, e := openSessionFor(ctx, sessionOptions, sessionInspect)
	if e != nil {
		return result, e
	}
	defer s.Close()
	if e = check(); e != nil {
		return result, e
	}
	name := "receipt-recovery-" + selected.Intent + ".json"
	record, exists, e := g.readReceiptRecovery(name, item, selected)
	if e != nil {
		return result, e
	}
	if s.state.Complete {
		if s.state.Receipt == nil || s.state.Receipt.Generation != selected.Generation || exists && record.Receipt != *s.state.Receipt {
			return result, ErrConflict
		}
		return *s.state.Receipt, check()
	}
	if len(s.state.Catalog) == 0 || storage.Hash(s.state.Catalog) != selected.Generation || s.state.Acknowledged {
		return result, ErrIncomplete
	}
	// Unknown files cannot be silently omitted from the recovered accounting.
	d, e := s.objectRoot.Open(".")
	if e != nil {
		return result, e
	}
	names, e := d.ReadDir(generation.MaxObjects*2 + 17)
	d.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return result, e
	}
	for _, entry := range names {
		if !storage.ID(entry.Name()) {
			return result, ErrConflict
		}
	}
	proof, e := o.Replica.PublishedEvidence(ctx, selected.Generation)
	if e != nil {
		return result, e
	}
	result = Receipt{Operation: s.intent.Operation, Ingress: s.intent.Ingress, Tenant: s.intent.Tenant, Domain: s.intent.Domain, Generation: selected.Generation, NewBytes: s.bytes, NewObjects: len(s.refs), VerifiedAt: proof.VerifiedAt}
	if !result.matches(s.intent) {
		return Receipt{}, ErrConflict
	}
	before, e := json.Marshal(s.state)
	if e != nil {
		return Receipt{}, e
	}
	if exists {
		if record.Before != storage.Hash(before) || record.Evidence != proof || record.Receipt != result {
			return Receipt{}, ErrConflict
		}
	} else {
		record = receiptRecoveryRecord{Format: receiptRecoveryRecordFormat, Authority: selected.Authority, Intent: selected.Intent, Before: storage.Hash(before), Evidence: proof, Receipt: result, OriginalGrant: bytes.Clone(item.Grant), CreatedUnix: time.Now().Unix()}
	}
	if !exists || !bytes.Equal(record.ExecutionGrant, item.Grant) {
		record.ExecutionGrant = bytes.Clone(item.Grant)
		record.AuthorizedUnix = time.Now().Unix()
		if e = check(); e != nil {
			return Receipt{}, e
		}
		if e = g.writeReceiptRecovery(name, &record); e != nil {
			return Receipt{}, e
		}
	}
	if e = g.point("receipt-recovery-authorized"); e != nil {
		return Receipt{}, e
	}
	e = o.Replica.WithProtectedPublication(ctx, s.pin("receipt"), proof, check, func() error {
		if e := g.point("receipt-recovery-pinned"); e != nil {
			return e
		}
		if e := check(); e != nil {
			return e
		}
		if time.Now().Unix() < s.state.LastObserved {
			return ErrConflict
		}
		s.state.Complete = true
		s.state.CompletedAt = proof.VerifiedAt
		s.state.LastObserved = time.Now().Unix()
		s.state.Receipt = &result
		if e := s.save(); e != nil {
			return e
		}
		return g.point("receipt-recovery-completed")
	})
	if e != nil {
		return Receipt{}, e
	}
	return result, check()
}
