package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

// ReceiptRecoveryPreview describes the same sealed intent as settlement, but
// requests separate local receiver permission. It proves no remote completion.
func (a *Agent) ReceiptRecoveryPreview(ctx context.Context) (ingress.ReceiptRecoveryAdmission, error) {
	item, e := a.SettlementPreview(ctx)
	if e != nil {
		return ingress.ReceiptRecoveryAdmission{}, e
	}
	var claim ingress.ReceiptRecovery
	if storage.Decode(item.Grant, &claim, ingress.MaxSettlementDocument) != nil {
		return ingress.ReceiptRecoveryAdmission{}, ErrInvalid
	}
	claim.Format = ingress.ReceiptRecoveryFormat
	raw, e := json.Marshal(claim)
	if e != nil {
		return ingress.ReceiptRecoveryAdmission{}, e
	}
	return ingress.ReceiptRecoveryAdmission{Authority: item.Authority, Intent: item.Intent, Grant: raw}, nil
}

func SignReceiptRecoveryAdmission(item ingress.ReceiptRecoveryAdmission, key ed25519.PrivateKey) (ingress.ReceiptRecoveryAdmission, error) {
	var claim ingress.ReceiptRecovery
	if storage.Decode(item.Grant, &claim, ingress.MaxSettlementDocument) != nil || len(claim.Signature) != 0 {
		return ingress.ReceiptRecoveryAdmission{}, ErrInvalid
	}
	raw, e := ingress.SignReceiptRecovery(claim, item.Authority, item.Intent, key, time.Now())
	if e != nil {
		return ingress.ReceiptRecoveryAdmission{}, e
	}
	return ingress.ReceiptRecoveryAdmission{Authority: bytes.Clone(item.Authority), Intent: bytes.Clone(item.Intent), Grant: raw}, nil
}
