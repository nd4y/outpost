package ingress

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

const ReceiptRecoveryFormat = "outpost-source-receipt-recovery-1"
const MaxReceiptRecoveryAdmission = 2*MaxDocument + MaxSettlementDocument + 1024

// ReceiptRecovery has the same exact intent/generation claims as Settlement,
// but a different format and signature domain. It admits only explicit local
// recovery from durable publication evidence, never a network payload route.
type ReceiptRecovery Settlement

type ReceiptRecoveryAdmission struct {
	Authority json.RawMessage `json:"authority"`
	Intent    json.RawMessage `json:"intent"`
	Grant     json.RawMessage `json:"grant"`
}

func (s ReceiptRecovery) validate(authority, intent []byte, owner ed25519.PublicKey, now time.Time) error {
	if s.Format != ReceiptRecoveryFormat {
		return ErrDenied
	}
	claims := Settlement(s)
	claims.Format = SettlementFormat
	return claims.validate(authority, intent, owner, now)
}

func SignReceiptRecovery(s ReceiptRecovery, authority, intent []byte, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || s.validate(authority, intent, key.Public().(ed25519.PublicKey), now) != nil {
		return nil, ErrDenied
	}
	s.Signature = nil
	sig, e := sign(ReceiptRecoveryFormat, s, key)
	if e != nil {
		return nil, e
	}
	s.Signature = sig
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > MaxSettlementDocument {
		return nil, ErrDenied
	}
	return raw, nil
}

func VerifyReceiptRecovery(raw, authority, intent []byte, owner ed25519.PublicKey, now time.Time) (ReceiptRecovery, error) {
	var s ReceiptRecovery
	if len(raw) > MaxSettlementDocument || canonical(raw, &s) != nil || s.validate(authority, intent, owner, now) != nil {
		return ReceiptRecovery{}, ErrDenied
	}
	sig := s.Signature
	s.Signature = nil
	valid := verify(ReceiptRecoveryFormat, s, sig, owner)
	s.Signature = sig
	if !valid {
		return ReceiptRecovery{}, ErrDenied
	}
	return s, nil
}
