package ingress

import (
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

const SettlementFormat = "outpost-source-settlement-1"
const MaxSettlementDocument = 4096

const (
	SettlementPublish        = "publish-staged"
	SettlementInspect        = "inspect-active"
	SettlementRetire         = "retire-unadmitted"
	SettlementRetireUnsealed = "retire-unsealed"
)

// Settlement is bound to an immutable intent. The legacy purpose retrieves
// and acknowledges a receipt. Other purposes permit only the exact staged
// publication, inspection or retirement described by the signed grant.
type Settlement struct {
	Format      string `json:"format"`
	ID          string `json:"id"`
	Authority   string `json:"authority"`
	Intent      string `json:"intent"`
	Operation   string `json:"operation"`
	Source      string `json:"source"`
	Ingress     string `json:"ingress"`
	Tenant      string `json:"tenant"`
	Domain      string `json:"domain"`
	Repository  string `json:"repository"`
	Epoch       uint64 `json:"writerEpoch"`
	Purpose     string `json:"purpose,omitempty"`
	Generation  string `json:"generation"`
	NotBefore   int64  `json:"notBefore"`
	ExpiresUnix int64  `json:"expiresUnix"`
	Signature   []byte `json:"signature,omitempty"`
}

func (s Settlement) validate(authority, intent []byte, owner ed25519.PublicKey, now time.Time) error {
	var i Intent
	if canonicalIntent(intent, authority, owner, &i) != nil {
		return ErrDenied
	}
	if s.Format != SettlementFormat || !storage.ID(s.ID) || s.Authority != storage.Hash(authority) || s.Intent != storage.Hash(intent) || s.Operation != i.Operation || s.Source != i.Source || s.Ingress != i.Ingress || s.Tenant != i.Tenant || s.Domain != i.Domain || s.Repository != i.Repository || s.Epoch != i.Epoch || s.NotBefore < 1 || s.ExpiresUnix <= s.NotBefore || s.ExpiresUnix > 1<<40 || !active(now, s.NotBefore, s.ExpiresUnix) {
		return ErrDenied
	}
	switch s.Purpose {
	case "":
		if !storage.ID(s.Generation) {
			return ErrDenied
		}
	case SettlementPublish, SettlementInspect, SettlementRetire, SettlementRetireUnsealed:
		if s.NotBefore < i.ExpiresUnix || s.ExpiresUnix-s.NotBefore > 86400 ||
			s.Purpose == SettlementPublish && !storage.ID(s.Generation) ||
			s.inspect() && s.Generation != "" {
			return ErrDenied
		}
	default:
		return ErrDenied
	}
	return nil
}

func (s Settlement) inspect() bool {
	return s.Purpose == SettlementInspect || s.Purpose == SettlementRetire || s.Purpose == SettlementRetireUnsealed
}

func SignSettlement(s Settlement, authority, intent []byte, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || s.validate(authority, intent, key.Public().(ed25519.PublicKey), now) != nil {
		return nil, ErrDenied
	}
	s.Signature = nil
	sig, e := sign(SettlementFormat, s, key)
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

func VerifySettlement(raw, authority, intent []byte, owner ed25519.PublicKey, now time.Time) (Settlement, error) {
	var s Settlement
	if len(raw) > MaxSettlementDocument || canonical(raw, &s) != nil || s.validate(authority, intent, owner, now) != nil {
		return Settlement{}, ErrDenied
	}
	sig := s.Signature
	s.Signature = nil
	valid := verify(SettlementFormat, s, sig, owner)
	s.Signature = sig
	if !valid {
		return Settlement{}, ErrDenied
	}
	return s, nil
}
