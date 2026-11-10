package generation

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
)

const RetentionProtectionFormat = "outpost-retention-protection-1"
const RetentionProtectionReceiptFormat = "outpost-retention-protection-receipt-1"
const MaxRetentionProtection = 4096
const maxRetentionProtectionRecords = 256
const retentionPinKind = "retention"

// RetentionProtection authorizes one local change. ExpiresUnix limits admission;
// an admitted hold persists until a matching RELEASE is durably applied.
type RetentionProtection struct {
	Format      string `json:"format"`
	Node        string `json:"node"`
	Domain      string `json:"domain"`
	Repository  string `json:"repository"`
	Epoch       uint64 `json:"epoch"`
	Operation   string `json:"operationId"`
	Generation  string `json:"generation"`
	Action      string `json:"action"`
	HoldDigest  string `json:"holdDigest,omitempty"`
	NotBefore   int64  `json:"notBefore"`
	ExpiresUnix int64  `json:"expiresUnix"`
	Signature   []byte `json:"signature,omitempty"`
}

type RetentionProtectionReceipt struct {
	Format       string            `json:"format"`
	Node         string            `json:"node"`
	NodeKey      ed25519.PublicKey `json:"nodeKey"`
	Domain       string            `json:"domain"`
	Repository   string            `json:"repository"`
	Epoch        uint64            `json:"epoch"`
	Operation    string            `json:"operationId"`
	Generation   string            `json:"generation"`
	State        string            `json:"state"`
	GrantDigest  string            `json:"grantDigest"`
	HoldDigest   string            `json:"holdDigest"`
	Revision     uint64            `json:"revision"`
	ObservedUnix int64             `json:"observedUnix"`
	Signature    []byte            `json:"signature,omitempty"`
}

func (p RetentionProtection) valid() bool {
	return p.Format == RetentionProtectionFormat && validID(p.Node) && validID(p.Domain) && validID(p.Repository) && p.Epoch > 0 &&
		validID(p.Operation) && validID(p.Generation) && p.NotBefore > 0 && p.ExpiresUnix <= 1<<40 &&
		p.ExpiresUnix > p.NotBefore && p.ExpiresUnix-p.NotBefore <= 24*3600 &&
		(p.Action == "HOLD" && p.HoldDigest == "" || p.Action == "RELEASE" && validID(p.HoldDigest))
}

func SignRetentionProtection(p RetentionProtection, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || len(p.Signature) != 0 || !p.valid() {
		return nil, ErrInvalid
	}
	unsigned, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	p.Signature = ed25519.Sign(key, append([]byte(RetentionProtectionFormat+"\x00"), unsigned...))
	return json.Marshal(p)
}

func verifyRetentionProtection(raw []byte, trust Trust, node string) (RetentionProtection, error) {
	var p RetentionProtection
	if canonical(raw, &p, MaxRetentionProtection) != nil || !p.valid() ||
		p.Node != node || p.Domain != trust.Domain || p.Repository != trust.Repository || p.Epoch != trust.Epoch {
		return p, ErrInvalid
	}
	sig := p.Signature
	p.Signature = nil
	unsigned, e := json.Marshal(p)
	if e != nil || !ed25519.Verify(trust.Maintenance, append([]byte(RetentionProtectionFormat+"\x00"), unsigned...), sig) {
		return p, ErrInvalid
	}
	return p, nil
}

// VerifyRetentionProtectionReceipt authenticates historical evidence from the
// expected enrolled node. The receipt retains its original observation time.
func VerifyRetentionProtectionReceipt(raw []byte, node string) (RetentionProtectionReceipt, error) {
	var receipt RetentionProtectionReceipt
	if canonical(raw, &receipt, MaxRetentionProtection) != nil || receipt.Node != node || !receipt.valid() {
		return receipt, ErrInvalid
	}
	return receipt, nil
}

func (r RetentionProtectionReceipt) valid() bool {
	if r.Format != RetentionProtectionReceiptFormat || len(r.NodeKey) != ed25519.PublicKeySize || !validID(r.Node) ||
		!validID(r.Domain) || !validID(r.Repository) || r.Epoch == 0 || !validID(r.Operation) || !validID(r.Generation) ||
		!validID(r.GrantDigest) || !validID(r.HoldDigest) || r.Revision == 0 || r.ObservedUnix < 1 || r.ObservedUnix > 1<<40 ||
		!(r.State == "HELD" && r.GrantDigest == r.HoldDigest || r.State == "RELEASED" && r.GrantDigest != r.HoldDigest) {
		return false
	}
	der, e := x509.MarshalPKIXPublicKey(r.NodeKey)
	if e != nil || Hash(der) != r.Node {
		return false
	}
	sig := r.Signature
	r.Signature = nil
	unsigned, e := json.Marshal(r)
	return e == nil && ed25519.Verify(r.NodeKey, append([]byte(RetentionProtectionReceiptFormat+"\x00"), unsigned...), sig)
}

func retentionPin(operation string) string {
	return Hash([]byte("retention-protection\x00" + operation))
}
