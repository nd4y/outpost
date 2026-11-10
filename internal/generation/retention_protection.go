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

// RetirementBinding identifies the operation that must close before a survivor
// can release its hold.
type RetirementBinding struct {
	Node      string `json:"node"`
	Operation string `json:"operationId"`
}

func (b *RetirementBinding) valid(holder string) bool {
	return b == nil || validID(b.Node) && b.Node != holder && validID(b.Operation)
}

func sameRetirement(a, b *RetirementBinding) bool {
	return a == b || a != nil && b != nil && *a == *b
}

// RetentionProtection authorizes one local change. ExpiresUnix limits admission;
// an admitted hold persists until a matching RELEASE is durably applied.
type RetentionProtection struct {
	Format      string                      `json:"format"`
	Node        string                      `json:"node"`
	Domain      string                      `json:"domain"`
	Repository  string                      `json:"repository"`
	Epoch       uint64                      `json:"epoch"`
	Operation   string                      `json:"operationId"`
	Generation  string                      `json:"generation"`
	Action      string                      `json:"action"`
	HoldDigest  string                      `json:"holdDigest,omitempty"`
	Retirement  *RetirementBinding          `json:"retirement,omitempty"`
	Closure     *RetentionProtectionReceipt `json:"closure,omitempty"`
	NotBefore   int64                       `json:"notBefore"`
	ExpiresUnix int64                       `json:"expiresUnix"`
	Signature   []byte                      `json:"signature,omitempty"`
}

type RetentionProtectionReceipt struct {
	Format       string             `json:"format"`
	Node         string             `json:"node"`
	NodeKey      ed25519.PublicKey  `json:"nodeKey"`
	Domain       string             `json:"domain"`
	Repository   string             `json:"repository"`
	Epoch        uint64             `json:"epoch"`
	Operation    string             `json:"operationId"`
	Generation   string             `json:"generation"`
	State        string             `json:"state"`
	GrantDigest  string             `json:"grantDigest"`
	HoldDigest   string             `json:"holdDigest"`
	Retirement   *RetirementBinding `json:"retirement,omitempty"`
	Revision     uint64             `json:"revision"`
	ObservedUnix int64              `json:"observedUnix"`
	Signature    []byte             `json:"signature,omitempty"`
}

func (p RetentionProtection) valid() bool {
	if p.Format != RetentionProtectionFormat || !validID(p.Node) || !validID(p.Domain) || !validID(p.Repository) ||
		p.Epoch == 0 || !validID(p.Operation) || p.NotBefore <= 0 || p.ExpiresUnix > 1<<40 ||
		p.ExpiresUnix <= p.NotBefore || p.ExpiresUnix-p.NotBefore > 24*3600 || !p.Retirement.valid(p.Node) {
		return false
	}
	switch p.Action {
	case "HOLD":
		return validID(p.Generation) && p.HoldDigest == "" && p.Closure == nil
	case "RELEASE":
		return validID(p.Generation) && validID(p.HoldDigest) && p.validClosure()
	case "CLOSE":
		return p.Generation == "" && p.HoldDigest == "" && p.Retirement == nil && p.Closure == nil
	default:
		return false
	}
}

func (p RetentionProtection) validClosure() bool {
	if p.Retirement == nil {
		return p.Closure == nil
	}
	c := p.Closure
	return c != nil && c.State == "CLOSED" && c.Node == p.Retirement.Node && c.Operation == p.Retirement.Operation &&
		c.Domain == p.Domain && c.Repository == p.Repository && c.Epoch == p.Epoch && c.valid()
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

// VerifyRetentionProtection authenticates a grant for the specified holder.
// The replica checks time when admitting a new effect.
func VerifyRetentionProtection(raw []byte, trust Trust, node string) (RetentionProtection, error) {
	var p RetentionProtection
	if !trust.valid() || canonical(raw, &p, MaxRetentionProtection) != nil || !p.valid() ||
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
		!validID(r.Domain) || !validID(r.Repository) || r.Epoch == 0 || !validID(r.Operation) ||
		!validID(r.GrantDigest) || r.Revision == 0 || r.ObservedUnix < 1 || r.ObservedUnix > 1<<40 ||
		!r.Retirement.valid(r.Node) || !r.validState() {
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

func (r RetentionProtectionReceipt) validState() bool {
	switch r.State {
	case "HELD":
		return validID(r.Generation) && r.HoldDigest == r.GrantDigest
	case "RELEASED":
		return validID(r.Generation) && validID(r.HoldDigest) && r.HoldDigest != r.GrantDigest
	case "CLOSED":
		return r.Generation == "" && r.HoldDigest == "" && r.Retirement == nil
	default:
		return false
	}
}

func retentionPin(operation string) string {
	return Hash([]byte("retention-protection\x00" + operation))
}
