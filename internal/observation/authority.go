// Package observation verifies owner-scoped, portable copy observations.
package observation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const GrantFormat = "outpost-observation-grant-1"
const ProofFormat = "outpost-copy-observation-1"
const MaxDocument = 16 << 10
const MaxReply = 128 << 10

var ErrDenied = errors.New("copy observation denied")
var ErrPending = errors.New("copy observation unavailable")

type Grant struct {
	Format        string           `json:"format"`
	Trust         generation.Trust `json:"trust"`
	Reader        string           `json:"reader"`
	Collector     string           `json:"collector"`
	Targets       []string         `json:"targets"`
	Epoch         uint64           `json:"epoch"`
	NotBefore     int64            `json:"notBefore"`
	ExpiresUnix   int64            `json:"expiresUnix"`
	MaxAgeSeconds int64            `json:"maxAgeSeconds"`
	Signature     []byte           `json:"signature,omitempty"`
}
type Proof struct {
	Format       string            `json:"format"`
	Grant        string            `json:"grant"`
	Generation   string            `json:"generation"`
	Target       string            `json:"target"`
	PublicKey    ed25519.PublicKey `json:"publicKey"`
	Verification string            `json:"verification"`
	ObservedUnix int64             `json:"observedUnix"`
	Signature    []byte            `json:"signature,omitempty"`
}
type Bundle struct {
	Format     string            `json:"format"`
	Grant      string            `json:"grant"`
	Generation string            `json:"generation"`
	Proofs     []json.RawMessage `json:"proofs"`
}

func Identity(k ed25519.PublicKey) string {
	if len(k) != ed25519.PublicKeySize {
		return ""
	}
	raw, e := x509.MarshalPKIXPublicKey(k)
	if e != nil {
		return ""
	}
	return storage.Hash(raw)
}
func SameTrust(a, b generation.Trust) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
func (g Grant) Target(id string) bool {
	for _, v := range g.Targets {
		if v == id {
			return true
		}
	}
	return false
}
func (g Grant) Active(now time.Time) bool {
	return now.Unix() >= g.NotBefore && now.Unix() < g.ExpiresUnix
}
func (g Grant) validate(owner ed25519.PublicKey) error {
	t := g.Trust
	if g.Format != GrantFormat || len(owner) != 32 || !storage.ID(t.Domain) || !storage.ID(t.Repository) || t.Epoch == 0 || len(t.Writer) != 32 || len(t.Maintenance) != 32 || bytes.Equal(owner, t.Writer) || bytes.Equal(owner, t.Maintenance) || bytes.Equal(t.Writer, t.Maintenance) || !storage.ID(g.Reader) || !storage.ID(g.Collector) || g.Reader == g.Collector || g.Epoch == 0 || g.NotBefore < 1 || g.ExpiresUnix <= g.NotBefore || g.ExpiresUnix > 1<<40 || g.MaxAgeSeconds < 60 || g.MaxAgeSeconds > 366*86400 || len(g.Targets) < 1 || len(g.Targets) > 32 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, id := range g.Targets {
		if !storage.ID(id) || id == g.Reader || seen[id] || id == Identity(owner) || id == Identity(t.Writer) || id == Identity(t.Maintenance) {
			return ErrDenied
		}
		seen[id] = true
	}
	return nil
}
func canonical(raw []byte, v any) error {
	if storage.Decode(raw, v, MaxDocument) != nil {
		return ErrDenied
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrDenied
	}
	return nil
}
func signed(prefix string, v any, k ed25519.PrivateKey) ([]byte, error) {
	if len(k) != 64 {
		return nil, ErrDenied
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > MaxDocument-128 {
		return nil, ErrDenied
	}
	return ed25519.Sign(k, append([]byte(prefix+"\x00"), b...)), nil
}
func valid(prefix string, v any, sig []byte, k ed25519.PublicKey) bool {
	if len(k) != 32 || len(sig) != 64 {
		return false
	}
	b, e := json.Marshal(v)
	return e == nil && ed25519.Verify(k, append([]byte(prefix+"\x00"), b...), sig)
}
func SignGrant(g Grant, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != 64 {
		return nil, ErrDenied
	}
	if e := g.validate(key.Public().(ed25519.PublicKey)); e != nil {
		return nil, e
	}
	g.Signature = nil
	sig, e := signed(GrantFormat, g, key)
	if e != nil {
		return nil, e
	}
	g.Signature = sig
	return json.Marshal(g)
}
func VerifyGrant(raw []byte, owner ed25519.PublicKey) (Grant, error) {
	var g Grant
	if canonical(raw, &g) != nil || g.validate(owner) != nil {
		return g, ErrDenied
	}
	sig := g.Signature
	g.Signature = nil
	ok := valid(GrantFormat, g, sig, owner)
	g.Signature = sig
	if !ok {
		return Grant{}, ErrDenied
	}
	return g, nil
}
func SignProof(grant []byte, owner ed25519.PublicKey, id string, observed int64, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	g, e := VerifyGrant(grant, owner)
	if e != nil || len(key) != 64 {
		return nil, ErrDenied
	}
	p := Proof{Format: ProofFormat, Grant: storage.Hash(grant), Generation: id, Target: Identity(key.Public().(ed25519.PublicKey)), PublicKey: key.Public().(ed25519.PublicKey), Verification: "ciphertext-readback", ObservedUnix: observed}
	if p.validate(g, storage.Hash(grant), id, now) != nil {
		return nil, ErrDenied
	}
	sig, e := signed(ProofFormat, p, key)
	if e != nil {
		return nil, e
	}
	p.Signature = sig
	return json.Marshal(p)
}
func (p Proof) validate(g Grant, grant, id string, now time.Time) error {
	if p.Format != ProofFormat || !g.Active(now) || p.Grant != grant || !storage.ID(id) || p.Generation != id || !g.Target(p.Target) || Identity(p.PublicKey) != p.Target || p.Verification != "ciphertext-readback" || p.ObservedUnix < 1 || p.ObservedUnix > now.Unix() || now.Unix()-p.ObservedUnix > g.MaxAgeSeconds {
		return ErrDenied
	}
	return nil
}
func VerifyProof(raw, grant []byte, owner ed25519.PublicKey, id string, now time.Time) (Proof, error) {
	p, e := VerifyProofDocument(raw, grant, owner, id)
	if e != nil {
		return Proof{}, e
	}
	g, _ := VerifyGrant(grant, owner)
	if p.validate(g, storage.Hash(grant), id, now) != nil {
		return Proof{}, ErrDenied
	}
	return p, nil
}

// Historical verification preserves stale evidence without treating it as current.
func VerifyProofDocument(raw, grant []byte, owner ed25519.PublicKey, id string) (Proof, error) {
	g, e := VerifyGrant(grant, owner)
	if e != nil {
		return Proof{}, e
	}
	var p Proof
	if canonical(raw, &p) != nil || p.Format != ProofFormat || p.Grant != storage.Hash(grant) || !storage.ID(id) || p.Generation != id || !g.Target(p.Target) || Identity(p.PublicKey) != p.Target || p.Verification != "ciphertext-readback" || p.ObservedUnix < 1 || p.ObservedUnix > 1<<40 {
		return Proof{}, ErrDenied
	}
	sig := p.Signature
	p.Signature = nil
	ok := valid(ProofFormat, p, sig, p.PublicKey)
	p.Signature = sig
	if !ok {
		return Proof{}, ErrDenied
	}
	return p, nil
}
