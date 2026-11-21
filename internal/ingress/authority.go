// Package ingress admits source ciphertext under explicit owner and writer
// authority. It does not grant placement or deletion rights by node category.
package ingress

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

const AuthorityFormat = "outpost-ingress-authority-1"
const IntentFormat = "outpost-capture-intent-1"
const MaxDocument = 16 << 10

var ErrDenied = errors.New("source ingress authority denied")
var ErrConflict = errors.New("source capture binding conflict")
var ErrIncomplete = errors.New("source capture is incomplete")

// Authority is a separate owner-signed capability carried by the approved
// source and ingress configurations. Tenant and profile are opaque identities;
// source paths, labels, decryption keys and storage secrets never appear here.
type Authority struct {
	Format      string           `json:"format"`
	Tenant      string           `json:"tenant"`
	Profile     string           `json:"profile"`
	Source      string           `json:"source"`
	Ingress     string           `json:"ingress"`
	Revision    uint64           `json:"revision"`
	NotBefore   int64            `json:"notBefore"`
	ExpiresUnix int64            `json:"expiresUnix"`
	Trust       generation.Trust `json:"trust"`
	MaxBytes    int64            `json:"maxBytes"`
	MaxObjects  int              `json:"maxObjects"`
	Signature   []byte           `json:"signature,omitempty"`
}
type Intent struct {
	Format       string `json:"format"`
	Operation    string `json:"operation"`
	Authority    string `json:"authority"`
	Tenant       string `json:"tenant"`
	Profile      string `json:"profile"`
	Source       string `json:"source"`
	Ingress      string `json:"ingress"`
	Domain       string `json:"domain"`
	Repository   string `json:"repository"`
	Epoch        uint64 `json:"writerEpoch"`
	Sequence     uint64 `json:"sequence"`
	Parent       string `json:"parentCheckpoint"`
	Policy       uint64 `json:"policyVersion"`
	SnapshotUnix int64  `json:"snapshotUnix"`
	NotBefore    int64  `json:"notBefore"`
	ExpiresUnix  int64  `json:"expiresUnix"`
	MaxBytes     int64  `json:"maxBytes"`
	MaxObjects   int    `json:"maxObjects"`
	Signature    []byte `json:"signature,omitempty"`
}

func keyID(key ed25519.PublicKey) string {
	b, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		return ""
	}
	return storage.Hash(b)
}
func (a Authority) validate(owner ed25519.PublicKey) error {
	t := a.Trust
	if a.Format != AuthorityFormat || !storage.ID(a.Tenant) || !storage.ID(a.Profile) || !storage.ID(a.Source) || !storage.ID(a.Ingress) || a.Source == a.Ingress || a.Revision == 0 || a.NotBefore < 1 || a.ExpiresUnix <= a.NotBefore || a.ExpiresUnix > 1<<40 || a.MaxObjects < 1 || a.MaxObjects > generation.MaxObjects || a.MaxBytes < 1 || a.MaxBytes > int64(a.MaxObjects)*generation.MaxObject || len(owner) != 32 || !storage.ID(t.Domain) || !storage.ID(t.Repository) || t.Epoch == 0 || len(t.Writer) != 32 || len(t.Maintenance) != 32 {
		return ErrDenied
	}
	if bytes.Equal(owner, t.Writer) || bytes.Equal(owner, t.Maintenance) || bytes.Equal(t.Writer, t.Maintenance) {
		return ErrDenied
	}
	for _, key := range []ed25519.PublicKey{owner, t.Writer, t.Maintenance} {
		if id := keyID(key); id == a.Source || id == a.Ingress {
			return ErrDenied
		}
	}
	return nil
}
func (i Intent) validate(a Authority, authorityID string) error {
	if i.Format != IntentFormat || !storage.ID(i.Operation) || i.Authority != authorityID || i.Tenant != a.Tenant || i.Profile != a.Profile || i.Source != a.Source || i.Ingress != a.Ingress || i.Domain != a.Trust.Domain || i.Repository != a.Trust.Repository || i.Epoch != a.Trust.Epoch || i.Policy != a.Revision || i.Sequence == 0 || i.SnapshotUnix < 1 || i.NotBefore < a.NotBefore || i.ExpiresUnix <= i.NotBefore || i.ExpiresUnix > a.ExpiresUnix || i.MaxBytes < 1 || i.MaxBytes > a.MaxBytes || i.MaxObjects < 1 || i.MaxObjects > a.MaxObjects || i.MaxBytes > int64(i.MaxObjects)*generation.MaxObject {
		return ErrDenied
	}
	if i.Sequence == 1 && i.Parent != "" || i.Sequence > 1 && !storage.ID(i.Parent) {
		return ErrDenied
	}
	return nil
}
func canonical(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > MaxDocument {
		return ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrDenied
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(raw, b) {
		return ErrDenied
	}
	return nil
}
func active(now time.Time, start, end int64) bool { return now.Unix() >= start && now.Unix() < end }
func sign(prefix string, v any, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrDenied
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > MaxDocument {
		return nil, ErrDenied
	}
	return ed25519.Sign(key, append([]byte(prefix+"\x00"), b...)), nil
}
func verify(prefix string, v any, sig []byte, key ed25519.PublicKey) bool {
	b, e := json.Marshal(v)
	return e == nil && len(key) == 32 && ed25519.Verify(key, append([]byte(prefix+"\x00"), b...), sig)
}
func SignAuthority(a Authority, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrDenied
	}
	if e := a.validate(key.Public().(ed25519.PublicKey)); e != nil {
		return nil, e
	}
	a.Signature = nil
	sig, e := sign(AuthorityFormat, a, key)
	if e != nil {
		return nil, e
	}
	a.Signature = sig
	return json.Marshal(a)
}
func VerifyAuthority(raw []byte, owner ed25519.PublicKey, now time.Time) (Authority, error) {
	a, e := VerifyAuthorityDocument(raw, owner)
	if e != nil {
		return a, e
	}
	if !active(now, a.NotBefore, a.ExpiresUnix) {
		return Authority{}, ErrDenied
	}
	return a, nil
}

// VerifyAuthorityDocument authenticates a capability without granting current
// use. Cached configuration validation must also check its enclosing lifetime.
func VerifyAuthorityDocument(raw []byte, owner ed25519.PublicKey) (Authority, error) {
	var a Authority
	if e := canonical(raw, &a); e != nil {
		return a, e
	}
	if a.validate(owner) != nil {
		return a, ErrDenied
	}
	sig := a.Signature
	a.Signature = nil
	valid := verify(AuthorityFormat, a, sig, owner)
	a.Signature = sig
	if !valid {
		return Authority{}, ErrDenied
	}
	return a, nil
}
func SignIntent(i Intent, authorityRaw []byte, owner ed25519.PublicKey, writer ed25519.PrivateKey, now time.Time) ([]byte, error) {
	a, e := VerifyAuthority(authorityRaw, owner, now)
	if e != nil {
		return nil, e
	}
	if len(writer) != ed25519.PrivateKeySize || !bytes.Equal(writer.Public().(ed25519.PublicKey), a.Trust.Writer) || i.validate(a, storage.Hash(authorityRaw)) != nil || !active(now, i.NotBefore, i.ExpiresUnix) {
		return nil, ErrDenied
	}
	i.Signature = nil
	sig, e := sign(IntentFormat, i, writer)
	if e != nil {
		return nil, e
	}
	i.Signature = sig
	return json.Marshal(i)
}
func VerifyIntent(raw, authorityRaw []byte, owner ed25519.PublicKey, now time.Time) (Intent, Authority, error) {
	var i Intent
	a, e := VerifyAuthority(authorityRaw, owner, now)
	if e != nil {
		return i, a, e
	}
	if canonical(raw, &i) != nil || i.validate(a, storage.Hash(authorityRaw)) != nil || !active(now, i.NotBefore, i.ExpiresUnix) {
		return i, a, ErrDenied
	}
	sig := i.Signature
	i.Signature = nil
	valid := verify(IntentFormat, i, sig, a.Trust.Writer)
	i.Signature = sig
	if !valid {
		return Intent{}, a, ErrDenied
	}
	return i, a, nil
}
func (i Intent) matches(c generation.Catalog) bool {
	return c.Domain == i.Domain && c.Repository == i.Repository && c.Epoch == i.Epoch && c.Sequence == i.Sequence && c.Parent == i.Parent && c.Policy == i.Policy && c.SnapshotUnix == i.SnapshotUnix
}
