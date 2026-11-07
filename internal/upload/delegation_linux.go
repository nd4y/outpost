package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const DelegationFormat = "outpost-upload-delegation-1"
const DerivedFormat = "outpost-external-plan-2"
const MaxDelegation = 32 << 10

// Delegation grants no storage credentials or deletion rights. The owner must
// independently admit the exact delegation under current placement policy.
type Delegation struct {
	Format         string           `json:"format"`
	Trust          generation.Trust `json:"trust"`
	Epoch          uint64           `json:"epoch"`
	Profile        storage.Profile  `json:"profile"`
	AllowedClasses []string         `json:"allowedClasses"`
	Workers        []Worker         `json:"workers"`
	StartMillis    int64            `json:"startMillis"`
	ExpiresUnix    int64            `json:"expiresUnix"`
	SlotMillis     int64            `json:"slotMillis"`
	Signature      []byte           `json:"signature,omitempty"`
}

func (d Delegation) template() Plan {
	return Plan{Format: Format, Operation: storage.Hash([]byte(DelegationFormat)), Profile: d.Profile, AllowExternal: true, AllowedClasses: d.AllowedClasses, Workers: d.Workers, StartMillis: d.StartMillis, ExpiresUnix: d.ExpiresUnix, SlotMillis: d.SlotMillis}
}
func (d Delegation) validate(a Authority) error {
	t := d.Trust
	if d.Format != DelegationFormat || d.Epoch == 0 || !sameTrust(t, a.Generation) || !storage.ID(t.Domain) || !storage.ID(t.Repository) || t.Epoch == 0 || len(t.Writer) != 32 || len(t.Maintenance) != 32 || len(a.Planner) != 32 || bytes.Equal(t.Writer, t.Maintenance) || bytes.Equal(t.Writer, a.Planner) || bytes.Equal(t.Maintenance, a.Planner) || d.Profile.Namespace != storage.Hash([]byte(t.Domain+"/"+t.Repository)) {
		return ErrDenied
	}
	return d.template().policy()
}
func SignDelegation(d Delegation, planner ed25519.PrivateKey) ([]byte, error) {
	if len(planner) != 64 {
		return nil, ErrDenied
	}
	if e := d.validate(Authority{d.Trust, planner.Public().(ed25519.PublicKey)}); e != nil {
		return nil, e
	}
	d.Signature = nil
	raw, e := json.Marshal(d)
	if e != nil || len(raw) > MaxDelegation-128 {
		return nil, ErrDenied
	}
	d.Signature = ed25519.Sign(planner, append([]byte(DelegationFormat+"\x00"), raw...))
	return json.Marshal(d)
}
func VerifyDelegation(raw []byte, a Authority) (Delegation, error) {
	var d Delegation
	if storage.Decode(raw, &d, MaxDelegation) != nil || d.validate(a) != nil || len(d.Signature) != 64 {
		return d, ErrDenied
	}
	canonical, e := json.Marshal(d)
	if e != nil || !bytes.Equal(canonical, raw) {
		return d, ErrDenied
	}
	sig := d.Signature
	d.Signature = nil
	unsigned, e := json.Marshal(d)
	d.Signature = sig
	if e != nil || !ed25519.Verify(a.Planner, append([]byte(DelegationFormat+"\x00"), unsigned...), sig) {
		return Delegation{}, ErrDenied
	}
	return d, nil
}
func DelegatedOperation(raw []byte, id string) string {
	return storage.Hash([]byte(storage.Hash(raw) + "/" + id))
}
func derivedTemplate(raw []byte, d Delegation, id string) Plan {
	p := d.template()
	p.Format = DerivedFormat
	p.Operation = DelegatedOperation(raw, id)
	p.Generation = id
	p.Delegation = bytes.Clone(raw)
	return p
}

// BuildDerived needs a complete local replica and public delegation only.
// The signed catalog authenticates full objects; partition hashes are checked
// against actual bytes again on upload and full target verification.
func BuildDerived(ctx context.Context, source *generation.Replica, id string, raw []byte, a Authority) ([]byte, error) {
	return BuildDerivedCached(ctx, source, id, raw, a, nil)
}

// BuildDerivedCached retains multipart descriptions between bounded attempts.
// Cached maps are planning metadata, never evidence of available source/target bytes.
func BuildDerivedCached(ctx context.Context, source *generation.Replica, id string, raw []byte, a Authority, cache *PlanningCache) ([]byte, error) {
	d, e := VerifyDelegation(raw, a)
	if e != nil || source == nil || !sameTrust(source.Trust(), a.Generation) || !storage.ID(id) {
		return nil, ErrDenied
	}
	p := derivedTemplate(raw, d, id)
	p.Catalog, e = source.Catalog(ctx, id)
	if e != nil {
		return nil, e
	}
	refs, e := generation.Dependencies(p.Catalog, a.Generation)
	if e != nil {
		return nil, e
	}
	if e = preflightPlan(p, refs); e != nil {
		return nil, e
	}
	scopeRaw, e := json.Marshal(struct {
		Authority Authority `json:"authority"`
		Operation string    `json:"operation"`
	}{a, p.Operation})
	if e != nil {
		return nil, e
	}
	scope := storage.Hash(scopeRaw)
	p.Blobs = make([]storage.Blob, 0, len(refs))
	for i, ref := range refs {
		compute := func() (storage.Blob, error) { return describeReference(ctx, source, id, ref, p.Profile.MaxObjectBytes) }
		var blob storage.Blob
		if cache != nil && ref.Bytes > p.Profile.MaxObjectBytes {
			blob, e = cache.describe(ctx, scope, refs, i, p.Profile.MaxObjectBytes, compute)
		} else {
			blob, e = compute()
		}
		if e != nil {
			return nil, e
		}
		p.Blobs = append(p.Blobs, blob)
	}
	if e = p.validate(a); e != nil {
		return nil, e
	}
	result, e := json.Marshal(p)
	if e != nil || len(result) > MaxPlan {
		return nil, ErrDenied
	}
	return result, ctx.Err()
}
func verifyDerived(raw []byte, p Plan, a Authority) error {
	d, e := VerifyDelegation(p.Delegation, a)
	if e != nil {
		return e
	}
	expected := derivedTemplate(p.Delegation, d, p.Generation)
	expected.Catalog = p.Catalog
	expected.Blobs = p.Blobs
	canonical, e := json.Marshal(expected)
	if e != nil || !bytes.Equal(canonical, raw) || p.validate(a) != nil {
		return ErrDenied
	}
	for _, blob := range p.Blobs {
		if canonicalParts(blob, p.Profile.MaxObjectBytes) != nil {
			return ErrDenied
		}
	}
	return nil
}
