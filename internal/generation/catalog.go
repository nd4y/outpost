// Package generation is the bounded G2 local-replica candidate. It is not a
// network service, admission controller or production format commitment.
package generation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

const (
	Format             = "outpost-generation-1"
	PermitWindowFormat = "outpost-maintenance-permit-2"
	MaxPermit          = 64 << 10
	StateFormat        = "outpost-replica-state-2"
	KitFormat          = "outpost-filekit-1"
	TypedKitFormat     = "outpost-filekit-2"
	MaxObject          = 8 << 20
	MaxCatalog         = 8 << 20
	MaxObjects         = 32768
	MaxKits            = 4096
	MaxGenerations     = 256
	MaxPins            = 1024
	MaxState           = 32 << 20
)

var (
	ErrInvalid           = errors.New("invalid generation or replica state")
	ErrConflict          = errors.New("conflicting signed generation")
	ErrRollback          = errors.New("stale generation or authority")
	ErrProtected         = errors.New("generation is locally protected")
	ErrIncomplete        = errors.New("generation dependencies unavailable or corrupt")
	ErrMigrationRequired = errors.New("explicit local replica migration required")
	ErrMaintenanceWindow = errors.New("maintenance node or window does not permit deletion")
	ErrRetirementClosed  = errors.New("retirement operation is durably closed")
)

type Object struct {
	ID    string `json:"id"`
	Bytes int    `json:"bytes"`
}
type Kit struct {
	File    string   `json:"file"`
	Version string   `json:"version"`
	Root    Object   `json:"root"`
	Objects []Object `json:"objects"`
}
type Catalog struct {
	Format       string `json:"format"`
	Domain       string `json:"domain"`
	Repository   string `json:"repository"`
	Epoch        uint64 `json:"writerEpoch"`
	Sequence     uint64 `json:"sequence"`
	Parent       string `json:"parentCheckpoint"`
	SnapshotUnix int64  `json:"snapshotUnix"`
	Policy       uint64 `json:"policyVersion"`
	KitFormat    string `json:"kitFormat"`
	Kits         []Kit  `json:"kits"`
	Signature    []byte `json:"signature,omitempty"`
}

// Trust is provisioned out of band. A generation writer cannot grant itself
// deletion authority or change epoch. No data-decryption keys belong here.
type Trust struct {
	Domain      string            `json:"domain"`
	Repository  string            `json:"repository"`
	Epoch       uint64            `json:"epoch"`
	Writer      ed25519.PublicKey `json:"writer"`
	Maintenance ed25519.PublicKey `json:"maintenance"`
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (t Trust) valid() bool {
	return validID(t.Domain) && validID(t.Repository) && t.Epoch > 0 && len(t.Writer) == ed25519.PublicKeySize && len(t.Maintenance) == ed25519.PublicKeySize && !bytes.Equal(t.Writer, t.Maintenance)
}
func canonical(raw []byte, v any, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return ErrInvalid
	}
	b, err := json.Marshal(v)
	if err != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func closure(c Catalog) (map[string]Object, error) {
	if c.Format != Format || (c.KitFormat != KitFormat && c.KitFormat != TypedKitFormat) || !validID(c.Domain) || !validID(c.Repository) || c.Epoch == 0 || c.Sequence == 0 || c.SnapshotUnix <= 0 || c.Policy == 0 || (c.Parent != "" && !validID(c.Parent)) || (c.Sequence == 1 && c.Parent != "") || (c.Sequence > 1 && c.Parent == "") || len(c.Kits) == 0 || len(c.Kits) > MaxKits {
		return nil, ErrInvalid
	}
	refs := map[string]Object{}
	add := func(o Object) error {
		if !validID(o.ID) || o.Bytes < 1 || o.Bytes > MaxObject {
			return ErrInvalid
		}
		if old, ok := refs[o.ID]; ok && old != o {
			return ErrInvalid
		}
		refs[o.ID] = o
		if len(refs) > MaxObjects {
			return ErrInvalid
		}
		return nil
	}
	previous := ""
	for _, k := range c.Kits {
		key := k.File + "/" + k.Version
		if !validID(k.File) || !validID(k.Version) || key <= previous || len(k.Objects) == 0 || len(k.Objects) > MaxObjects || k.Root.Bytes > 128<<10 {
			return nil, ErrInvalid
		}
		previous = key
		if err := add(k.Root); err != nil {
			return nil, err
		}
		last := ""
		for _, o := range k.Objects {
			if o.ID <= last || o.ID == k.Root.ID {
				return nil, ErrInvalid
			}
			last = o.ID
			if err := add(o); err != nil {
				return nil, err
			}
		}
	}
	return refs, nil
}

// SignCatalog signs an already complete closure from a trusted consistent view.
// It does not itself establish that an arbitrary caller supplied all dependencies.
func SignCatalog(c Catalog, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	if _, err := closure(c); err != nil {
		return nil, err
	}
	c.Signature = nil
	unsigned, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Signature = ed25519.Sign(key, append([]byte(Format+"\x00catalog\x00"), unsigned...))
	b, err := json.Marshal(c)
	if len(b) > MaxCatalog {
		return nil, ErrInvalid
	}
	return b, err
}
func VerifyCatalog(raw []byte, t Trust) (Catalog, error) {
	var c Catalog
	if !t.valid() {
		return c, ErrInvalid
	}
	if err := canonical(raw, &c, MaxCatalog); err != nil {
		return c, err
	}
	if _, err := closure(c); err != nil {
		return c, err
	}
	if c.Domain != t.Domain || c.Repository != t.Repository || c.Epoch != t.Epoch {
		return c, ErrRollback
	}
	sig := c.Signature
	c.Signature = nil
	unsigned, _ := json.Marshal(c)
	c.Signature = sig
	if !ed25519.Verify(t.Writer, append([]byte(Format+"\x00catalog\x00"), unsigned...), sig) {
		return c, ErrInvalid
	}
	return c, nil
}

type Permit struct {
	Format     string             `json:"format"`
	Domain     string             `json:"domain"`
	Repository string             `json:"repository"`
	Epoch      uint64             `json:"epoch"`
	Revision   uint64             `json:"revision"`
	Operation  string             `json:"operation"`
	Retire     []string           `json:"retire"`
	Window     *PermitWindow      `json:"window,omitempty"`
	Coverage   *RetentionCoverage `json:"coverage,omitempty"`
	Signature  []byte             `json:"signature,omitempty"`
}

type PermitWindow struct {
	Node        string `json:"node"`
	StartUnix   int64  `json:"startUnix"`
	ExpiresUnix int64  `json:"expiresUnix"`
}

func validPermit(p Permit) bool {
	if !validID(p.Domain) || !validID(p.Repository) || p.Epoch == 0 || !validID(p.Operation) || len(p.Retire) > MaxGenerations {
		return false
	}
	if p.Format != RetentionPermitFormat && p.Coverage != nil {
		return false
	}
	switch p.Format {
	case Format:
		if p.Window != nil {
			return false
		}
	case PermitWindowFormat, RetentionPermitFormat:
		w := p.Window
		if w == nil || !validID(w.Node) || w.StartUnix <= 0 || w.ExpiresUnix > 1<<40 || w.ExpiresUnix <= w.StartUnix || w.ExpiresUnix-w.StartUnix > 86400 {
			return false
		}
	default:
		return false
	}
	last := ""
	for _, id := range p.Retire {
		if !validID(id) || id <= last {
			return false
		}
		last = id
	}
	return p.Format != RetentionPermitFormat || p.validRetentionCoverage()
}
func SignPermit(p Permit, key ed25519.PrivateKey) ([]byte, error) {
	if !validPermit(p) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	p.Signature = nil
	b, _ := json.Marshal(p)
	p.Signature = ed25519.Sign(key, append([]byte(p.Format+"\x00maintenance\x00"), b...))
	signed, e := json.Marshal(p)
	if e != nil || len(signed) > MaxPermit {
		return nil, ErrInvalid
	}
	return signed, nil
}

// VerifyPermit checks the separate maintenance authority. Execution additionally
// binds revision, operation, current references, pins and any command admission.
func VerifyPermit(raw []byte, t Trust) (Permit, error) { return verifyPermit(raw, t) }
func verifyPermit(raw []byte, t Trust) (Permit, error) {
	var p Permit
	if !t.valid() {
		return p, ErrInvalid
	}
	if err := canonical(raw, &p, MaxPermit); err != nil {
		return p, err
	}
	if p.Domain != t.Domain || p.Repository != t.Repository || p.Epoch != t.Epoch {
		return p, ErrInvalid
	}
	sig := p.Signature
	p.Signature = nil
	b, _ := json.Marshal(p)
	p.Signature = sig
	if !ed25519.Verify(t.Maintenance, append([]byte(p.Format+"\x00maintenance\x00"), b...), sig) || !validPermit(p) {
		return p, ErrInvalid
	}
	return p, nil
}
func sortedIDs[T any](refs map[string]T) []string {
	ids := make([]string, 0, len(refs))
	for id := range refs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
