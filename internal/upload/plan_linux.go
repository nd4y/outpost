// Package upload runs cached signed upload plans without a live coordinator.
package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const Format = "outpost-external-plan-1"
const MaxPlan = 16 << 20
const MaxTasks = 32768

var ErrDenied = errors.New("upload plan or worker denied")
var ErrConflict = errors.New("upload journal binding conflict")

type Worker struct {
	ID        string            `json:"id"`
	Class     string            `json:"class"`
	PublicKey ed25519.PublicKey `json:"publicKey"`
}

func Identity(key ed25519.PublicKey) string {
	if len(key) != ed25519.PublicKeySize {
		return ""
	}
	raw, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		return ""
	}
	return storage.Hash(raw)
}

type Plan struct {
	Format         string          `json:"format"`
	Operation      string          `json:"operationId"`
	Generation     string          `json:"generation"`
	Profile        storage.Profile `json:"profile"`
	AllowExternal  bool            `json:"allowExternal"`
	AllowedClasses []string        `json:"allowedClasses"`
	Workers        []Worker        `json:"workers"`
	StartMillis    int64           `json:"startMillis"`
	ExpiresUnix    int64           `json:"expiresUnix"`
	SlotMillis     int64           `json:"slotMillis"`
	Catalog        json.RawMessage `json:"catalog"`
	Blobs          []storage.Blob  `json:"blobs"`
	Delegation     json.RawMessage `json:"delegation,omitempty"`
	Signature      []byte          `json:"signature,omitempty"`
}
type Authority struct {
	Generation generation.Trust
	Planner    ed25519.PublicKey
}
type Task struct {
	Part   generation.Object
	Object generation.Object
	Offset int
}

func (p Plan) policy() error {
	if p.ExpiresUnix > (int64(^uint64(0)>>1)-300000)/1000 {
		return ErrDenied
	}
	if (p.Format != Format && p.Format != DerivedFormat) || p.Format == Format && len(p.Delegation) > 0 || p.Format == DerivedFormat && (len(p.Delegation) == 0 || len(p.Signature) > 0) || !storage.ID(p.Operation) || !p.AllowExternal || p.Profile.Validate() != nil || len(p.Workers) < 1 || len(p.Workers) > 32 || len(p.AllowedClasses) < 1 || len(p.AllowedClasses) > 2 || p.StartMillis < 1 || p.ExpiresUnix <= p.StartMillis/1000 || p.SlotMillis < 500 || p.SlotMillis > 300000 {
		return ErrDenied
	}
	allowed := map[string]bool{}
	for _, c := range p.AllowedClasses {
		if c != "trusted" && c != "untrusted" || allowed[c] {
			return ErrDenied
		}
		allowed[c] = true
	}
	seen := map[string]bool{}
	for _, w := range p.Workers {
		if !storage.ID(w.ID) || Identity(w.PublicKey) != w.ID || seen[w.ID] || !allowed[w.Class] || w.Class == "untrusted" && p.Profile.CredentialScope != "namespace" {
			return ErrDenied
		}
		seen[w.ID] = true
	}
	return nil
}
func (p Plan) Tasks() ([]Task, error) {
	tasks := []Task{}
	seen := map[string]generation.Object{}
	for _, blob := range p.Blobs {
		if e := blob.Validate(p.Profile.MaxObjectBytes); e != nil {
			return nil, e
		}
		offset := 0
		for _, part := range blob.Parts {
			known, ok := seen[part.ID]
			if ok && known != part {
				return nil, ErrDenied
			}
			if !ok {
				tasks = append(tasks, Task{part, blob.Object, offset})
				seen[part.ID] = part
			}
			offset += part.Bytes
			if len(tasks) > MaxTasks {
				return nil, ErrDenied
			}
		}
	}
	return tasks, nil
}
func (p Plan) validate(a Authority) error {
	if p.policy() != nil || len(a.Planner) != ed25519.PublicKeySize || !storage.ID(p.Generation) || storage.Hash(p.Catalog) != p.Generation || p.Profile.Namespace != storage.Hash([]byte(a.Generation.Domain+"/"+a.Generation.Repository)) {
		return ErrDenied
	}
	refs, e := generation.Dependencies(p.Catalog, a.Generation)
	if e != nil {
		return e
	}
	if len(refs) != len(p.Blobs) {
		return ErrDenied
	}
	for i, ref := range refs {
		if p.Blobs[i].Object != ref {
			return ErrDenied
		}
	}
	_, e = p.Tasks()
	return e
}
func Build(ctx context.Context, source *generation.Replica, id string, p Plan, planner ed25519.PrivateKey) ([]byte, error) {
	// Policy is checked before reading or describing source payloads.
	if source == nil || p.Format != Format || p.policy() != nil || len(planner) != ed25519.PrivateKeySize {
		return nil, ErrDenied
	}
	if p.Profile.Namespace != storage.Hash([]byte(source.Trust().Domain+"/"+source.Trust().Repository)) {
		return nil, ErrDenied
	}
	p.Generation = id
	p.Signature = nil
	raw, e := source.Catalog(ctx, id)
	if e != nil {
		return nil, e
	}
	p.Catalog = raw
	refs, e := generation.Dependencies(raw, source.Trust())
	if e != nil {
		return nil, e
	}
	if e = preflightPlan(p, refs); e != nil {
		return nil, e
	}
	p.Blobs = make([]storage.Blob, 0, len(refs))
	for _, ref := range refs {
		blob, e := describeReference(ctx, source, id, ref, p.Profile.MaxObjectBytes)
		if e != nil {
			return nil, e
		}
		p.Blobs = append(p.Blobs, blob)
	}
	a := Authority{source.Trust(), planner.Public().(ed25519.PublicKey)}
	if e = p.validate(a); e != nil {
		return nil, e
	}
	unsigned, e := json.Marshal(p)
	if e != nil || len(unsigned) > MaxPlan-128 {
		return nil, ErrDenied
	}
	p.Signature = ed25519.Sign(planner, append([]byte(Format+"\x00"), unsigned...))
	return json.Marshal(p)
}

// An unsplit immutable object already has its exact digest and length in the
// authenticated catalog. Planning is not a fresh source integrity observation.
// Multipart maps still require actual bytes to determine each part digest.
func describeReference(ctx context.Context, source *generation.Replica, id string, ref generation.Object, limit int) (storage.Blob, error) {
	if e := ctx.Err(); e != nil {
		return storage.Blob{}, e
	}
	if ref.Bytes <= limit {
		return storage.Blob{Format: storage.BlobFormat, Object: ref, Parts: []generation.Object{ref}}, nil
	}
	data, e := source.ReadObject(ctx, id, ref)
	if e != nil {
		return storage.Blob{}, e
	}
	return storage.Describe(ref, data, limit)
}
func Verify(raw []byte, a Authority) (Plan, error) {
	var p Plan
	if storage.Decode(raw, &p, MaxPlan) != nil || len(a.Planner) != ed25519.PublicKeySize {
		return p, ErrDenied
	}
	if p.Format == DerivedFormat {
		return p, verifyDerived(raw, p, a)
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return p, ErrDenied
	}
	signature := append([]byte(nil), p.Signature...)
	p.Signature = nil
	unsigned, e := json.Marshal(p)
	p.Signature = signature
	if e != nil || !ed25519.Verify(a.Planner, append([]byte(Format+"\x00"), unsigned...), signature) {
		return p, ErrDenied
	}
	if e = p.validate(a); e != nil {
		return p, e
	}
	return p, nil
}
func (p Plan) worker(id string) (Worker, bool) {
	for _, w := range p.Workers {
		if w.ID == id {
			return w, true
		}
	}
	return Worker{}, false
}
func (p Plan) round(now time.Time) (int64, time.Time) {
	round := (now.UnixMilli() - p.StartMillis) / p.SlotMillis
	if round < 0 {
		round = 0
	}
	return round, time.UnixMilli(p.StartMillis + (round+1)*p.SlotMillis)
}
func (p Plan) owner(object string, round int64) string {
	workers := append([]Worker(nil), p.Workers...)
	sort.Slice(workers, func(i, j int) bool {
		return storage.Hash([]byte(p.Operation+"/"+object+"/"+workers[i].ID)) > storage.Hash([]byte(p.Operation+"/"+object+"/"+workers[j].ID))
	})
	return workers[int(round%int64(len(workers)))].ID
}
func sameTrust(a, b generation.Trust) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
