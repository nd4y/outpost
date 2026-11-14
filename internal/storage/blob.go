package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/nd4y/outpost/internal/generation"
)

const BlobFormat = "outpost-external-blob-1"
const CompleteFormat = "outpost-external-complete-1"

// MissingPart identifies the exact immutable part absent during a content
// read. Callers can retry that part without discarding unrelated progress.
type MissingPart struct{ Part generation.Object }

func (e *MissingPart) Error() string { return "external part absent" }
func (e *MissingPart) Unwrap() error { return ErrNotFound }

type Blob struct {
	Format string              `json:"format"`
	Object generation.Object   `json:"object"`
	Parts  []generation.Object `json:"parts"`
}

func Decode(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrIntegrity
	}
	b, e := json.Marshal(out)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrIntegrity
	}
	return nil
}
func Describe(ref generation.Object, data []byte, limit int) (Blob, error) {
	blob := Blob{Format: BlobFormat, Object: ref, Parts: []generation.Object{}}
	if !ID(ref.ID) || ref.Bytes < 1 || ref.Bytes > MaxPhysical || len(data) != ref.Bytes || Hash(data) != ref.ID || limit < 64<<10 || limit > MaxPhysical {
		return blob, ErrIntegrity
	}
	for offset := 0; offset < len(data); offset += limit {
		end := offset + limit
		if end > len(data) {
			end = len(data)
		}
		part := data[offset:end]
		blob.Parts = append(blob.Parts, generation.Object{ID: Hash(part), Bytes: len(part)})
	}
	return blob, nil
}
func (b Blob) Validate(limit int) error {
	if b.Format != BlobFormat || !ID(b.Object.ID) || b.Object.Bytes < 1 || b.Object.Bytes > MaxPhysical || len(b.Parts) == 0 || len(b.Parts) > 128 {
		return ErrIntegrity
	}
	total := 0
	for _, part := range b.Parts {
		if !ID(part.ID) || part.Bytes < 1 || part.Bytes > limit {
			return ErrIntegrity
		}
		total += part.Bytes
	}
	if total != b.Object.Bytes {
		return ErrIntegrity
	}
	return nil
}
func (b *Backend) PutPart(ctx context.Context, part generation.Object, data []byte) error {
	if !ID(part.ID) || part.Bytes != len(data) || Hash(data) != part.ID {
		return ErrIntegrity
	}
	return b.Put(ctx, "part-"+part.ID, data)
}
func (b *Backend) ReadPart(ctx context.Context, part generation.Object) ([]byte, error) {
	if !ID(part.ID) || part.Bytes < 1 || part.Bytes > b.profile.MaxObjectBytes {
		return nil, ErrIntegrity
	}
	raw, e := b.Get(ctx, "part-"+part.ID)
	if errors.Is(e, ErrNotFound) {
		return nil, &MissingPart{Part: part}
	}
	if e != nil {
		return nil, e
	}
	if len(raw) != part.Bytes || Hash(raw) != part.ID {
		return nil, ErrIntegrity
	}
	return raw, nil
}

// SealBlob publishes its immutable descriptor only after every part is read back.
func (b *Backend) SealBlob(ctx context.Context, blob Blob) error {
	if _, e := b.ReadDescribed(ctx, blob); e != nil {
		return e
	}
	raw, e := json.Marshal(blob)
	if e != nil {
		return e
	}
	return b.Put(ctx, "blob-"+blob.Object.ID, raw)
}

// ReadDescribed always reads actual parts and verifies the reconstructed hash.
// It never accepts cached evidence, even when an uploader enables reuse.
func (b *Backend) ReadDescribed(ctx context.Context, blob Blob) ([]byte, error) {
	if e := blob.Validate(b.profile.MaxObjectBytes); e != nil {
		return nil, e
	}
	all := make([]byte, 0, blob.Object.Bytes)
	for _, p := range blob.Parts {
		raw, e := b.ReadPart(ctx, p)
		if e != nil {
			return nil, e
		}
		all = append(all, raw...)
	}
	if Hash(all) != blob.Object.ID {
		return nil, ErrIntegrity
	}
	return all, nil
}

// Descriptor validates the remote immutable map, not the underlying payload.
func (b *Backend) Descriptor(ctx context.Context, ref generation.Object) (Blob, error) {
	var blob Blob
	if !ID(ref.ID) || ref.Bytes < 1 || ref.Bytes > MaxPhysical {
		return blob, ErrIntegrity
	}
	raw, e := b.Get(ctx, "blob-"+ref.ID)
	if e != nil {
		return blob, e
	}
	if Decode(raw, &blob, b.profile.MaxObjectBytes) != nil || blob.Validate(b.profile.MaxObjectBytes) != nil || blob.Object != ref {
		return blob, ErrIntegrity
	}
	return blob, nil
}
func (b *Backend) ReadBlob(ctx context.Context, ref generation.Object) ([]byte, error) {
	blob, e := b.Descriptor(ctx, ref)
	if e != nil {
		return nil, e
	}
	return b.ReadDescribed(ctx, blob)
}
func (b *Backend) PutBlob(ctx context.Context, ref generation.Object, data []byte) error {
	blob, e := Describe(ref, data, b.profile.MaxObjectBytes)
	if e != nil {
		return e
	}
	offset := 0
	for _, p := range blob.Parts {
		if e = b.PutPart(ctx, p, data[offset:offset+p.Bytes]); e != nil {
			return e
		}
		offset += p.Bytes
	}
	return b.SealBlob(ctx, blob)
}

type Complete struct {
	Format     string            `json:"format"`
	Domain     string            `json:"domain"`
	Repository string            `json:"repository"`
	Epoch      uint64            `json:"epoch"`
	Generation string            `json:"generation"`
	Catalog    generation.Object `json:"catalog"`
}

func (b *Backend) Publish(ctx context.Context, raw []byte, trust generation.Trust) error {
	return b.PublishChecked(ctx, raw, trust, func(ctx context.Context, refs []generation.Object) error {
		for _, ref := range refs {
			if _, e := b.ReadBlob(ctx, ref); e != nil {
				return e
			}
		}
		return nil
	})
}

// PublishChecked authenticates the catalog and requires its entire closure to
// pass the caller's explicit verification policy before writing COMPLETE last.
// Ordinary Publish and all recovery reads use fresh payload verification.
func (b *Backend) PublishChecked(ctx context.Context, raw []byte, trust generation.Trust, verify func(context.Context, []generation.Object) error) error {
	catalog, e := generation.VerifyCatalog(raw, trust)
	if e != nil {
		return e
	}
	id := Hash(raw)
	if b.profile.Namespace != Hash([]byte(trust.Domain+"/"+trust.Repository)) {
		return ErrDenied
	}
	refs, e := generation.Dependencies(raw, trust)
	if e != nil {
		return e
	}
	if verify == nil {
		return ErrDenied
	}
	if e = verify(ctx, refs); e != nil {
		return e
	}
	ref := generation.Object{ID: id, Bytes: len(raw)}
	if e = b.PutBlob(ctx, ref, raw); e != nil {
		return e
	}
	marker := Complete{CompleteFormat, catalog.Domain, catalog.Repository, catalog.Epoch, id, ref}
	body, e := json.Marshal(marker)
	if e != nil {
		return e
	}
	// The immutable marker is the last write. No mutable latest pointer or listing
	// can turn a partial generation into a complete one.
	return b.Put(ctx, "complete-"+id, body)
}
func (b *Backend) Catalog(ctx context.Context, id string, trust generation.Trust) ([]byte, error) {
	if !ID(id) || b.profile.Namespace != Hash([]byte(trust.Domain+"/"+trust.Repository)) {
		return nil, ErrDenied
	}
	raw, e := b.Get(ctx, "complete-"+id)
	if e != nil {
		return nil, e
	}
	var marker Complete
	if Decode(raw, &marker, 4096) != nil || marker.Format != CompleteFormat || marker.Domain != trust.Domain || marker.Repository != trust.Repository || marker.Epoch != trust.Epoch || marker.Generation != id || marker.Catalog.ID != id {
		return nil, ErrIntegrity
	}
	raw, e = b.ReadBlob(ctx, marker.Catalog)
	if e != nil {
		return nil, e
	}
	if _, e = generation.VerifyCatalog(raw, trust); e != nil {
		return nil, e
	}
	return raw, nil
}

// Recover needs a selected generation ID and public trust, not a planner or any
// other worker. The destination retains its previous complete generation on error.
func (b *Backend) Recover(ctx context.Context, id string, target *generation.Replica) error {
	if target == nil {
		return ErrDenied
	}
	raw, e := b.Catalog(ctx, id, target.Trust())
	if e != nil {
		return e
	}
	_, e = target.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) { return b.ReadBlob(ctx, ref) })
	return e
}
func Missing(err error) bool { return errors.Is(err, ErrNotFound) }
