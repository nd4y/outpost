package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

// ReadbackOptions is local owner policy, not delegated planner authority.
// Zero MaxAgeSeconds always uses fresh reads. Store can be shared between
// operations; the scope includes protocol/profile, reader and generation trust.
type ReadbackOptions struct {
	MaxAgeSeconds int64
	Store         *statefile.Store
}
type blobEvidence struct {
	readback.Record
	Reused bool
}
type cloudAudit struct {
	backend      *storage.Backend
	cache        readback.Cache
	maxAge       int64
	owned        *statefile.Store
	blobs        map[string]storage.Blob
	keys         map[string]generation.Object
	baseKeys     map[string]generation.Object
	epochs       map[string]uint64
	proofs       map[string]blobEvidence
	skipChecked  map[string]bool
	verified     map[string]bool
	partialScope string
	afterPart    func() error // local fault hook, never configured by a remote peer
}

func validVerification(level string) bool {
	return level == "full-target-readback" || level == "cached-target-readback"
}
func (j *Journal) newAudit(ctx context.Context, b *storage.Backend) (*cloudAudit, error) {
	o := j.Readback
	if o.MaxAgeSeconds < 0 || o.MaxAgeSeconds > readback.MaxAgeSeconds {
		return nil, ErrDenied
	}
	if o.MaxAgeSeconds == 0 {
		return nil, nil
	}
	a := &cloudAudit{backend: b, maxAge: o.MaxAgeSeconds, blobs: map[string]storage.Blob{}, keys: map[string]generation.Object{}, proofs: map[string]blobEvidence{}, skipChecked: map[string]bool{}, verified: map[string]bool{}}
	a.baseKeys = map[string]generation.Object{}
	a.epochs = map[string]uint64{}
	if o.Store == nil {
		store, e := statefile.OpenAt(j.root, ".", readback.MaxPage, false)
		if e != nil {
			return nil, e
		}
		store.Admit = j.Admit
		a.owned, o.Store = store, store
	}
	scope, e := json.Marshal(struct {
		Protocol, Profile, Reader string
		Trust                     generation.Trust
	}{"outpost-cloud-readback-1", b.Profile().ID(), j.worker, j.authority.Generation})
	if e != nil {
		a.close()
		return nil, e
	}
	a.cache = readback.Cache{Store: o.Store, Scope: storage.Hash(scope)}
	a.partialScope = storage.Hash([]byte(a.cache.Scope + "/" + j.planID))
	for _, blob := range j.plan.Blobs {
		raw, e := json.Marshal(blob)
		if e != nil {
			a.close()
			return nil, e
		}
		ref := generation.Object{ID: storage.Hash(raw), Bytes: blob.Object.Bytes}
		a.blobs[blob.Object.ID], a.baseKeys[blob.Object.ID] = blob, ref
	}
	if e = a.initializeEpochs(ctx); e != nil {
		a.close()
		return nil, e
	}
	refs := make([]generation.Object, 0, len(a.keys))
	for _, ref := range a.keys {
		refs = append(refs, ref)
	}
	loaded, e := a.cache.Lookup(ctx, refs, time.Now(), a.maxAge)
	if e != nil {
		a.close()
		return nil, e
	}
	for id, ref := range a.keys {
		if r, ok := loaded[ref.ID]; ok {
			a.proofs[id] = blobEvidence{r, true}
		}
	}
	return a, nil
}
func (a *cloudAudit) close() {
	if a != nil && a.owned != nil {
		a.owned.Close()
	}
}
func (a *cloudAudit) invalidate(ctx context.Context, id string) error {
	return a.invalidateProgress(ctx, id, true)
}
func (a *cloudAudit) invalidateProgress(ctx context.Context, id string, force bool) error {
	_, hadProof := a.proofs[id]
	oldKey := a.keys[id]
	delete(a.proofs, id)
	delete(a.skipChecked, id)
	delete(a.verified, id)
	// Known loss must survive cancellation of the network attempt. This bounded
	// local-only write is joined before returning; failed persistence blocks work.
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if e := a.cache.InvalidateChecked(save, []generation.Object{oldKey}, time.Now(), func() error { return a.invalidateEpochLocked(id, force, hadProof) }); e != nil {
		return ErrConflict
	}
	return nil
}
func (a *cloudAudit) usable(id string) bool {
	r, ok := a.proofs[id]
	now := time.Now().Unix()
	return ok && r.Bytes == a.blobs[id].Object.Bytes && r.ObservedUnix > 0 && r.ObservedUnix <= now && now-r.ObservedUnix <= a.maxAge
}
func (a *cloudAudit) descriptor(ctx context.Context, id string) error {
	expected := a.blobs[id]
	got, e := a.backend.Descriptor(ctx, expected.Object)
	if e == nil {
		left, _ := json.Marshal(expected)
		right, _ := json.Marshal(got)
		if !bytes.Equal(left, right) {
			e = storage.ErrConflict
		}
	}
	if storage.Missing(e) || errors.Is(e, storage.ErrIntegrity) || errors.Is(e, storage.ErrConflict) {
		if x := a.invalidateProgress(ctx, id, !storage.Missing(e)); x != nil {
			return x
		}
	}
	return e
}

// reusable skips transfer work only after checking the exact remote map. The
// receipt still carries the original payload observation; this is not a fresh
// proof that a malicious target continues to retain those bytes.
func (a *cloudAudit) reusable(ctx context.Context, id string) (bool, error) {
	if !a.usable(id) {
		return false, nil
	}
	if a.skipChecked[id] {
		return true, nil
	}
	if e := a.checkEpochs(ctx, id); e != nil {
		return false, e
	}
	if e := a.descriptor(ctx, id); e != nil {
		if storage.Missing(e) {
			return false, nil
		}
		return false, e
	}
	a.skipChecked[id] = true
	return true, nil
}
func (a *cloudAudit) verify(ctx context.Context, id string, seal bool) error {
	blob, ok := a.blobs[id]
	if !ok {
		return ErrDenied
	}
	if e := a.checkEpochs(ctx, id); e != nil {
		return e
	}
	e := a.descriptor(ctx, id)
	absent := storage.Missing(e)
	if e != nil && !(seal && absent) {
		return e
	}
	if !a.usable(id) {
		progress, reused, readErr := a.readParts(ctx, id, !absent)
		if e = readErr; e != nil {
			if storage.Missing(e) || errors.Is(e, storage.ErrIntegrity) {
				if x := a.invalidate(ctx, id); x != nil {
					return x
				}
			}
			return e
		}
		// A descriptor is durable before its evidence can be reused.
		if absent {
			raw, e := json.Marshal(blob)
			if e != nil {
				return e
			}
			if e = a.backend.Put(ctx, "blob-"+id, raw); e != nil {
				return e
			}
		}
		r := readback.Record{Bytes: progress.Bytes, ObservedUnix: progress.ObservedUnix}
		if e = a.cache.RememberChecked(ctx, map[string]readback.Record{a.keys[id].ID: r}, time.Now(), func() error {
			if e := a.checkEpoch(id); e != nil {
				return e
			}
			return a.hashWindow(id).sealLocked(progress)
		}); e != nil {
			return e
		}
		a.proofs[id] = blobEvidence{r, reused}
	}
	a.verified[id] = true
	return nil
}
func (a *cloudAudit) evidence(ctx context.Context) (string, int64, error) {
	ids := make([]string, 0, len(a.blobs))
	for id := range a.blobs {
		ids = append(ids, id)
	}
	if e := a.checkEpochs(ctx, ids...); e != nil {
		return "", 0, e
	}
	oldest := time.Now().Unix()
	level := "full-target-readback"
	for id := range a.blobs {
		if !a.verified[id] || !a.usable(id) {
			return "", 0, storage.ErrUnavailable
		}
		r := a.proofs[id]
		oldest = min(oldest, r.ObservedUnix)
		if r.Reused {
			level = "cached-target-readback"
		}
	}
	return level, oldest, nil
}
func (a *cloudAudit) publish(ctx context.Context, raw []byte, trust generation.Trust) error {
	for id := range a.blobs {
		if e := a.verify(ctx, id, true); e != nil {
			return e
		}
	}
	return a.backend.PublishChecked(ctx, raw, trust, func(ctx context.Context, refs []generation.Object) error {
		if len(refs) != len(a.blobs) {
			return ErrDenied
		}
		for _, ref := range refs {
			if blob, ok := a.blobs[ref.ID]; !ok || blob.Object != ref {
				return ErrDenied
			}
			if e := a.verify(ctx, ref.ID, false); e != nil {
				return e
			}
		}
		_, _, e := a.evidence(ctx)
		return e
	})
}
