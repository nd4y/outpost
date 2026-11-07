package upload

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const hashProgressFormat = "outpost-cloud-hash-progress-1"

// This is private verification scratch, never a backup or transferable receipt.
// The standard SHA256 state can contain a short ciphertext suffix. It stays on
// the admitted volume and is never logged or sent to another executor.
type hashProgress struct {
	Format         string `json:"format"`
	Scope          string `json:"scope"`
	Epoch          uint64 `json:"epoch"`
	Next           int    `json:"next"`
	Bytes          int    `json:"bytes"`
	ObservedUnix   int64  `json:"observedUnix"`
	State          []byte `json:"state"`
	StateHash      string `json:"stateHash"`
	Sealed         bool   `json:"sealed"`
	DescriptorSeen bool   `json:"descriptorSeen"`
}
type hashWindow struct {
	store  *statefile.Store
	scope  string
	blob   storage.Blob
	maxAge int64
}

func marshalHash(h hash.Hash) ([]byte, error) {
	m, ok := h.(encoding.BinaryMarshaler)
	if !ok {
		return nil, storage.ErrUnsupported
	}
	raw, e := m.MarshalBinary()
	if e != nil {
		return nil, e
	}
	if len(raw) == 0 || len(raw) > 512 {
		return nil, storage.ErrUnsupported
	}
	return raw, nil
}
func restoreHash(raw []byte) (hash.Hash, error) {
	h := sha256.New()
	u, ok := h.(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, storage.ErrUnsupported
	}
	if e := u.UnmarshalBinary(raw); e != nil {
		return nil, readback.ErrInvalid
	}
	return h, nil
}
func (w hashWindow) name() string { return "readback-hash-" + w.scope + ".json" }
func (w hashWindow) empty(epoch uint64) (hashProgress, error) {
	raw, e := marshalHash(sha256.New())
	return hashProgress{Format: hashProgressFormat, Scope: w.scope, Epoch: epoch, State: raw, StateHash: storage.Hash(raw)}, e
}
func (w hashWindow) load() (hashProgress, error) {
	p, e := w.empty(1)
	if e != nil {
		return p, e
	}
	raw, e := w.store.Read(w.name())
	if errors.Is(e, os.ErrNotExist) {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	if storage.Decode(raw, &p, 4096) != nil || p.Format != hashProgressFormat || p.Scope != w.scope || p.Epoch == 0 || p.Next < 0 || p.Next > len(w.blob.Parts) || len(p.State) == 0 || len(p.State) > 512 || storage.Hash(p.State) != p.StateHash || p.ObservedUnix < 0 || p.ObservedUnix > time.Now().Unix() || p.Sealed && p.Next != len(w.blob.Parts) {
		return p, readback.ErrInvalid
	}
	n := 0
	for _, part := range w.blob.Parts[:p.Next] {
		n += part.Bytes
	}
	if n != p.Bytes || p.Next == 0 && p.ObservedUnix != 0 || p.Next > 0 && p.ObservedUnix == 0 {
		return p, readback.ErrInvalid
	}
	if p.Sealed && !p.DescriptorSeen {
		return p, readback.ErrInvalid
	}
	h, e := restoreHash(p.State)
	if e != nil {
		return p, e
	}
	if p.Next == 0 {
		empty, e := w.empty(p.Epoch)
		if e != nil {
			return p, e
		}
		if p.StateHash != empty.StateHash {
			return p, readback.ErrInvalid
		}
	}
	if p.Next == len(w.blob.Parts) && hex.EncodeToString(h.Sum(nil)) != w.blob.Object.ID {
		return p, storage.ErrIntegrity
	}
	return p, nil
}
func (w hashWindow) write(p hashProgress) error {
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	return w.store.Write(w.name(), raw)
}
func (w hashWindow) expired(p hashProgress) bool {
	return p.Next > 0 && time.Now().Unix()-p.ObservedUnix > w.maxAge
}

// Caller holds Store.WithLock. Absence during initial upload is expected;
// previously sealed evidence or an observed bad part always fences old writers.
func (w hashWindow) resetLocked(force bool) error {
	p, e := w.load()
	if e != nil {
		return e
	}
	if !force && !p.Sealed {
		return nil
	}
	if p.Epoch == ^uint64(0) {
		return storage.ErrCapacity
	}
	p, e = w.empty(p.Epoch + 1)
	if e != nil {
		return e
	}
	return w.write(p)
}
func (w hashWindow) start(ctx context.Context, descriptorPresent bool) (hashProgress, error) {
	var p hashProgress
	e := w.store.WithLock(ctx, func() error {
		var e error
		p, e = w.load()
		if e != nil {
			return e
		}
		// Reaching this path means the whole-object evidence is unavailable.
		// Never resurrect a sealed prefix whose evidence was invalidated.
		if w.expired(p) || p.Sealed {
			if p.Epoch == ^uint64(0) {
				return storage.ErrCapacity
			}
			p, e = w.empty(p.Epoch + 1)
			if e != nil {
				return e
			}
			p.DescriptorSeen = descriptorPresent
			return w.write(p)
		}
		if descriptorPresent && !p.DescriptorSeen {
			p.DescriptorSeen = true
			return w.write(p)
		}
		return nil
	})
	return p, e
}
func (w hashWindow) commit(ctx context.Context, candidate hashProgress) (hashProgress, error) {
	result := candidate
	e := w.store.WithLock(ctx, func() error {
		old, e := w.load()
		if e != nil {
			return e
		}
		if old.Epoch != candidate.Epoch {
			return ErrConflict
		}
		if old.Next > candidate.Next {
			result = old
			return nil
		}
		if old.Next == candidate.Next && old.StateHash != candidate.StateHash {
			return ErrConflict
		}
		if old.ObservedUnix > 0 {
			result.ObservedUnix = min(result.ObservedUnix, old.ObservedUnix)
		}
		result.Sealed = result.Sealed || old.Sealed
		result.DescriptorSeen = result.DescriptorSeen || old.DescriptorSeen
		return w.write(result)
	})
	return result, e
}
func (w hashWindow) sealLocked(expected hashProgress) error {
	p, e := w.load()
	if e != nil {
		return e
	}
	if p.Epoch != expected.Epoch || p.StateHash != expected.StateHash || p.ObservedUnix != expected.ObservedUnix {
		return ErrConflict
	}
	if p.Next != len(w.blob.Parts) || w.expired(p) {
		return storage.ErrUnavailable
	}
	p.Sealed = true
	p.DescriptorSeen = true
	return w.write(p)
}
func (a *cloudAudit) hashWindow(id string) hashWindow {
	return hashWindow{a.cache.Store, storage.Hash([]byte(a.partialScope + "/" + a.keys[id].ID)), a.blobs[id], a.maxAge}
}
func (a *cloudAudit) readParts(ctx context.Context, id string, descriptorPresent bool) (hashProgress, bool, error) {
	w := a.hashWindow(id)
	p, e := w.start(ctx, descriptorPresent)
	if e != nil {
		return hashProgress{}, false, e
	}
	reused := p.Next > 0
	for p.Next < len(w.blob.Parts) {
		if e = ctx.Err(); e != nil {
			return hashProgress{}, reused, e
		}
		observed := time.Now().Unix()
		data, e := a.backend.ReadPart(ctx, w.blob.Parts[p.Next])
		if e != nil {
			return hashProgress{}, reused, e
		}
		h, e := restoreHash(p.State)
		if e != nil {
			return hashProgress{}, reused, e
		}
		if _, e = h.Write(data); e != nil {
			return hashProgress{}, reused, e
		}
		p.State, e = marshalHash(h)
		if e != nil {
			return hashProgress{}, reused, e
		}
		p.StateHash = storage.Hash(p.State)
		p.Next++
		p.Bytes += len(data)
		if p.ObservedUnix == 0 {
			p.ObservedUnix = observed
		}
		if p.Next == len(w.blob.Parts) && hex.EncodeToString(h.Sum(nil)) != w.blob.Object.ID {
			return hashProgress{}, reused, storage.ErrIntegrity
		}
		next, e := w.commit(ctx, p)
		if e != nil {
			return hashProgress{}, reused, e
		}
		if next.Next > p.Next {
			reused = true
		}
		p = next
		if a.afterPart != nil {
			if e = a.afterPart(); e != nil {
				return hashProgress{}, reused, e
			}
		}
	}
	if w.expired(p) {
		return hashProgress{}, reused, storage.ErrUnavailable
	}
	return p, reused, nil
}
