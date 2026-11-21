package upload

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/storage"
)

const evidenceEpochFormat = "outpost-cloud-evidence-epoch-1"

type evidenceEpoch struct {
	Format string `json:"format"`
	Scope  string `json:"scope"`
	Epoch  uint64 `json:"epoch"`
}

func (a *cloudAudit) epochScope(id string) string {
	return storage.Hash([]byte(a.cache.Scope + "/" + a.baseKeys[id].ID))
}

// Caller holds the shared store lock. Missing means the original epoch; files
// are created only for observed loss, never automatically garbage-collected.
func (a *cloudAudit) loadEpoch(id string) (uint64, error) {
	scope := a.epochScope(id)
	raw, e := a.cache.Store.Read("readback-epoch-" + scope + ".json")
	if errors.Is(e, os.ErrNotExist) {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	var s evidenceEpoch
	if storage.Decode(raw, &s, 1024) != nil || s.Format != evidenceEpochFormat || s.Scope != scope || s.Epoch == 0 {
		return 0, readback.ErrInvalid
	}
	return s.Epoch, nil
}
func (a *cloudAudit) proofKey(id string, epoch uint64) generation.Object {
	key := a.baseKeys[id]
	if epoch != 0 {
		key.ID = storage.Hash([]byte(key.ID + "/" + strconv.FormatUint(epoch, 10)))
	}
	return key
}
func (a *cloudAudit) initializeEpochs(ctx context.Context) error {
	return a.cache.Store.WithLock(ctx, func() error {
		for id := range a.blobs {
			if e := ctx.Err(); e != nil {
				return e
			}
			epoch, e := a.loadEpoch(id)
			if e != nil {
				return e
			}
			a.epochs[id] = epoch
			a.keys[id] = a.proofKey(id, epoch)
		}
		return nil
	})
}
func (a *cloudAudit) checkEpoch(id string) error {
	epoch, e := a.loadEpoch(id)
	if e != nil {
		return e
	}
	if epoch != a.epochs[id] {
		return storage.ErrUnavailable
	}
	return nil
}
func (a *cloudAudit) checkEpochs(ctx context.Context, ids ...string) error {
	return a.cache.Store.WithLock(ctx, func() error {
		for _, id := range ids {
			if e := ctx.Err(); e != nil {
				return e
			}
			if e := a.checkEpoch(id); e != nil {
				return e
			}
		}
		return nil
	})
}
func (a *cloudAudit) invalidateEpochLocked(id string, force, hadProof bool) error {
	if !force && !hadProof {
		p, e := a.hashWindow(id).load()
		if e != nil {
			return e
		}
		if !p.Sealed && !p.DescriptorSeen {
			return nil
		}
	}
	epoch, e := a.loadEpoch(id)
	if e != nil {
		return e
	}
	if epoch == ^uint64(0) {
		return storage.ErrCapacity
	}
	epoch++
	scope := a.epochScope(id)
	raw, e := json.Marshal(evidenceEpoch{evidenceEpochFormat, scope, epoch})
	if e != nil {
		return e
	}
	// The new key fences all operations even if a crash interrupts removal of
	// the old advisory record. Stale writers cannot certify into either epoch.
	if e = a.cache.Store.Write("readback-epoch-"+scope+".json", raw); e != nil {
		return e
	}
	a.epochs[id] = epoch
	a.keys[id] = a.proofKey(id, epoch)
	return nil
}
