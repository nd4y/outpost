package generation

import (
	"context"
	"crypto/ed25519"
	"os"
	"syscall"

	"github.com/nd4y/outpost/internal/localfs"
)

const RecordedDamageFormat = "outpost-replica-damage-status-1"

type RecordedDamageVersion struct {
	File    string `json:"file"`
	Version string `json:"version"`
}

type RecordedDamage struct {
	Format     string                  `json:"format"`
	Generation string                  `json:"generation"`
	State      string                  `json:"state"`
	Affected   []RecordedDamageVersion `json:"affected"`
}

// ReadRecordedDamageAt reads one retained generation's damage ledger. It
// neither opens payloads nor creates a lock or updates diagnosis and publication.
func ReadRecordedDamageAt(ctx context.Context, root *os.Root, path string, trust Trust, key ed25519.PrivateKey, id string) (RecordedDamage, error) {
	var out RecordedDamage
	if !validID(id) || !trust.valid() || len(key) != ed25519.PrivateKeySize {
		return out, ErrInvalid
	}
	dir, err := localfs.Directory(root, path, false)
	if err != nil {
		return out, err
	}
	defer dir.Close()
	r := &Replica{root: dir, trust: trust}
	r.setIndexKey(key)
	err = r.withLock(ctx, os.O_RDONLY, syscall.LOCK_SH, func() error {
		s, err := r.load()
		if err != nil {
			return err
		}
		item, ok := s.Generations[id]
		if !ok {
			return ErrInvalid
		}
		out = RecordedDamage{Format: RecordedDamageFormat, Generation: id, State: "CATALOG_UNAVAILABLE"}
		if _, unavailable := s.CatalogDamage[id]; unavailable {
			return ctx.Err()
		}
		catalog, _, err := r.catalogEntry(id, item, true)
		if err != nil {
			return ctx.Err()
		}
		out.State = "NO_RECORDED_DAMAGE"
		if item.Damaged {
			out.State = "RECHECK_PENDING"
		}
		out.Affected = []RecordedDamageVersion{}
		for _, kit := range catalog.Kits {
			if err := ctx.Err(); err != nil {
				return err
			}
			if damagedKit(kit, s.Damage) {
				out.Affected = append(out.Affected, RecordedDamageVersion{File: kit.File, Version: kit.Version})
			}
		}
		if len(out.Affected) != 0 {
			out.State = "DAMAGE_RECORDED"
		}
		return ctx.Err()
	})
	if err != nil {
		return RecordedDamage{}, err
	}
	return out, nil
}

func damagedKit(kit Kit, damage map[string]DamageRecord) bool {
	if _, ok := damage[kit.Root.ID]; ok {
		return true
	}
	for _, object := range kit.Objects {
		if _, ok := damage[object.ID]; ok {
			return true
		}
	}
	return false
}
