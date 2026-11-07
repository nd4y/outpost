package generation

import (
	"context"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/filekit"
)

type RecoverySelection struct {
	Versions  []string `json:"versions,omitempty"`
	Directory string   `json:"directory,omitempty"`
}
type RecoveryReceipt struct {
	Generation      string                  `json:"generation"`
	Epoch           uint64                  `json:"epoch"`
	Sequence        uint64                  `json:"sequence"`
	CheckpointMatch bool                    `json:"checkpointMatch"`
	Restored        filekit.RecoverySummary `json:"restored"`
}

// RecoverMaterialized reads a stopped/materialized replica using only its
// immutable catalogs/objects and an independently supplied expected checkpoint.
// No state index, queue, control service, source or other node is required.
// A live GC can make reads fail; operators should recover from a retained view.
func RecoverMaterialized(ctx context.Context, dir, expected string, trust Trust, owner filekit.Owner, selection RecoverySelection, dest string) (RecoveryReceipt, error) {
	var result RecoveryReceipt
	if !validID(expected) || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || owner.Domain != trust.Domain {
		return result, ErrInvalid
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return result, e
	}
	defer r.Close()
	raw, e := read(r, "catalogs/"+expected, MaxCatalog)
	if e != nil {
		return result, e
	}
	return RecoverCatalog(ctx, expected, raw, trust, owner, selection, func(ctx context.Context, o Object) ([]byte, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if !validID(o.ID) || o.Bytes < 1 || o.Bytes > MaxObject {
			return nil, ErrInvalid
		}
		return read(r, "objects/"+o.ID, MaxObject)
	}, dest)
}

// RecoverCatalog also accepts an authenticated external-storage object reader.
// Every read is restricted to the selected catalog closure and checked again.
func recoveryMaterial(ctx context.Context, expected string, raw []byte, trust Trust, owner filekit.Owner, selection RecoverySelection, fetch func(context.Context, Object) ([]byte, error)) (Catalog, []filekit.RecoveryKit, filekit.ObjectReader, error) {
	if !validID(expected) || Hash(raw) != expected || fetch == nil || owner.Domain != trust.Domain {
		return Catalog{}, nil, nil, ErrInvalid
	}
	c, e := VerifyCatalog(raw, trust)
	if e != nil {
		return Catalog{}, nil, nil, e
	}
	wanted := map[string]bool{}
	if len(selection.Versions) > MaxKits {
		return Catalog{}, nil, nil, ErrInvalid
	}
	for _, v := range selection.Versions {
		if !validID(v) || wanted[v] {
			return Catalog{}, nil, nil, ErrInvalid
		}
		wanted[v] = true
	}
	refs := map[string]Object{}
	var selected []Kit
	for _, k := range c.Kits {
		if len(wanted) > 0 && !wanted[k.Version] {
			continue
		}
		selected = append(selected, k)
		refs[k.Root.ID] = k.Root
		for _, o := range k.Objects {
			refs[o.ID] = o
		}
	}
	if len(selected) == 0 || (len(wanted) > 0 && len(selected) != len(wanted)) {
		return Catalog{}, nil, nil, ErrIncomplete
	}
	get := func(ctx context.Context, o Object) ([]byte, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if refs[o.ID] != o {
			return nil, ErrInvalid
		}
		b, e := fetch(ctx, o)
		if e != nil {
			return nil, e
		}
		if len(b) != o.Bytes || Hash(b) != o.ID {
			return nil, ErrInvalid
		}
		return b, nil
	}
	var kits []filekit.RecoveryKit
	rootBytes := 0
	for _, k := range selected {
		rootBytes += k.Root.Bytes
		if rootBytes > filekit.MaxDescriptor {
			return Catalog{}, nil, nil, ErrInvalid
		}
		b, e := get(ctx, k.Root)
		if e != nil {
			return Catalog{}, nil, nil, e
		}
		kits = append(kits, filekit.RecoveryKit{Version: k.Version, Root: b})
	}
	readObject := func(ctx context.Context, o filekit.Object) ([]byte, error) {
		return get(ctx, Object{ID: o.ID, Bytes: o.Bytes})
	}
	return c, kits, readObject, nil
}

func RecoverCatalog(ctx context.Context, expected string, raw []byte, trust Trust, owner filekit.Owner, selection RecoverySelection, fetch func(context.Context, Object) ([]byte, error), dest string) (RecoveryReceipt, error) {
	var result RecoveryReceipt
	c, kits, readObject, e := recoveryMaterial(ctx, expected, raw, trust, owner, selection, fetch)
	if e != nil {
		return result, e
	}
	var restored filekit.RecoverySummary
	if selection.Directory == "" {
		restored, e = filekit.RecoverSet(ctx, owner, kits, readObject, dest)
	} else {
		restored, e = filekit.RecoverDirectory(ctx, owner, kits, readObject, selection.Directory, dest)
	}
	if e != nil {
		return result, e
	}
	return RecoveryReceipt{Generation: expected, Epoch: c.Epoch, Sequence: c.Sequence, CheckpointMatch: true, Restored: restored}, nil
}

// PlanRecoveryCatalog checks authenticated selection metadata before the
// trusted executor reserves output space. Payload is not decrypted here.
func PlanRecoveryCatalog(ctx context.Context, expected string, raw []byte, trust Trust, owner filekit.Owner, selection RecoverySelection, fetch func(context.Context, Object) ([]byte, error)) (filekit.RecoverySummary, error) {
	_, kits, readObject, e := recoveryMaterial(ctx, expected, raw, trust, owner, selection, fetch)
	if e != nil {
		return filekit.RecoverySummary{}, e
	}
	return filekit.PlanRecovery(ctx, owner, kits, readObject, selection.Directory)
}

func RecoverCatalogAt(ctx context.Context, expected string, raw []byte, trust Trust, owner filekit.Owner, selection RecoverySelection, fetch func(context.Context, Object) ([]byte, error), parent *os.Root, name string) (RecoveryReceipt, error) {
	var result RecoveryReceipt
	c, kits, readObject, e := recoveryMaterial(ctx, expected, raw, trust, owner, selection, fetch)
	if e != nil {
		return result, e
	}
	restored, e := filekit.RecoverSetAt(ctx, owner, kits, readObject, selection.Directory, parent, name)
	if e != nil {
		return result, e
	}
	return RecoveryReceipt{Generation: expected, Epoch: c.Epoch, Sequence: c.Sequence, CheckpointMatch: true, Restored: restored}, nil
}
