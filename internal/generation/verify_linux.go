package generation

import (
	"context"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/localfs"
)

const ContentVerificationFormat = "outpost-content-verification-1"

type VersionVerification struct {
	File         string                `json:"file"`
	Version      string                `json:"version"`
	State        string                `json:"state"`
	VerifiedUnix int64                 `json:"verifiedUnix"`
	Content      *filekit.Verification `json:"content,omitempty"`
}
type ContentVerification struct {
	Format          string                `json:"format"`
	Generation      string                `json:"generation"`
	Epoch           uint64                `json:"epoch"`
	Sequence        uint64                `json:"sequence"`
	WholeGeneration bool                  `json:"wholeGeneration"`
	Complete        bool                  `json:"complete"`
	StartedUnix     int64                 `json:"startedUnix"`
	FinishedUnix    int64                 `json:"finishedUnix"`
	Versions        []VersionVerification `json:"versions"`
}

// VerifyMaterialized uses only immutable catalog/object files. It neither
// trusts nor rewrites the replica publication index. Supply a retained view;
// a concurrently removed object makes that version UNREADABLE, never verified.
func VerifyMaterialized(ctx context.Context, dir, expected string, trust Trust, owner filekit.Owner, versions []string) (ContentVerification, error) {
	var result ContentVerification
	if !validID(expected) || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || owner.Domain != trust.Domain {
		return result, ErrInvalid
	}
	r, e := localfs.OpenRoot(dir)
	if e != nil {
		return result, e
	}
	defer r.Close()
	raw, e := read(r, "catalogs/"+expected, MaxCatalog)
	if e != nil {
		return result, e
	}
	return VerifyCatalogContents(ctx, expected, raw, trust, owner, versions, func(ctx context.Context, o Object) ([]byte, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		return read(r, "objects/"+o.ID, MaxObject)
	})
}

// VerifyCatalogContents reports each independently selected version, including
// multiple retained versions of one file. UNREADABLE includes missing data,
// corruption or a wrong key; it does not diagnose a storage device. Cancellation
// leaves untouched versions NOT_VERIFIED. Any incomplete report returns an error.
func VerifyCatalogContents(ctx context.Context, expected string, raw []byte, trust Trust, owner filekit.Owner, versions []string, fetch func(context.Context, Object) ([]byte, error)) (ContentVerification, error) {
	var result ContentVerification
	if !validID(expected) || Hash(raw) != expected || fetch == nil || owner.Domain != trust.Domain || len(versions) > MaxKits {
		return result, ErrInvalid
	}
	c, e := VerifyCatalog(raw, trust)
	if e != nil {
		return result, e
	}
	wanted := map[string]bool{}
	for _, v := range versions {
		if !validID(v) || wanted[v] {
			return result, ErrInvalid
		}
		wanted[v] = true
	}
	var selected []Kit
	for _, k := range c.Kits {
		if len(wanted) == 0 || wanted[k.Version] {
			selected = append(selected, k)
		}
	}
	if len(selected) == 0 || len(wanted) > 0 && len(selected) != len(wanted) {
		return result, ErrInvalid
	}
	result = ContentVerification{Format: ContentVerificationFormat, Generation: expected, Epoch: c.Epoch, Sequence: c.Sequence, WholeGeneration: len(selected) == len(c.Kits), StartedUnix: time.Now().Unix(), Versions: make([]VersionVerification, len(selected))}
	for i, k := range selected {
		result.Versions[i] = VersionVerification{File: k.File, Version: k.Version, State: "NOT_VERIFIED"}
	}
	finish := func(err error) (ContentVerification, error) {
		result.FinishedUnix = time.Now().Unix()
		if result.FinishedUnix < result.StartedUnix {
			result.Complete = false
			return result, ErrInvalid
		}
		for _, v := range result.Versions {
			if v.VerifiedUnix > result.FinishedUnix {
				result.Complete = false
				return result, ErrInvalid
			}
		}
		return result, err
	}
	failed := false
	for i, k := range selected {
		if e = ctx.Err(); e != nil {
			return finish(e)
		}
		started := time.Now().Unix()
		if started < result.StartedUnix {
			return finish(ErrInvalid)
		}
		refs := map[string]Object{k.Root.ID: k.Root}
		for _, o := range k.Objects {
			refs[o.ID] = o
		}
		get := func(ctx context.Context, o Object) ([]byte, error) {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			want, exists := refs[o.ID]
			if !exists || want != o {
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
		var verified filekit.Verification
		root, readErr := get(ctx, k.Root)
		if readErr == nil {
			verified, readErr = filekit.VerifyRecoveryKit(ctx, owner, filekit.RecoveryKit{Version: k.Version, Root: root}, func(ctx context.Context, o filekit.Object) ([]byte, error) {
				return get(ctx, Object{ID: o.ID, Bytes: o.Bytes})
			})
			if readErr == nil && verified.File != k.File {
				readErr = ErrInvalid
			}
		}
		if e = ctx.Err(); e != nil {
			return finish(e)
		}
		if readErr != nil {
			failed = true
			result.Versions[i].State = "UNREADABLE"
			continue
		}
		result.Versions[i].State = "DECRYPTED"
		result.Versions[i].VerifiedUnix = started
		result.Versions[i].Content = &verified
	}
	if failed {
		return finish(ErrIncomplete)
	}
	result.Complete = true
	return finish(nil)
}

// KnownDamage is a detection ledger, not a fresh integrity read. An empty
// affected list after object repair does not re-publish the generation: its
// full verification window must still finish. Opaque version IDs permit precise
// owner-side selection without exposing plaintext names to workers.
type AffectedVersion struct {
	File    string   `json:"file"`
	Version string   `json:"version"`
	Objects []string `json:"objects"`
}
type KnownGenerationDamage struct {
	Generation  string            `json:"generation"`
	Damaged     bool              `json:"damaged"`
	RepairToken string            `json:"repairToken,omitempty"`
	Affected    []AffectedVersion `json:"affected"`
}

func (r *Replica) KnownDamage(ctx context.Context, id string) (KnownGenerationDamage, error) {
	var out KnownGenerationDamage
	e := r.locked(ctx, func(s *state) error {
		c, _, e := r.get(s, id, true)
		if e != nil {
			return e
		}
		item := s.Generations[id]
		out = KnownGenerationDamage{Generation: id, Damaged: item.Damaged, RepairToken: item.RepairToken, Affected: []AffectedVersion{}}
		for _, k := range c.Kits {
			if e := ctx.Err(); e != nil {
				return e
			}
			v := AffectedVersion{File: k.File, Version: k.Version, Objects: []string{}}
			if _, bad := s.Damage[k.Root.ID]; bad {
				v.Objects = append(v.Objects, k.Root.ID)
			}
			for _, o := range k.Objects {
				if _, bad := s.Damage[o.ID]; bad {
					v.Objects = append(v.Objects, o.ID)
				}
			}
			if len(v.Objects) > 0 {
				out.Affected = append(out.Affected, v)
			}
		}
		return nil
	})
	return out, e
}
