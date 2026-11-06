package filekit

import (
	"context"
	"encoding/json"
	"sort"
)

// SealedKit contains only opaque metadata and the complete physical closure.
// The callback must finish reading objects before WithSealedKits returns.
type SealedKit struct {
	File, Version string
	Root          []byte
	Objects       []Object
}

// WithSealedKits holds one shared maintenance lock across all selected versions
// and their copying. No decryption key or plaintext metadata leaves this API.
func (s *Store) WithSealedKits(ctx context.Context, versions []string, consume func([]SealedKit, func(Object) ([]byte, error)) error) error {
	if len(versions) == 0 || len(versions) > 64 || consume == nil {
		return ErrInvalid
	}
	unlock, err := s.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	seen := map[string]bool{}
	var kits []SealedKit
	for _, version := range versions {
		if err = ctx.Err(); err != nil {
			return err
		}
		if seen[version] {
			return ErrInvalid
		}
		seen[version] = true
		e, d, err := s.LoadVersion(version)
		if err != nil {
			return err
		}
		refs, err := dependencies(e, d)
		if err != nil {
			return err
		}
		root, err := json.Marshal(e)
		if err != nil {
			return err
		}
		kit := SealedKit{File: e.File, Version: version, Root: root}
		for _, ref := range refs {
			kit.Objects = append(kit.Objects, ref)
		}
		sort.Slice(kit.Objects, func(i, j int) bool { return kit.Objects[i].ID < kit.Objects[j].ID })
		kits = append(kits, kit)
	}
	return consume(kits, func(ref Object) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return s.readObject(ref)
	})
}
