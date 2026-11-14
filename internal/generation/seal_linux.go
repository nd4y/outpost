package generation

import (
	"context"
	"crypto/ed25519"
	"sort"

	"github.com/nd4y/outpost/internal/filekit"
)

// Seal copies a complete consistent source view directly into an isolated
// local replica. The source owner verifies encrypted descriptors; the receiving
// replica sees only ciphertext, public verification keys and opaque identities.
// Signing and deletion keys are independent of the source data owner key.
func Seal(ctx context.Context, source *filekit.Store, versions []string, target *Replica, c Catalog, writer ed25519.PrivateKey) (string, error) {
	var id string
	if source == nil || target == nil || source.Owner.Domain != c.Domain {
		return id, ErrInvalid
	}
	err := source.WithSealedKits(ctx, versions, func(kits []filekit.SealedKit, read func(filekit.Object) ([]byte, error)) error {
		raw, roots, e := assembleCatalog(kits, c, writer)
		if e != nil {
			return e
		}
		id, e = target.Receive(ctx, raw, func(ref Object) ([]byte, error) {
			if b, ok := roots[ref.ID]; ok {
				return b, nil
			}
			return read(filekit.Object{ID: ref.ID, Bytes: ref.Bytes})
		})
		return e
	})
	return id, err
}

// BuildCatalog authenticates immutable file descriptors and signs their opaque
// closure without reading payload back through the source. The receiving ingress
// must verify every object before COMPLETE. This function alone is not a durable
// acceptance receipt and must never release a source snapshot.
func BuildCatalog(ctx context.Context, source *filekit.Store, versions []string, c Catalog, writer ed25519.PrivateKey) ([]byte, map[string][]byte, error) {
	if source == nil || source.Owner.Domain != c.Domain {
		return nil, nil, ErrInvalid
	}
	var raw []byte
	var roots map[string][]byte
	err := source.WithSealedKits(ctx, versions, func(kits []filekit.SealedKit, _ func(filekit.Object) ([]byte, error)) error {
		var e error
		raw, roots, e = assembleCatalog(kits, c, writer)
		return e
	})
	return raw, roots, err
}
func assembleCatalog(kits []filekit.SealedKit, c Catalog, writer ed25519.PrivateKey) ([]byte, map[string][]byte, error) {
	roots := map[string][]byte{}
	c.Kits = nil
	c.KitFormat = KitFormat
	for _, kit := range kits {
		if kit.Format == filekit.TypedFormat {
			c.KitFormat = TypedKitFormat
		}
		ref := Object{Hash(kit.Root), len(kit.Root)}
		roots[ref.ID] = kit.Root
		k := Kit{File: kit.File, Version: kit.Version, Root: ref}
		for _, o := range kit.Objects {
			k.Objects = append(k.Objects, Object{o.ID, o.Bytes})
		}
		c.Kits = append(c.Kits, k)
	}
	sort.Slice(c.Kits, func(i, j int) bool {
		return c.Kits[i].File+"/"+c.Kits[i].Version < c.Kits[j].File+"/"+c.Kits[j].Version
	})
	raw, e := SignCatalog(c, writer)
	return raw, roots, e
}
