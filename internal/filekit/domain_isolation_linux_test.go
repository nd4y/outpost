package filekit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIndependentOwnerDomainsIdenticalInput(t *testing.T) {
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	type savedDomain struct {
		base, source, kit string
		store             *Store
		owner             Owner
		version           Stats
		envelope          Envelope
		objects           map[string]Object
	}
	domains := make([]savedDomain, 2)
	file := randomID() // Hold file identity constant across the two domains.
	name := "same/секрет.bin"
	stamp := time.Unix(1710000000, 123456789)
	var content []byte
	for i := range domains {
		base, store, source, data := fixture(t, 128<<10)
		if i == 0 {
			content = bytes.Clone(data)
		}
		must(os.WriteFile(source, content, 0640))
		must(os.Chtimes(source, stamp, stamp))
		v := mustBackup(t, store, source, BackupOptions{Names: []string{name}, File: file})
		e, d, err := store.LoadVersion(v.Version)
		must(err)
		if v.File != file || d.File != file || d.Domain != store.Owner.Domain || d.SHA256 != digest(content) || len(d.Names) != 1 || d.Names[0] != name {
			t.Fatal("fixture did not preserve identical file identity, name and bytes")
		}
		objects, err := dependencies(e, d)
		must(err)
		if len(objects) < 2 {
			t.Fatal("fixture lacks encrypted metadata and payload dependencies")
		}
		owner, err := store.Owner.RecoveryMaterial()
		must(err)
		if len(owner.SigningKey) != 0 {
			t.Fatal("independent reader retained signing authority")
		}
		domains[i] = savedDomain{base, source, filepath.Join(base, "kit"), store, owner, v, e, objects}
	}
	if domains[0].owner.Domain == domains[1].owner.Domain || bytes.Equal(domains[0].owner.Master, domains[1].owner.Master) || domains[0].version.Version == domains[1].version.Version {
		t.Fatal("fixture did not create independent owner domains and versions")
	}
	for id := range domains[0].objects {
		if _, exists := domains[1].objects[id]; exists {
			t.Fatal("identical input reused encrypted dependencies across domains")
		}
	}
	for i, saved := range domains {
		must(saved.store.Export(ctx, saved.version.Version, saved.kit))
		must(saved.store.Close())
		wrong, err := OpenStore(filepath.Join(saved.base, "store"), domains[1-i].owner, false)
		if wrong != nil {
			wrong.Close()
		}
		if !errors.Is(err, ErrInvalid) {
			t.Fatal("foreign owner opened the domain store", err)
		}
		for _, global := range []string{"versions", ".txn", ".lock", "store.json"} {
			must(os.RemoveAll(filepath.Join(saved.kit, global)))
		}
		entries, err := os.ReadDir(saved.kit)
		must(err)
		if len(entries) != 2 || entries[0].Name() != "kit.json" || entries[1].Name() != "objects" {
			t.Fatal("independent kit retained unexpected shared state")
		}
		must(os.RemoveAll(filepath.Join(saved.base, "store")))
		must(os.Remove(saved.source))
	}
	for i, saved := range domains {
		foreignMaster := saved.owner
		foreignMaster.Master = bytes.Clone(domains[1-i].owner.Master)
		// This variant passes signed-envelope admission before data-key refusal.
		must(foreignMaster.verifyEnvelope(saved.envelope, saved.version.Version))
		for _, variant := range []struct {
			name  string
			owner Owner
		}{{"foreign-owner", domains[1-i].owner}, {"foreign-data-key", foreignMaster}} {
			kit, err := OpenStore(saved.kit, variant.owner, false)
			must(err)
			out := filepath.Join(saved.base, variant.name)
			_, err = kit.Restore(ctx, saved.version.Version, out)
			must(kit.Close())
			if err == nil {
				t.Fatal("cross-domain recovery succeeded", variant.name)
			}
			if _, err = os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cross-domain refusal left plaintext output", variant.name, err)
			}
			stages, err := filepath.Glob(filepath.Join(saved.base, ".outpost-restore-*"))
			must(err)
			if len(stages) != 0 {
				t.Fatal("cross-domain refusal left a plaintext stage", variant.name)
			}
		}
		kit, err := OpenStore(saved.kit, saved.owner, false)
		must(err)
		d := mustRestore(t, kit, saved.version.Version, filepath.Join(saved.base, "restored"), content, true)
		must(kit.Close())
		if d.Domain != saved.owner.Domain || d.File != file || d.Metadata.MtimeNS != stamp.UnixNano() || d.Metadata.Mode&0777 != 0640 {
			t.Fatal("authorized independent recovery changed identity or metadata")
		}
	}
	t.Logf("DOMAIN_ISOLATION domains=2 bytes=%d objectSets=DISJOINT independentRestores=2 crossedOwnerRefusals=2 crossedDataKeyRefusals=2", len(content))
}
