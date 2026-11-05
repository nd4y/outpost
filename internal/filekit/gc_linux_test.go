package filekit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGCAbortsBeforeDeletionOnInvalidRootOrMissingDependency(t *testing.T) {
	for _, damage := range []string{"invalid-signature", "unknown-version-entry", "missing-payload"} {
		t.Run(damage, func(t *testing.T) {
			base, s, source, data := fixture(t, 2<<20)
			ctx := context.Background()
			v := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
			_, d, err := s.LoadVersion(v.Version)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.putObject([]byte("unreachable synthetic object"), false); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "invalid-signature":
				b, err := s.readFile("versions/"+v.Version+".json", MaxRoot)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)-5] ^= 1
				if err = os.WriteFile(filepath.Join(base, "store/versions", v.Version+".json"), b, 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-version-entry":
				if err = os.WriteFile(filepath.Join(base, "store/versions/unexpected"), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-payload":
				if err = s.root.Remove(objectPath(d.Blocks[0].Object.ID)); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.objectInventory()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.GC(ctx); err == nil {
				t.Fatal("unsafe GC accepted invalid retained inventory")
			}
			after, err := s.objectInventory()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("GC deleted objects before validating all roots")
			}
			if damage == "unknown-version-entry" {
				if err = s.root.Remove("versions/unexpected"); err != nil {
					t.Fatal(err)
				}
				mustRestore(t, s, v.Version, filepath.Join(base, "good"), data, false)
			}
		})
	}
}

func TestConfidentialNamesAndFileDomainIsolation(t *testing.T) {
	_, s, source, data := fixture(t, 128<<10)
	marker := "unique-private-name-5c41a128.bin"
	a := mustBackup(t, s, source, BackupOptions{Names: []string{marker}})
	b := mustBackup(t, s, source, BackupOptions{Names: []string{"another-name"}})
	ae, ad, err := s.LoadVersion(a.Version)
	if err != nil {
		t.Fatal(err)
	}
	be, bd, err := s.LoadVersion(b.Version)
	if err != nil {
		t.Fatal(err)
	}
	ar, err := dependencies(ae, ad)
	if err != nil {
		t.Fatal(err)
	}
	br, err := dependencies(be, bd)
	if err != nil {
		t.Fatal(err)
	}
	for id, ref := range ar {
		if _, shared := br[id]; shared {
			t.Fatal("cross-file encrypted objects shared")
		}
		ciphertext, err := s.readObject(ref)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ciphertext, []byte(marker)) || bytes.Contains(ciphertext, data[:64]) {
			t.Fatal("plaintext disclosed")
		}
	}
	root, err := s.readFile("versions/"+a.Version+".json", MaxRoot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(root, []byte(marker)) || bytes.Contains(root, []byte(ad.Blocks[0].Hash)) {
		t.Fatal("root disclosed names or plaintext chunk identity")
	}
}
