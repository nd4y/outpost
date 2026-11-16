package filekit

import (
	"bytes"
	"context"
	"io/fs"
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
	base, s, source, data := fixture(t, 128<<10)
	marker := "unique-private-name-5c41a128.bin"
	otherName := "another-private-name-62e59c10.bin"
	payloadMarker := []byte("private-payload-marker-fb98e145")
	for _, offset := range []int{0, len(data) / 2, len(data) - len(payloadMarker)} {
		copy(data[offset:], payloadMarker)
	}
	if err := os.WriteFile(source, data, 0640); err != nil {
		t.Fatal(err)
	}
	a := mustBackup(t, s, source, BackupOptions{Names: []string{marker}})
	b := mustBackup(t, s, source, BackupOptions{Names: []string{otherName}})
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
	for id := range ar {
		if _, shared := br[id]; shared {
			t.Fatal("cross-file encrypted objects shared")
		}
	}
	for _, version := range []string{a.Version, b.Version} {
		root, err := s.readFile("versions/"+version+".json", MaxRoot)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range [][]byte{[]byte(marker), []byte(otherName), payloadMarker, []byte(ad.Blocks[0].Hash), []byte(bd.Blocks[0].Hash)} {
			if bytes.Contains(root, secret) {
				t.Fatal("version root disclosed a private marker")
			}
		}
		kit := filepath.Join(base, "export-"+version)
		if err := s.Export(context.Background(), version, kit); err != nil {
			t.Fatal(err)
		}
		files := 0
		err = filepath.WalkDir(kit, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(kit, name)
			if err != nil {
				return err
			}
			for _, secret := range []string{marker, otherName, string(payloadMarker), ad.Blocks[0].Hash, bd.Blocks[0].Hash} {
				if bytes.Contains([]byte(relative), []byte(secret)) {
					t.Fatal("export filename disclosed a private marker")
				}
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				t.Fatal("export contains a non-regular entry")
			}
			files++
			raw, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			for _, secret := range [][]byte{[]byte(marker), []byte(otherName), payloadMarker, []byte(ad.Blocks[0].Hash), []byte(bd.Blocks[0].Hash)} {
				if bytes.Contains(raw, secret) {
					t.Fatal("export bytes disclosed a private marker")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if files < 3 {
			t.Fatal("export must contain the envelope, descriptor and encrypted payload")
		}
	}
}
