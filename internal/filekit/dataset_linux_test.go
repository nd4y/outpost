package filekit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDatasetRequiresExplicitVersionAndBoundsAncestorExpansion(t *testing.T) {
	base, s, source, old := fixture(t, 1)
	ctx := context.Background()
	v1, e := s.Backup(ctx, source, BackupOptions{Names: []string{"data"}})
	entryOK(t, e)
	entryOK(t, os.WriteFile(source, []byte("new version"), 0600))
	v2, e := s.Backup(ctx, source, BackupOptions{Names: []string{"data"}, File: v1.File, Previous: v1.Version})
	entryOK(t, e)
	kits, objects := recoveryMaterial(t, s, []string{v1.Version, v2.Version})
	if _, e = RecoverSet(ctx, s.Owner, kits, recoveryRead(objects), filepath.Join(base, "ambiguous")); !errors.Is(e, ErrInvalid) {
		t.Fatal("ambiguous version silently selected", e)
	}
	_, e = RecoverSet(ctx, s.Owner, kits[:1], recoveryRead(objects), filepath.Join(base, "old"))
	entryOK(t, e)
	b, e := os.ReadFile(filepath.Join(base, "old/data"))
	entryOK(t, e)
	if !bytes.Equal(b, old) {
		t.Fatal("selected version changed")
	}
	d := Descriptor{Format: Format, Domain: s.Owner.Domain, File: v1.File, SHA256: digest(nil), Metadata: Metadata{Mode: 0600}}
	for i := 0; i < 256; i++ {
		d.Names = append(d.Names, fmt.Sprintf("%03d/", i)+strings.Repeat("d/", 128)+"file")
	}
	if _, _, e = validateSet([]Descriptor{d}); !errors.Is(e, ErrInvalid) {
		t.Fatal("unbounded implicit directories", e)
	}
}

func recoveryMaterial(t *testing.T, s *Store, versions []string) ([]RecoveryKit, map[string][]byte) {
	t.Helper()
	var kits []RecoveryKit
	objects := map[string][]byte{}
	err := s.WithSealedKits(context.Background(), versions, func(all []SealedKit, read func(Object) ([]byte, error)) error {
		for _, k := range all {
			kits = append(kits, RecoveryKit{Version: k.Version, Root: k.Root})
			for _, o := range k.Objects {
				b, e := read(o)
				if e != nil {
					return e
				}
				objects[o.ID] = bytes.Clone(b)
			}
		}
		return nil
	})
	entryOK(t, err)
	return kits, objects
}
func recoveryRead(objects map[string][]byte) ObjectReader {
	return func(ctx context.Context, o Object) ([]byte, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		b, ok := objects[o.ID]
		if !ok {
			return nil, os.ErrNotExist
		}
		return bytes.Clone(b), nil
	}
}

func TestIndependentDatasetRestoresDirectoryMetadataLastAndHardlinks(t *testing.T) {
	base, s, source, _ := fixture(t, 1)
	ctx := context.Background()
	tree := filepath.Join(base, "tree")
	entryOK(t, os.Mkdir(tree, 0700))
	entryOK(t, os.Mkdir(filepath.Join(tree, "folder"), 0700))
	body := bytes.Repeat([]byte("whole dataset"), 300)
	entryOK(t, os.WriteFile(filepath.Join(tree, "folder/data"), body, 0600))
	entryOK(t, os.Link(filepath.Join(tree, "folder/data"), filepath.Join(tree, "alias")))
	outside := filepath.Join(base, "outside")
	entryOK(t, os.WriteFile(outside, []byte("untouched"), 0600))
	entryOK(t, os.Symlink(outside, filepath.Join(tree, "folder/link")))
	stamp := time.Unix(1700000000, 123456789)
	entryOK(t, os.Chtimes(filepath.Join(tree, "folder"), stamp, stamp))
	entryOK(t, os.Chmod(filepath.Join(tree, "folder"), 0500))
	r, e := os.OpenRoot(tree)
	entryOK(t, e)
	defer r.Close()
	var versions []string
	for _, name := range []string{"folder", "folder/data", "folder/link"} {
		names := []string{name}
		if name == "folder/data" {
			names = append(names, "alias")
		}
		got, e := s.BackupEntry(ctx, r, name, BackupOptions{Names: names})
		entryOK(t, e)
		versions = append(versions, got.Version)
	}
	kits, objects := recoveryMaterial(t, s, versions)
	owner := s.Owner
	owner.SigningKey = nil
	storePath := s.root.Name()
	entryOK(t, s.Close())
	entryOK(t, os.RemoveAll(storePath))
	entryOK(t, os.Remove(source))
	entryOK(t, os.Chmod(filepath.Join(tree, "folder"), 0700))
	entryOK(t, os.RemoveAll(tree))
	out := filepath.Join(base, "restored")
	summary, e := RecoverSet(ctx, owner, kits, recoveryRead(objects), out)
	entryOK(t, e)
	if summary.Files != 1 || summary.Directories != 1 || summary.Aliases != 1 || summary.Symlinks != 1 || summary.ImplicitDirectories != 0 || summary.Bytes != int64(len(body)) {
		t.Fatal("bad restore summary", summary)
	}
	got, e := os.ReadFile(filepath.Join(out, "folder/data"))
	entryOK(t, e)
	if !bytes.Equal(got, body) {
		t.Fatal("content differs")
	}
	a, e := os.Stat(filepath.Join(out, "alias"))
	entryOK(t, e)
	b, e := os.Stat(filepath.Join(out, "folder/data"))
	entryOK(t, e)
	if !os.SameFile(a, b) {
		t.Fatal("hardlinks differ")
	}
	d, e := os.Stat(filepath.Join(out, "folder"))
	entryOK(t, e)
	if d.Mode().Perm() != 0500 || d.ModTime().UnixNano() != stamp.UnixNano() {
		t.Fatal("directory metadata overwritten by children", d.Mode(), d.ModTime())
	}
	target, e := os.Readlink(filepath.Join(out, "folder/link"))
	entryOK(t, e)
	if target != outside {
		t.Fatal("symlink changed")
	}
	got, e = os.ReadFile(outside)
	entryOK(t, e)
	if string(got) != "untouched" {
		t.Fatal("outside target modified")
	}
	if _, e = RecoverSet(ctx, owner, kits, recoveryRead(objects), out); !errors.Is(e, os.ErrExist) {
		t.Fatal("destination overwritten", e)
	}
	entryOK(t, os.Chmod(filepath.Join(out, "folder"), 0700))
}
func TestDatasetRejectsAuthenticatedPathCollisionsBeforeOutput(t *testing.T) {
	for _, kind := range []string{"same-path", "symlink-ancestor", "file-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			base, s, source, _ := fixture(t, 1)
			ctx := context.Background()
			one := "a"
			two := "a/data"
			var versions []string
			if kind == "same-path" {
				two = "a"
			}
			if kind == "symlink-ancestor" {
				tree := filepath.Join(base, "tree")
				entryOK(t, os.Mkdir(tree, 0700))
				entryOK(t, os.Symlink("/outside", filepath.Join(tree, "link")))
				r, e := os.OpenRoot(tree)
				entryOK(t, e)
				defer r.Close()
				got, e := s.BackupEntry(ctx, r, "link", BackupOptions{Names: []string{one}})
				entryOK(t, e)
				versions = append(versions, got.Version)
			} else {
				got, e := s.Backup(ctx, source, BackupOptions{Names: []string{one}})
				entryOK(t, e)
				versions = append(versions, got.Version)
			}
			got, e := s.Backup(ctx, source, BackupOptions{Names: []string{two}})
			entryOK(t, e)
			versions = append(versions, got.Version)
			kits, objects := recoveryMaterial(t, s, versions)
			out := filepath.Join(base, "restore")
			if _, e = RecoverSet(ctx, s.Owner, kits, recoveryRead(objects), out); !errors.Is(e, ErrInvalid) {
				t.Fatal("collision accepted", e)
			}
			if _, e = os.Lstat(out); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("partial output exists", e)
			}
			entries, e := os.ReadDir(base)
			entryOK(t, e)
			for _, n := range entries {
				if len(n.Name()) >= 17 && n.Name()[:17] == ".outpost-restore-" {
					t.Fatal("failed staging retained")
				}
			}
		})
	}
}
func TestDatasetRejectsMissingCorruptAndCancelledPayloadWithoutPublication(t *testing.T) {
	base, s, source, _ := fixture(t, 1)
	ctx := context.Background()
	got, e := s.Backup(ctx, source, BackupOptions{Names: []string{"folder/data"}})
	entryOK(t, e)
	kits, objects := recoveryMaterial(t, s, []string{got.Version})
	_, d, e := s.LoadVersion(got.Version)
	entryOK(t, e)
	ref := d.Blocks[0].Object
	valid := bytes.Clone(objects[ref.ID])
	for _, kind := range []string{"missing", "corrupt", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			objects[ref.ID] = bytes.Clone(valid)
			attempt := ctx
			switch kind {
			case "missing":
				delete(objects, ref.ID)
			case "corrupt":
				objects[ref.ID][0] ^= 1
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				attempt = c
			}
			out := filepath.Join(base, "restore-"+kind)
			if _, e := RecoverSet(attempt, s.Owner, kits, recoveryRead(objects), out); e == nil {
				t.Fatal("bad restore accepted")
			}
			if _, e := os.Lstat(out); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("bad restore published", e)
			}
		})
	}
}
