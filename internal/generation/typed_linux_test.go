package generation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/filekit"
)

func TestTypedGenerationKeepsStandaloneRecoveryAfterSourceLoss(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	owner, e := filekit.NewOwner()
	ok(t, e)
	trust.Domain = owner.Domain
	source := filepath.Join(base, "tree")
	ok(t, os.Mkdir(source, 0700))
	ok(t, os.Mkdir(filepath.Join(source, "folder"), 0750))
	ok(t, os.WriteFile(filepath.Join(source, "folder", "file"), []byte("retained content"), 0640))
	ok(t, os.Symlink("/absent/outside-target", filepath.Join(source, "link")))
	root, e := os.OpenRoot(source)
	ok(t, e)
	storeDir := filepath.Join(base, "source-kit")
	store, e := filekit.OpenStore(storeDir, owner, true)
	ok(t, e)
	var versions []string
	for _, name := range []string{"folder", "folder/file", "link"} {
		result, e := store.BackupEntry(ctx, root, name, filekit.BackupOptions{Names: []string{"dataset/" + name}})
		ok(t, e)
		versions = append(versions, result.Version)
	}
	receiver := openTest(t, filepath.Join(base, "receiver"), trust)
	id, e := Seal(ctx, store, versions, receiver, Catalog{Format: Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1, KitFormat: KitFormat}, key)
	ok(t, e)
	raw, e := receiver.Catalog(ctx, id)
	ok(t, e)
	catalog, e := VerifyCatalog(raw, trust)
	ok(t, e)
	if catalog.KitFormat != TypedKitFormat {
		t.Fatal("new reader requirement omitted")
	}
	ok(t, root.Close())
	ok(t, store.Close())
	ok(t, os.RemoveAll(source))
	ok(t, os.RemoveAll(storeDir))
	owner.SigningKey = nil
	for i, version := range versions {
		kit := filepath.Join(base, []string{"kit-dir", "kit-file", "kit-link"}[i])
		ok(t, receiver.ExportKit(ctx, id, version, kit))
		reader, e := filekit.OpenStore(kit, owner, false)
		ok(t, e)
		output := filepath.Join(base, []string{"restore-dir", "restore-file", "restore-link"}[i])
		d, e := reader.Restore(ctx, version, output)
		ok(t, e)
		ok(t, reader.Close())
		name := filepath.Join(output, d.Names[0])
		switch i {
		case 0:
			st, e := os.Lstat(name)
			ok(t, e)
			if !st.IsDir() || st.Mode().Perm() != 0750 {
				t.Fatal("directory lost")
			}
		case 1:
			b, e := os.ReadFile(name)
			ok(t, e)
			if string(b) != "retained content" {
				t.Fatal("regular file changed")
			}
		case 2:
			target, e := os.Readlink(name)
			ok(t, e)
			if target != "/absent/outside-target" {
				t.Fatal("link changed")
			}
		}
	}
	ok(t, receiver.Close())
	ok(t, os.Remove(filepath.Join(base, "receiver/state.json")))
	whole, e := RecoverMaterialized(ctx, filepath.Join(base, "receiver"), id, trust, owner, RecoverySelection{}, filepath.Join(base, "whole-dataset"))
	ok(t, e)
	if whole.Generation != id || !whole.CheckpointMatch || whole.Restored.Files != 1 || whole.Restored.Directories != 1 || whole.Restored.Symlinks != 1 {
		t.Fatal("incomplete dataset receipt", whole)
	}
	body, e := os.ReadFile(filepath.Join(base, "whole-dataset/dataset/folder/file"))
	ok(t, e)
	if string(body) != "retained content" {
		t.Fatal("dataset content changed")
	}
	selected, e := RecoverMaterialized(ctx, filepath.Join(base, "receiver"), id, trust, owner, RecoverySelection{Directory: "dataset/folder"}, filepath.Join(base, "selected-directory"))
	ok(t, e)
	if selected.Restored.Files != 1 || selected.Restored.Symlinks != 0 {
		t.Fatal("directory scope widened", selected)
	}
	if _, e = RecoverMaterialized(ctx, filepath.Join(base, "receiver"), Hash([]byte("wrong checkpoint")), trust, owner, RecoverySelection{}, filepath.Join(base, "wrong")); e == nil {
		t.Fatal("checkpoint replaced with latest")
	}
}
