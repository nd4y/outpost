package localfs

import (
	"github.com/nd4y/outpost/internal/teststore"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateTreeCreationRejectsSymlinkAncestors(t *testing.T) {
	base := teststore.Root(t)
	target := filepath.Join(base, "owned", "nested", "state")
	if e := MkdirAll(target); e != nil {
		t.Fatal(e)
	}
	r, e := OpenRoot(target)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	i, e := os.Stat(target)
	if e != nil || i.Mode().Perm() != 0700 {
		t.Fatal("private mode", i, e)
	}
	if e = os.Symlink(filepath.Join(base, "owned"), filepath.Join(base, "alias")); e != nil {
		t.Fatal(e)
	}
	if e = MkdirAll(filepath.Join(base, "alias", "unexpected")); e == nil {
		t.Fatal("followed ancestor link")
	}
	if _, e = os.Stat(filepath.Join(base, "owned", "unexpected")); !os.IsNotExist(e) {
		t.Fatal("wrote through alias", e)
	}
	if r, e = OpenRoot(filepath.Join(base, "alias", "nested")); e == nil {
		r.Close()
		t.Fatal("opened alias root")
	}
	if e = MkdirAll("relative"); e == nil {
		t.Fatal("relative creation accepted")
	}
}

func TestRootedCreationStaysOnMovedParentAndRejectsAliases(t *testing.T) {
	base := teststore.Root(t)
	old := filepath.Join(base, "old")
	if e := MkdirAll(old); e != nil {
		t.Fatal(e)
	}
	r, e := OpenRoot(old)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	held := filepath.Join(base, "held")
	if e = os.Rename(old, held); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(old, 0700); e != nil {
		t.Fatal(e)
	}
	child, e := OpenAt(r, "deep/state", true)
	if e != nil {
		t.Fatal(e)
	}
	child.Close()
	if _, e = os.Stat(filepath.Join(held, "deep/state")); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(old)
	if e != nil || len(entries) != 0 {
		t.Fatal("replacement written", entries, e)
	}
	if e = r.Symlink("deep", "alias"); e != nil {
		t.Fatal(e)
	}
	if child, e = OpenAt(r, "alias/unexpected", true); e == nil {
		child.Close()
		t.Fatal("followed alias")
	}
	for _, name := range []string{"../outside", "/absolute", "deep/../escape", "deep//state"} {
		if child, e = OpenAt(r, name, true); e == nil {
			child.Close()
			t.Fatal("accepted", name)
		}
	}
}

func TestRootedFileOpenRejectsFinalAndAncestorLinks(t *testing.T) {
	base := teststore.Root(t)
	if e := MkdirAll(filepath.Join(base, "real")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(base, "real", "private"), []byte("value"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := OpenRoot(base)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = r.Symlink("real/private", "leaf"); e != nil {
		t.Fatal(e)
	}
	if e = r.Symlink("real", "alias"); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"leaf", "alias/private"} {
		f, e := OpenFile(r, name, os.O_RDONLY, 0)
		if e == nil {
			f.Close()
			t.Fatal("followed", name)
		}
	}
	f, e := OpenFile(r, "real/private", os.O_RDONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
}
