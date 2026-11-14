package volume

import (
	"context"
	"errors"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"os"
	"path/filepath"
	"testing"
)

func TestVolumeEnrollmentRequiresObservedIdentityAndPrivateSentinel(t *testing.T) {
	ctx := context.Background()
	root := teststore.Root(t)
	o, e := Probe(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	changed := o
	changed.RootInode++
	if _, e = Enroll(ctx, root, changed, storage.Hash([]byte("worker")), 1); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unexpected identity enrolled", e)
	}
	if _, e = os.Stat(filepath.Join(root, Sentinel)); !os.IsNotExist(e) {
		t.Fatal("wrote before matching observation", e)
	}
	b, e := Enroll(ctx, root, o, storage.Hash([]byte("worker")), 1)
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "worker")
	if e = b.Check(ctx, dir, true); e != nil {
		t.Fatal(e)
	}
	if e = b.Check(ctx, dir, false); !errors.Is(e, ErrUnavailable) {
		t.Fatal("missing runtime accepted", e)
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = b.Check(ctx, dir, false); e != nil {
		t.Fatal(e)
	}
	copy := b
	copy.FSID[0]++
	if e = copy.Check(ctx, dir, false); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wrong filesystem accepted", e)
	}
	if e = b.Check(ctx, root, true); !errors.Is(e, ErrUnavailable) {
		t.Fatal("runtime at volume root accepted", e)
	}
	if e = b.Check(ctx, filepath.Dir(root), true); !errors.Is(e, ErrUnavailable) {
		t.Fatal("outside runtime accepted", e)
	}
	if e = os.Chmod(filepath.Join(root, Sentinel), 0644); e != nil {
		t.Fatal(e)
	}
	if e = b.Check(ctx, dir, false); !errors.Is(e, ErrUnavailable) {
		t.Fatal("public sentinel accepted", e)
	}
}
func TestVolumeLossAndAliasesNeverCreateFallbackState(t *testing.T) {
	ctx := context.Background()
	root := teststore.Root(t)
	o, e := Probe(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Enroll(ctx, root, o, storage.Hash([]byte("worker")), 1)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(root, "real"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("real", filepath.Join(root, "alias")); e != nil {
		t.Fatal(e)
	}
	if e = b.Check(ctx, filepath.Join(root, "alias", "state"), true); !errors.Is(e, ErrUnavailable) {
		t.Fatal("alias accepted", e)
	}
	if e = os.Rename(filepath.Join(root, Sentinel), filepath.Join(root, "saved-sentinel")); e != nil {
		t.Fatal(e)
	}
	if e = b.Check(ctx, filepath.Join(root, "fallback"), true); !errors.Is(e, ErrUnavailable) {
		t.Fatal("missing sentinel accepted", e)
	}
	if _, e = os.Stat(filepath.Join(root, "fallback")); !os.IsNotExist(e) {
		t.Fatal("fallback state created", e)
	}
	if _, e = Probe(ctx, filepath.Join(root, "missing-volume")); !errors.Is(e, ErrUnavailable) {
		t.Fatal("missing volume accepted", e)
	}
	if _, e = os.Stat(filepath.Join(root, "missing-volume")); !os.IsNotExist(e) {
		t.Fatal("missing volume auto-created", e)
	}
}

func TestMissingMarkerNeverReenrollsExistingState(t *testing.T) {
	ctx := context.Background()
	root := teststore.Root(t)
	scope := storage.Hash([]byte("worker"))
	o, e := Probe(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Enroll(ctx, root, o, scope, 1)
	if e != nil {
		t.Fatal(e)
	}
	r, e := b.Open(ctx, filepath.Join(root, "worker"), true)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	if e = os.Remove(filepath.Join(root, Sentinel)); e != nil {
		t.Fatal(e)
	}
	o, e = Probe(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Enroll(ctx, root, o, scope, 2); !errors.Is(e, ErrUnavailable) {
		t.Fatal("reenrolled nonempty target", e)
	}
	if _, e = os.Stat(filepath.Join(root, Sentinel)); !os.IsNotExist(e) {
		t.Fatal("recreated missing marker", e)
	}
}
