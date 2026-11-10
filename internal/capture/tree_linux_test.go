package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestTreeProviderEnrolmentAndReleaseNeverMutateSource(t *testing.T) {
	ctx := context.Background()
	base := teststore.Root(t)
	tree := filepath.Join(base, "tree")
	runtime := filepath.Join(base, "runtime")
	must(t, os.Mkdir(tree, 0700))
	must(t, os.Mkdir(runtime, 0700))
	must(t, os.WriteFile(filepath.Join(tree, "private"), []byte("retained source"), 0600))
	binding, e := ProbeTree(ctx, tree, storage.Hash([]byte("origin")))
	must(t, e)
	names, e := os.ReadDir(tree)
	must(t, e)
	if len(names) != 1 {
		t.Fatal("probe wrote source")
	}
	root, e := localfs.OpenRoot(runtime)
	must(t, e)
	defer root.Close()
	operation := storage.Hash([]byte("operation"))
	view := storage.Hash([]byte("view"))
	p, e := OpenTreeProvider(ctx, root, "provider", operation, view, binding, true, nil, nil)
	must(t, e)
	p.ReleaseObservationAdmission = func(string, int) (func(bool) error, error) {
		return func(bool) error { return nil }, nil
	}
	source, e := p.Open(ctx, view)
	must(t, e)
	source.Close()
	if e = p.Release(ctx, storage.Hash([]byte("other")), view); !errors.Is(e, ErrInvalid) {
		t.Fatal("released wrong operation", e)
	}
	if ProviderReleaseObservedUnix(root, operation, "provider") != 0 {
		t.Fatal("unreleased provider has release timing")
	}
	start := time.Now().Unix()
	must(t, p.Release(ctx, operation, view))
	released := ProviderReleaseObservedUnix(root, operation, "provider")
	if released < start || released > time.Now().Unix() {
		t.Fatal("missing durable release timing", released)
	}
	must(t, p.Close())
	p, e = OpenTreeProvider(ctx, root, "provider", operation, view, binding, false, nil, nil)
	must(t, e)
	defer p.Close()
	must(t, p.Release(ctx, operation, view))
	if ProviderReleaseObservedUnix(root, operation, "provider") != released {
		t.Fatal("replay changed original release timing")
	}
	if source, e = p.Open(ctx, view); e == nil {
		source.Close()
		t.Fatal("released view reopened")
	}
	data, e := os.ReadFile(filepath.Join(tree, "private"))
	must(t, e)
	if string(data) != "retained source" {
		t.Fatal("source changed")
	}
	names, e = os.ReadDir(tree)
	must(t, e)
	if len(names) != 1 {
		t.Fatal("provider wrote into source")
	}
}

func TestReleaseObservationQuotaAndLegacyRemainUnknown(t *testing.T) {
	ctx := context.Background()
	base := teststore.Root(t)
	source := filepath.Join(base, "source")
	must(t, os.Mkdir(source, 0700))
	runtime := filepath.Join(base, "runtime")
	must(t, os.Mkdir(runtime, 0700))
	root, err := localfs.OpenRoot(runtime)
	must(t, err)
	defer root.Close()
	operation := storage.Hash([]byte("operation"))
	binding, err := ProbeTree(ctx, source, storage.Hash([]byte("origin")))
	must(t, err)
	rejected := false
	p, err := OpenTreeProvider(ctx, root, "provider", operation, operation, binding, true, nil, nil)
	must(t, err)
	p.ReleaseObservationAdmission = func(name string, _ int) (func(bool) error, error) {
		if name != releaseObservationName(operation) {
			t.Fatal("unexpected observation path", name)
		}
		rejected = true
		return nil, statefile.ErrCapacity
	}
	must(t, p.Release(ctx, operation, operation))
	must(t, p.Close())
	if !rejected || ProviderReleaseObservedUnix(root, operation, "provider") != 0 {
		t.Fatal("quota failure was not kept as unknown timing")
	}
	// An older installation has the same released view with no observation.
	p, err = OpenTreeProvider(ctx, root, "provider", operation, operation, binding, false, nil, nil)
	must(t, err)
	defer p.Close()
	must(t, p.Release(ctx, operation, operation))
	if view, err := p.Open(ctx, operation); err == nil {
		view.Close()
		t.Fatal("optional observation failure kept the view open")
	}
	if ProviderReleaseObservedUnix(root, operation, "provider") != 0 {
		t.Fatal("replay invented release timing")
	}
	store, err := statefile.OpenAt(root, "telemetry", 4096, true)
	must(t, err)
	defer store.Close()
	must(t, store.Write(releaseObservationName(operation), []byte(`{"viewDigest":"`+operation+`","observedUnix":1}`)))
	if ProviderReleaseObservedUnix(root, operation, "provider") != 0 {
		t.Fatal("accepted release evidence from a different view")
	}
}
func TestTreeProviderRejectsOverlapsAliasAndReplacedSource(t *testing.T) {
	for _, kind := range []string{"equal", "source-ancestor", "source-descendant", "alias", "replaced"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			base := teststore.Root(t)
			runtime := filepath.Join(base, "runtime")
			tree := filepath.Join(base, "source")
			must(t, os.Mkdir(runtime, 0700))
			must(t, os.Mkdir(tree, 0700))
			switch kind {
			case "equal":
				tree = runtime
			case "source-ancestor":
				tree = base
			case "source-descendant":
				tree = filepath.Join(runtime, "source")
				must(t, os.Mkdir(tree, 0700))
			}
			binding, e := ProbeTree(ctx, tree, storage.Hash([]byte("origin")))
			must(t, e)
			root, e := localfs.OpenRoot(runtime)
			must(t, e)
			defer root.Close()
			if kind == "alias" {
				alias := filepath.Join(base, "alias")
				must(t, os.Symlink(tree, alias))
				binding.Path = alias
			}
			if kind == "replaced" {
				must(t, os.Rename(tree, tree+"-held"))
				must(t, os.Mkdir(tree, 0700))
			}
			p, e := OpenTreeProvider(ctx, root, "provider", storage.Hash([]byte("op")), storage.Hash([]byte("view")), binding, true, nil, nil)
			must(t, e)
			defer p.Close()
			if source, e := p.Open(ctx, storage.Hash([]byte("view"))); e == nil {
				source.Close()
				t.Fatal("unsafe source admitted", kind)
			}
		})
	}
}
