package capture

import (
	"context"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"os"
	"path/filepath"
	"testing"
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
	source, e := p.Open(ctx, view)
	must(t, e)
	source.Close()
	if e = p.Release(ctx, storage.Hash([]byte("other")), view); !errors.Is(e, ErrInvalid) {
		t.Fatal("released wrong operation", e)
	}
	must(t, p.Release(ctx, operation, view))
	must(t, p.Close())
	p, e = OpenTreeProvider(ctx, root, "provider", operation, view, binding, false, nil, nil)
	must(t, e)
	defer p.Close()
	must(t, p.Release(ctx, operation, view))
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
