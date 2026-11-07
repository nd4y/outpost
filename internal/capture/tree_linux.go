package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

const TreeFormat = "outpost-best-effort-tree-1"

// TreeBinding is private local enrollment, not a snapshot consistency claim.
// Probe uses read-only metadata calls and never writes a sentinel to the source.
type TreeBinding struct {
	Format   string             `json:"format"`
	Path     string             `json:"path"`
	Observed volume.Observation `json:"observed"`
	Origin   string             `json:"origin"`
}
type treeState struct {
	Format    string `json:"format"`
	Binding   string `json:"binding"`
	Operation string `json:"operation"`
	View      string `json:"view"`
	Released  bool   `json:"released"`
}
type TreeProvider struct {
	binding                   TreeBinding
	runtimeRoot               *os.Root
	operation, view, identity string
	store                     *statefile.Store
	guard                     func(context.Context) error
}

func ProbeTree(ctx context.Context, path, origin string) (TreeBinding, error) {
	if !storage.ID(origin) {
		return TreeBinding{}, ErrInvalid
	}
	observed, e := volume.Probe(ctx, path)
	if e != nil {
		return TreeBinding{}, e
	}
	return TreeBinding{Format: TreeFormat, Path: path, Observed: observed, Origin: origin}, nil
}
func OpenTreeProvider(ctx context.Context, parent *os.Root, directory, operation, view string, binding TreeBinding, initialize bool, admit statefile.Admission, guard func(context.Context) error) (*TreeProvider, error) {
	if parent == nil || !storage.ID(operation) || !storage.ID(view) || binding.Format != TreeFormat || !storage.ID(binding.Origin) || !filepath.IsAbs(binding.Path) || filepath.Clean(binding.Path) != binding.Path || binding.Observed.RootInode == 0 || binding.Observed.FSID == [2]int32{} {
		return nil, ErrInvalid
	}
	if guard != nil {
		if e := guard(ctx); e != nil {
			return nil, e
		}
	}
	raw, _ := json.Marshal(binding)
	p := &TreeProvider{binding: binding, operation: operation, view: view, identity: storage.Hash(raw), guard: guard}
	var e error
	p.runtimeRoot, e = localfs.OpenAt(parent, ".", false)
	if e != nil {
		return nil, e
	}
	p.store, e = statefile.OpenAt(parent, directory, 4096, initialize)
	if e != nil {
		p.runtimeRoot.Close()
		return nil, e
	}
	p.store.Admit = admit
	e = p.store.WithLock(ctx, func() error {
		_, e := p.load()
		if errors.Is(e, os.ErrNotExist) && initialize {
			raw, _ := json.Marshal(treeState{Format: TreeFormat, Binding: p.identity, Operation: operation, View: view})
			return p.store.Write("view.json", raw)
		}
		return e
	})
	if e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
func (p *TreeProvider) Close() error { return errors.Join(p.store.Close(), p.runtimeRoot.Close()) }
func (p *TreeProvider) load() (treeState, error) {
	var s treeState
	raw, e := p.store.Read("view.json")
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, 4096) != nil || s.Format != TreeFormat || s.Binding != p.identity || s.Operation != p.operation || s.View != p.view {
		return s, ErrInvalid
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(raw, canonical) {
		return s, ErrInvalid
	}
	return s, nil
}
func (p *TreeProvider) Open(ctx context.Context, view string) (*os.Root, error) {
	if view != p.view {
		return nil, ErrInvalid
	}
	var result *os.Root
	e := p.store.WithLock(ctx, func() error {
		if p.guard != nil {
			if e := p.guard(ctx); e != nil {
				return e
			}
		}
		s, e := p.load()
		if e != nil {
			return e
		}
		if s.Released {
			return ErrInvalid
		}
		result, e = localfs.OpenRoot(p.binding.Path)
		if e != nil {
			return e
		}
		current, e := volume.InspectRoot(ctx, result)
		expected := p.binding.Observed
		if e != nil || current.Filesystem != expected.Filesystem || current.FSID != expected.FSID || current.RootInode != expected.RootInode {
			result.Close()
			result = nil
			return ErrInvalid
		}
		if e = localfs.Disjoint(ctx, result, p.runtimeRoot); e != nil {
			result.Close()
			result = nil
			return e
		}
		return ctx.Err()
	})
	if e != nil && result != nil {
		result.Close()
		result = nil
	}
	return result, e
}

// Release drops only this agent's best-effort view lease. It never deletes,
// unmounts or changes the source, and makes no native snapshot-release claim.
func (p *TreeProvider) Release(ctx context.Context, operation, view string) error {
	if operation != p.operation || view != p.view {
		return ErrInvalid
	}
	return p.store.WithLock(ctx, func() error {
		if p.guard != nil {
			if e := p.guard(ctx); e != nil {
				return e
			}
		}
		s, e := p.load()
		if e != nil || s.Released {
			return e
		}
		s.Released = true
		raw, _ := json.Marshal(s)
		if e = p.store.Write("view.json", raw); e != nil {
			return e
		}
		if p.guard != nil {
			return p.guard(ctx)
		}
		return nil
	})
}
