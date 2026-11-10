package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/source"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

const PreparedViewFormat = "outpost-prepared-view-1"

// VerifyingProvider binds the selected plan and final bytes to provider proof.
// Validation runs only before sealing, never during receipt/checkpoint recovery.
type VerifyingProvider interface {
	Provider
	Consistency() string
	Validate(context.Context, string, *os.Root, source.Plan, string) error
}

// LogicalProvider supplies a stable private artifact identity across native
// exports whose filesystem inodes differ. It never supplies an encryption key.
type LogicalProvider interface {
	Lineage(source.Entry) ([]byte, bool, error)
}
type PreparedProviderOptions struct {
	Parent                      *os.Root
	Directory, Operation        string
	Tree                        TreeBinding
	Trust                       PreparedTrust
	Manifest                    []byte
	Initialize                  bool
	Admission                   statefile.Admission
	ReleaseObservationAdmission statefile.Admission
	Guard                       func(context.Context) error
	Fault                       func(string) error
}
type preparedViewState struct {
	Format    string          `json:"format"`
	Binding   string          `json:"binding"`
	Operation string          `json:"operation"`
	Manifest  json.RawMessage `json:"manifest"`
	Released  bool            `json:"released"`
}
type PreparedProvider struct {
	o       PreparedProviderOptions
	binding string
	store   *statefile.Store
	runtime *os.Root
}

func OpenPreparedProvider(ctx context.Context, o PreparedProviderOptions) (*PreparedProvider, error) {
	if o.Parent == nil || !storage.ID(o.Operation) || o.Trust.validate() != nil || o.Tree.Format != TreeFormat || o.Tree.Origin != o.Trust.Origin || !filepath.IsAbs(o.Tree.Path) || filepath.Clean(o.Tree.Path) != o.Tree.Path || o.Tree.Observed.RootInode == 0 || o.Tree.Observed.FSID == [2]int32{} || len(o.Manifest) > MaxPreparedExport || o.Initialize && len(o.Manifest) == 0 {
		return nil, ErrInvalid
	}
	if len(o.Manifest) != 0 {
		if storage.Hash(o.Manifest) != o.Operation {
			return nil, ErrInvalid
		}
		if _, e := VerifyPreparedExport(o.Manifest, o.Trust, time.Now()); e != nil {
			return nil, e
		}
	}
	o.Manifest = bytes.Clone(o.Manifest)
	o.Trust.Producer = bytes.Clone(o.Trust.Producer)
	raw, _ := json.Marshal(struct {
		Tree  TreeBinding
		Trust PreparedTrust
	}{o.Tree, o.Trust})
	p := &PreparedProvider{o: o, binding: storage.Hash(raw)}
	if e := p.guard(ctx); e != nil {
		return nil, e
	}
	if o.Initialize {
		sourceRoot, e := localfs.OpenRoot(o.Tree.Path)
		if e != nil {
			return nil, e
		}
		current, e := volume.InspectRoot(ctx, sourceRoot)
		expected := o.Tree.Observed
		if e == nil && (current.Filesystem != expected.Filesystem || current.FSID != expected.FSID || current.RootInode != expected.RootInode) {
			e = ErrInvalid
		}
		if e == nil {
			e = localfs.Disjoint(ctx, sourceRoot, o.Parent)
		}
		sourceRoot.Close()
		if e != nil {
			return nil, e
		}
	}
	var e error
	p.runtime, e = localfs.OpenAt(o.Parent, ".", false)
	if e != nil {
		return nil, e
	}
	p.store, e = statefile.OpenAt(o.Parent, o.Directory, MaxPreparedExport+8192, o.Initialize)
	if e != nil {
		p.runtime.Close()
		return nil, e
	}
	p.store.Admit = o.Admission
	e = p.store.WithLock(ctx, func() error {
		s, e := p.load()
		if errors.Is(e, os.ErrNotExist) && o.Initialize {
			s = preparedViewState{Format: PreparedViewFormat, Binding: p.binding, Operation: o.Operation, Manifest: o.Manifest}
			if e = p.save(ctx, s); e != nil {
				return e
			}
			return p.point("prepared-view-durable")
		}
		if e != nil {
			return e
		}
		if len(o.Manifest) != 0 && !bytes.Equal(s.Manifest, o.Manifest) {
			return ErrInvalid
		}
		return p.guard(ctx)
	})
	if e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
func (p *PreparedProvider) Close() error        { return errors.Join(p.store.Close(), p.runtime.Close()) }
func (p *PreparedProvider) Consistency() string { return p.o.Trust.Consistency() }
func (p *PreparedProvider) Lineage(entry source.Entry) ([]byte, bool, error) {
	if entry.Identity.Kind() != "regular" {
		return nil, false, nil
	}
	if len(entry.Names) != 1 || !preparedName(entry.Names[0], false) {
		return nil, false, ErrInvalid
	}
	raw, e := json.Marshal(struct{ Format, Binding, Name string }{PreparedViewFormat + "/logical-artifact", p.binding, entry.Names[0]})
	return raw, true, e
}
func (p *PreparedProvider) guard(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if p.o.Guard != nil {
		return p.o.Guard(ctx)
	}
	return nil
}
func (p *PreparedProvider) point(name string) error {
	if p.o.Fault != nil {
		return p.o.Fault(name)
	}
	return nil
}
func (p *PreparedProvider) load() (preparedViewState, error) {
	var s preparedViewState
	raw, e := p.store.Read("view.json")
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, MaxPreparedExport+8192) != nil || s.Format != PreparedViewFormat || s.Binding != p.binding || s.Operation != p.o.Operation || storage.Hash(s.Manifest) != s.Operation {
		return s, ErrInvalid
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(canonical, raw) {
		return s, ErrInvalid
	}
	if _, e = VerifyPreparedExport(s.Manifest, p.o.Trust, time.Now()); e != nil {
		return s, e
	}
	return s, nil
}
func (p *PreparedProvider) save(ctx context.Context, s preparedViewState) error {
	if e := p.guard(ctx); e != nil {
		return e
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if e = p.store.Write("view.json", raw); e != nil {
		return e
	}
	return p.guard(ctx)
}
func (p *PreparedProvider) open(ctx context.Context, s preparedViewState) (*os.Root, source.Plan, error) {
	var empty source.Plan
	if s.Released {
		return nil, empty, ErrInvalid
	}
	parent, e := localfs.OpenRoot(p.o.Tree.Path)
	if e != nil {
		return nil, empty, e
	}
	defer parent.Close()
	current, e := volume.InspectRoot(ctx, parent)
	expected := p.o.Tree.Observed
	if e != nil || current.Filesystem != expected.Filesystem || current.FSID != expected.FSID || current.RootInode != expected.RootInode {
		return nil, empty, ErrInvalid
	}
	if e = localfs.Disjoint(ctx, parent, p.runtime); e != nil {
		return nil, empty, e
	}
	return OpenPreparedExport(ctx, parent, s.Manifest, p.o.Trust, time.Now())
}
func (p *PreparedProvider) Open(ctx context.Context, view string) (*os.Root, error) {
	if view != p.o.Operation {
		return nil, ErrInvalid
	}
	var root *os.Root
	e := p.store.WithLock(ctx, func() error {
		if e := p.guard(ctx); e != nil {
			return e
		}
		s, e := p.load()
		if e != nil {
			return e
		}
		root, _, e = p.open(ctx, s)
		if e != nil {
			return e
		}
		return p.guard(ctx)
	})
	if e != nil && root != nil {
		root.Close()
		root = nil
	}
	return root, e
}
func (p *PreparedProvider) Validate(ctx context.Context, view string, root *os.Root, selected source.Plan, domain string) error {
	if view != p.o.Operation || root == nil || !storage.ID(domain) {
		return ErrInvalid
	}
	return p.store.WithLock(ctx, func() error {
		if e := p.guard(ctx); e != nil {
			return e
		}
		s, e := p.load()
		if e != nil {
			return e
		}
		checked, proof, e := p.open(ctx, s)
		if e != nil {
			return e
		}
		defer checked.Close()
		identity, e := filekit.InspectEntry(root, ".")
		if e != nil {
			return e
		}
		if identity != proof.Root || selected.Root != proof.Root || selected.Excluded != 0 || selected.SourceBytes != proof.SourceBytes || len(selected.Observed) != len(proof.Observed) || len(selected.Entries) != len(proof.Entries) {
			return ErrInvalid
		}
		for name, id := range proof.Observed {
			if selected.Observed[name] != id {
				return ErrInvalid
			}
		}
		entries := map[string]filekit.SourceIdentity{}
		for _, entry := range proof.Entries {
			if len(entry.Names) != 1 {
				return ErrInvalid
			}
			entries[entry.Names[0]] = entry.Identity
		}
		for _, entry := range selected.Entries {
			if entry.Domain != domain || len(entry.Names) != 1 || entries[entry.Names[0]] != entry.Identity {
				return ErrInvalid
			}
			delete(entries, entry.Names[0])
		}
		if len(entries) != 0 {
			return ErrInvalid
		}
		if e = selected.Recheck(ctx, root); e != nil {
			return e
		}
		return p.guard(ctx)
	})
}

// Release acknowledges only this consumer lease. It never accesses, unlinks or
// changes the producer's export. Producer retention/cleanup remains independent.
func (p *PreparedProvider) Release(ctx context.Context, operation, view string) error {
	if operation != p.o.Operation || view != operation {
		return ErrInvalid
	}
	return p.store.WithLock(ctx, func() error {
		if e := p.guard(ctx); e != nil {
			return e
		}
		s, e := p.load()
		if e != nil || s.Released {
			return e
		}
		s.Released = true
		if e = p.save(ctx, s); e != nil {
			return e
		}
		recordReleaseObservation(p.runtime, p.o.Operation, p.store, p.o.ReleaseObservationAdmission)
		return p.point("prepared-view-released")
	})
}
