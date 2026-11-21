package filekit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const MaxRecoveryKits = 4096

// RecoveryKit is selected by exact opaque version; no latest-version fallback.
type RecoveryKit struct {
	Version string
	Root    []byte
}
type ObjectReader func(context.Context, Object) ([]byte, error)
type RecoverySummary struct {
	Files               int   `json:"files"`
	Directories         int   `json:"directories"`
	Symlinks            int   `json:"symlinks"`
	Aliases             int   `json:"aliases"`
	Bytes               int64 `json:"bytes"`
	ImplicitDirectories int   `json:"implicitDirectories"`
}
type readOnlyBackend struct{ read ObjectReader }

func (b readOnlyBackend) Read(ctx context.Context, o Object) ([]byte, error) { return b.read(ctx, o) }
func (readOnlyBackend) Write(context.Context, Object, []byte) (bool, error) {
	return false, ErrRemoteMaintenance
}
func (readOnlyBackend) Check(context.Context, Object) error { return ErrRemoteMaintenance }

// RecoverSet reads only the supplied signed envelopes and their ciphertext.
// It needs no source store, global index, worker journal or running service.
// All names/types are checked before creating output; directory metadata is
// applied last and destination publication is an atomic no-overwrite rename.
func RecoverSet(ctx context.Context, owner Owner, kits []RecoveryKit, read ObjectReader, dest string) (RecoverySummary, error) {
	return recoverSet(ctx, owner, kits, read, "", dest)
}

// RecoverDirectory selects only authenticated names at or below relative.
// Hardlink aliases outside that selection are not created in the output.
func RecoverDirectory(ctx context.Context, owner Owner, kits []RecoveryKit, read ObjectReader, relative, dest string) (RecoverySummary, error) {
	if !safeName(relative) {
		return RecoverySummary{}, ErrInvalid
	}
	return recoverSet(ctx, owner, kits, read, relative, dest)
}
func loadRecoveryDescriptors(ctx context.Context, owner Owner, kits []RecoveryKit, read ObjectReader, directory string) ([]Descriptor, error) {
	if e := owner.validate(); e != nil {
		return nil, e
	}
	if read == nil || len(kits) == 0 || len(kits) > MaxRecoveryKits {
		return nil, ErrInvalid
	}
	s := &Store{Owner: owner, backend: readOnlyBackend{read: read}}
	var descriptors []Descriptor
	seen := map[string]bool{}
	size := 0
	for _, k := range kits {
		size += len(k.Root)
		if size > MaxDescriptor {
			return nil, ErrInvalid
		}
		_, d, e := s.loadEnvelope(ctx, k.Root, k.Version)
		if e != nil {
			return nil, e
		}
		if seen[d.File] {
			return nil, ErrInvalid
		}
		seen[d.File] = true
		b, e := json.Marshal(d)
		if e != nil {
			return nil, e
		}
		size += len(b)
		if size > MaxDescriptor {
			return nil, ErrInvalid
		}
		if directory != "" {
			var selected []string
			for _, n := range d.Names {
				if n == directory || strings.HasPrefix(n, directory+"/") {
					selected = append(selected, n)
				}
			}
			if len(selected) == 0 {
				continue
			}
			d.Names = selected
		}
		descriptors = append(descriptors, d)
	}
	if len(descriptors) == 0 {
		return nil, os.ErrNotExist
	}
	return descriptors, nil
}

// PlanRecovery authenticates selection metadata and names before any plaintext
// output. Counts are an admission estimate, not a content verification receipt.
func PlanRecovery(ctx context.Context, owner Owner, kits []RecoveryKit, read ObjectReader, directory string) (RecoverySummary, error) {
	if directory != "" && !safeName(directory) {
		return RecoverySummary{}, ErrInvalid
	}
	ds, e := loadRecoveryDescriptors(ctx, owner, kits, read, directory)
	if e != nil {
		return RecoverySummary{}, e
	}
	summary, _, e := validateSet(ds)
	return summary, e
}

func recoverSet(ctx context.Context, owner Owner, kits []RecoveryKit, read ObjectReader, directory, dest string) (RecoverySummary, error) {
	ds, e := loadRecoveryDescriptors(ctx, owner, kits, read, directory)
	if e != nil {
		return RecoverySummary{}, e
	}
	s := &Store{Owner: owner, backend: readOnlyBackend{read: read}}
	return s.restoreSet(ctx, ds, dest)
}

// RecoverSetAt retains the caller's admitted parent descriptor across writes
// and publication. Remote commands supply no absolute destination path.
func RecoverSetAt(ctx context.Context, owner Owner, kits []RecoveryKit, read ObjectReader, directory string, parent *os.Root, name string) (RecoverySummary, error) {
	if parent == nil || !safeName(name) || strings.Contains(name, "/") {
		return RecoverySummary{}, ErrInvalid
	}
	if directory != "" && !safeName(directory) {
		return RecoverySummary{}, ErrInvalid
	}
	ds, e := loadRecoveryDescriptors(ctx, owner, kits, read, directory)
	if e != nil {
		return RecoverySummary{}, e
	}
	s := &Store{Owner: owner, backend: readOnlyBackend{read: read}}
	return s.restoreSetAt(ctx, ds, parent, name)
}

func validateSet(ds []Descriptor) (RecoverySummary, []string, error) {
	var summary RecoverySummary
	names := map[string]string{}
	dirs := map[string]bool{}
	if len(ds) == 0 || len(ds) > MaxRecoveryKits {
		return summary, nil, ErrInvalid
	}
	for _, d := range ds {
		if e := validateDescriptor(d); e != nil {
			return summary, nil, e
		}
		switch d.Kind {
		case "":
			summary.Files++
			summary.Bytes += d.Size
		case "directory":
			summary.Directories++
		case "symlink":
			summary.Symlinks++
		}
		summary.Aliases += len(d.Names) - 1
		for _, n := range d.Names {
			if _, exists := names[n]; exists {
				return summary, nil, ErrInvalid
			}
			names[n] = d.Kind
			if len(names) > 32768 {
				return summary, nil, ErrInvalid
			}
			if d.Kind == "directory" {
				dirs[n] = true
			}
		}
	}
	for n := range names {
		for p := path.Dir(n); p != "."; p = path.Dir(p) {
			if kind, exists := names[p]; exists && kind != "directory" {
				return summary, nil, ErrInvalid
			}
			dirs[p] = true
			if len(dirs) > 32768 {
				return summary, nil, ErrInvalid
			}
		}
	}
	if len(dirs) > 32768 {
		return summary, nil, ErrInvalid
	}
	ordered := make([]string, 0, len(dirs))
	for n := range dirs {
		ordered = append(ordered, n)
		if _, explicit := names[n]; !explicit {
			summary.ImplicitDirectories++
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := strings.Count(ordered[i], "/"), strings.Count(ordered[j], "/")
		if a != b {
			return a < b
		}
		return ordered[i] < ordered[j]
	})
	return summary, ordered, nil
}
func (s *Store) restoreSet(ctx context.Context, ds []Descriptor, dest string) (RecoverySummary, error) {
	if !filepath.IsAbs(dest) || filepath.Clean(dest) != dest || path.Base(dest) == "/" {
		return RecoverySummary{}, ErrInvalid
	}
	parent, e := os.OpenRoot(path.Dir(dest))
	if e != nil {
		return RecoverySummary{}, e
	}
	defer parent.Close()
	return s.restoreSetAt(ctx, ds, parent, path.Base(dest))
}

func (s *Store) restoreSetAt(ctx context.Context, ds []Descriptor, parent *os.Root, name string) (summary RecoverySummary, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	if parent == nil || !safeName(name) || strings.Contains(name, "/") {
		return summary, ErrInvalid
	}
	summary, dirs, err := validateSet(ds)
	if err != nil {
		return summary, err
	}
	if _, err = parent.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = os.ErrExist
		}
		return summary, err
	}
	tmp := ".outpost-restore-" + randomID()
	if err = parent.Mkdir(tmp, 0700); err != nil {
		return summary, err
	}
	finished := false
	out, err := parent.OpenRoot(tmp)
	if err != nil {
		_ = parent.Remove(tmp)
		return summary, err
	}
	defer func() {
		if !finished {
			// A recorded 000 directory must not prevent removing our own failed
			// staging output. These paths were validated as directories above.
			for _, d := range dirs {
				_ = out.Chmod(d, 0700)
			}
		}
		_ = out.Close()
		if !finished {
			err = errors.Join(err, parent.RemoveAll(tmp))
		}
	}()
	for _, d := range dirs {
		if err = ctx.Err(); err != nil {
			return summary, err
		}
		if err = out.Mkdir(d, 0700); err != nil {
			return summary, err
		}
	}
	for _, d := range ds {
		if err = ctx.Err(); err != nil {
			return summary, err
		}
		switch d.Kind {
		case "":
			err = s.restoreRegular(ctx, out, d)
		case "symlink":
			err = restoreSpecial(out, d)
		}
		if err != nil {
			return summary, err
		}
	}
	metadata := map[string]Metadata{}
	for _, d := range ds {
		if d.Kind == "directory" {
			metadata[d.Names[0]] = d.Metadata
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err = ctx.Err(); err != nil {
			return summary, err
		}
		f, e := out.OpenFile(dirs[i], os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return summary, e
		}
		if m, ok := metadata[dirs[i]]; ok {
			e = applyMetadata(f, m)
		} else {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return summary, e
		}
		if ce != nil {
			return summary, ce
		}
	}
	f, err := out.Open(".")
	if err != nil {
		return summary, err
	}
	err = f.Sync()
	ce := f.Close()
	if err != nil {
		return summary, err
	}
	if ce != nil {
		return summary, ce
	}
	if err = s.checkpoint("restore-verified"); err != nil {
		return summary, err
	}
	if err = ctx.Err(); err != nil {
		return summary, err
	}
	p, err := parent.Open(".")
	if err != nil {
		return summary, err
	}
	defer p.Close()
	if err = unix.Renameat2(int(p.Fd()), tmp, int(p.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return summary, err
	}
	finished = true
	return summary, p.Sync()
}
