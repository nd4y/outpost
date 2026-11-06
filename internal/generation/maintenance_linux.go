package generation

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Maintain verifies a revision-bound deletion permit, then independently checks
// latest-complete, explicit pins and all complete/receiving object references.
// Retire and GC are replayable: a crash may leave extra bytes, never a dangling
// protected root. Revision zero is valid only for the initial empty replica.
func (r *Replica) Maintain(ctx context.Context, raw []byte) (int, error) {
	p, e := verifyPermit(raw, r.trust)
	if e != nil {
		return 0, e
	}
	operation := Hash(raw)
	removed := 0
	e = r.locked(ctx, func(s *state) error {
		previous, replay := s.Receipts[p.Operation]
		if replay && previous != operation {
			return ErrConflict
		}
		if !replay && p.Revision != s.Revision {
			return ErrRollback
		}
		if !replay && len(s.Receipts) >= MaxPins {
			return ErrInvalid
		}
		if !replay {
			for _, id := range p.Retire {
				if _, ok := s.Generations[id]; !ok {
					return ErrInvalid
				}
				if id == s.Latest {
					return ErrProtected
				}
				for _, pin := range s.Pins {
					if pin.Generation == id {
						return ErrProtected
					}
				}
			}
		}
		// Validate *all* current complete roots before retiring any of them.
		keep := map[string]Object{}
		retiring := map[string]bool{}
		if !replay {
			for _, id := range p.Retire {
				retiring[id] = true
			}
		}
		for id, item := range s.Generations {
			_, refs, e := get(s, id, r.trust)
			if e != nil {
				return e
			}
			for key, ref := range refs {
				if e = ctx.Err(); e != nil {
					return e
				}
				if item.Complete {
					if _, e = r.object(ref); e != nil {
						return ErrIncomplete
					}
				}
				if !retiring[id] {
					if old, ok := keep[key]; ok && old != ref {
						return ErrInvalid
					}
					keep[key] = ref
				}
			}
		}
		f, e := r.root.Open("objects")
		if e != nil {
			return e
		}
		entries, e := f.ReadDir(MaxObjects*4 + 1)
		f.Close()
		if (e != nil && !errors.Is(e, io.EOF)) || len(entries) > MaxObjects*4 {
			return ErrInvalid
		}
		var garbage []string
		for _, item := range entries {
			if !item.Type().IsRegular() || !validID(item.Name()) {
				return ErrInvalid
			}
			info, e := item.Info()
			if e != nil {
				return e
			}
			if info.Size() < 1 || info.Size() > MaxObject {
				return ErrInvalid
			}
			if ref, ok := keep[item.Name()]; ok {
				if int64(ref.Bytes) != info.Size() {
					return ErrIncomplete
				}
			} else {
				garbage = append(garbage, item.Name())
			}
		}
		if !replay {
			for id := range retiring {
				delete(s.Generations, id)
			}
			s.Receipts[p.Operation] = operation
			s.Revision++
			if e = r.save(*s); e != nil {
				return e
			}
		}
		if e = r.point("retirement-durable"); e != nil {
			return e
		}
		for _, id := range garbage {
			if e = ctx.Err(); e != nil {
				return e
			}
			if e = r.root.Remove("objects/" + id); e != nil {
				return e
			}
			removed++
			if e = r.point("gc-object-removed"); e != nil {
				return e
			}
		}
		return syncDir(r.root, "objects")
	})
	return removed, e
}

// ExportKit copies a single complete file kit while maintenance is excluded.
// This creates independent inodes and atomically publishes a new directory;
// it requires neither a repository key nor a running source/control plane.
func (r *Replica) ExportKit(ctx context.Context, generation, version, destination string) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return ErrInvalid
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(destination))
	if e != nil {
		return e
	}
	destination = filepath.Join(parent, filepath.Base(destination))
	source, e := filepath.EvalSymlinks(r.root.Name())
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(source, destination)
	if e != nil || rel == "." || !(rel == ".." || len(rel) > 3 && rel[:3] == ".."+string(os.PathSeparator)) {
		return ErrInvalid
	}
	return r.locked(ctx, func(s *state) error {
		c, _, e := get(s, generation, r.trust)
		if e != nil {
			return e
		}
		if !s.Generations[generation].Complete {
			return ErrIncomplete
		}
		var selected *Kit
		for i := range c.Kits {
			if c.Kits[i].Version == version {
				if selected != nil {
					return ErrInvalid
				}
				selected = &c.Kits[i]
			}
		}
		if selected == nil {
			return ErrInvalid
		}
		stage, e := os.MkdirTemp(parent, ".outpost-kit-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(stage)
		out, e := os.OpenRoot(stage)
		if e != nil {
			return e
		}
		defer out.Close()
		for _, name := range []string{".txn", "objects"} {
			if e = out.Mkdir(name, 0700); e != nil {
				return e
			}
		}
		for _, ref := range selected.Objects {
			if e = ctx.Err(); e != nil {
				return e
			}
			b, e := r.object(ref)
			if e != nil {
				return ErrIncomplete
			}
			dir := "objects/" + ref.ID[:2]
			if e = out.MkdirAll(dir, 0700); e != nil {
				return e
			}
			if e = atomic(out, dir+"/"+ref.ID, b); e != nil {
				return e
			}
		}
		b, e := r.object(selected.Root)
		if e != nil {
			return ErrIncomplete
		}
		if e = atomic(out, "kit.json", b); e != nil {
			return e
		}
		if e = syncDir(out, "objects"); e != nil {
			return e
		}
		if e = out.Remove(".txn"); e != nil {
			return e
		}
		if e = syncDir(out, "."); e != nil {
			return e
		}
		if e = r.point("export-before-publish"); e != nil {
			return e
		}
		if e = unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); e != nil {
			return e
		}
		parentRoot, e := os.OpenRoot(parent)
		if e != nil {
			return e
		}
		defer parentRoot.Close()
		return syncDir(parentRoot, ".")
	})
}
