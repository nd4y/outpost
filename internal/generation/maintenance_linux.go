package generation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Maintain verifies a revision-bound deletion permit, then independently checks
// latest-complete, explicit pins and all complete/receiving object references.
// Retire and GC are replayable: a crash may leave extra bytes, never a dangling
// protected root. Revision zero is valid only for the initial empty replica.
func (r *Replica) Maintain(ctx context.Context, raw []byte) (int, error) {
	return r.MaintainAdmitted(ctx, raw, nil)
}

// MaintainAdmitted rechecks short caller admission before retirement and each
// destructive step. The caller must cancel and join it before acknowledging a
// hold or policy replacement. Admission must not re-enter this replica.
func (r *Replica) MaintainAdmitted(ctx context.Context, raw []byte, admit func() error) (int, error) {
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if admit != nil {
			return admit()
		}
		return nil
	}
	if e := check(); e != nil {
		return 0, e
	}
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
		record, frozen := s.GC[p.Operation]
		if replay && !frozen {
			// A legacy receipt has no durable candidate set. It cannot authorize
			// a new scan; a newly signed revision-bound permit is required.
			return ErrMigrationRequired
		}
		if replay && record.Result != nil {
			return nil
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
		if len(s.CatalogDamage) > 0 {
			return ErrCatalogUnavailable
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
			_, refs, e := r.get(s, id, true)
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
		plan, digest, e := r.gcPlan(ctx, p, operation, record.Plan, keep, retiring, s)
		if e != nil {
			return e
		}
		if !replay {
			// Persist the signed authority before removing its catalogs. A crash
			// can retain extra data, but cannot lose the retirement tombstone.
			if e = check(); e != nil {
				return e
			}
			if e = r.recordRetirement(s, raw); e != nil {
				return e
			}
			for id := range retiring {
				delete(s.Generations, id)
			}
			s.Receipts[p.Operation] = operation
			if s.GC == nil {
				s.GC = map[string]gcRecord{}
			}
			s.GC[p.Operation] = gcRecord{Plan: digest}
			if !integrityState(s.Format) {
				s.Format = MaintenanceStateFormat
			}
			s.Revision++
			if e = r.save(*s); e != nil {
				return e
			}
		}
		if e = r.point("retirement-durable"); e != nil {
			return e
		}
		result := MaintenanceReceipt{Operation: p.Operation, Permit: operation, CandidateObjects: len(plan.Objects), CandidateCatalogs: len(plan.Catalogs)}
		for _, ref := range plan.Objects {
			if e = check(); e != nil {
				return e
			}
			if _, protected := keep[ref.ID]; protected {
				result.ProtectedObjects++
				continue
			}
			// Do not erase replacement/corrupt bytes under an old object name.
			if _, e = r.object(ref); errors.Is(e, os.ErrNotExist) {
				result.AbsentObjects++
				continue
			} else if e != nil {
				return e
			}
			if e = r.root.Remove("objects/" + ref.ID); e != nil {
				return e
			}
			result.AbsentObjects++
			removed++
			if e = r.point("gc-object-removed"); e != nil {
				return e
			}
		}
		if e = syncDir(r.root, "objects"); e != nil {
			return e
		}
		for _, id := range plan.Catalogs {
			if e = check(); e != nil {
				return e
			}
			if _, protected := s.Generations[id]; protected {
				result.ProtectedCatalogs++
				continue
			}
			raw, e := read(r.root, "catalogs/"+id, MaxCatalog)
			if errors.Is(e, os.ErrNotExist) {
				result.AbsentCatalogs++
				continue
			}
			if e != nil {
				return e
			}
			if Hash(raw) != id {
				return ErrIncomplete
			}
			if _, e = VerifyCatalog(raw, r.trust); e != nil {
				return e
			}
			if e = r.root.Remove("catalogs/" + id); e != nil {
				return e
			}
			result.AbsentCatalogs++
		}
		if e = syncDir(r.root, "catalogs"); e != nil {
			return e
		}
		result.CompletedUnix = time.Now().Unix()
		record = s.GC[p.Operation]
		record.Result = &result
		s.GC[p.Operation] = record
		s.Revision++
		if e = r.save(*s); e != nil {
			return e
		}
		return r.point("gc-result-durable")
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
		c, _, e := r.get(s, generation, true)
		if e != nil {
			return e
		}
		if !s.Generations[generation].Complete || s.Generations[generation].Damaged {
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
