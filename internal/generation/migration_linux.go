package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/statefile"
)

type legacyEntry struct {
	Catalog  json.RawMessage `json:"catalog"`
	Complete bool            `json:"complete"`
}
type legacyState struct {
	Format          string                 `json:"format"`
	Trust           Trust                  `json:"trust"`
	Revision        uint64                 `json:"revision"`
	HighestSequence uint64                 `json:"highestSequence"`
	HighestID       string                 `json:"highestId"`
	Latest          string                 `json:"latestComplete"`
	Generations     map[string]legacyEntry `json:"generations"`
	Pins            map[string]Pin         `json:"pins"`
	Receipts        map[string]string      `json:"maintenanceReceipts"`
}

func migrationReplica(dir string, t Trust, admit statefile.Admission) (*Replica, error) {
	if !filepath.IsAbs(dir) || !t.valid() {
		return nil, ErrInvalid
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	return &Replica{root: root, trust: t, Admit: admit}, nil
}
func (r *Replica) legacy(raw []byte) (legacyState, state, error) {
	var old legacyState
	if e := canonical(raw, &old, MaxState); e != nil {
		return old, state{}, e
	}
	if old.Format != Format || old.Generations == nil {
		return old, state{}, ErrInvalid
	}
	s := state{Format: StateFormat, Trust: old.Trust, Revision: old.Revision, HighestSequence: old.HighestSequence, HighestID: old.HighestID, Latest: old.Latest, Generations: map[string]entry{}, Pins: old.Pins, Receipts: old.Receipts}
	for id, item := range old.Generations {
		c, e := VerifyCatalog(item.Catalog, r.trust)
		if e != nil || id != Hash(item.Catalog) {
			return old, s, ErrInvalid
		}
		s.Generations[id] = entry{Sequence: c.Sequence, Bytes: len(item.Catalog), Complete: item.Complete}
	}
	s, e := r.validateState(s)
	return old, s, e
}
func (r *Replica) verifyLegacyPayload(ctx context.Context, old legacyState) error {
	for _, item := range old.Generations {
		if !item.Complete {
			continue
		}
		c, e := VerifyCatalog(item.Catalog, r.trust)
		if e != nil {
			return e
		}
		refs, e := closure(c)
		if e != nil {
			return e
		}
		for _, ref := range refs {
			if e = ctx.Err(); e != nil {
				return e
			}
			if _, e = r.object(ref); e != nil {
				return ErrIncomplete
			}
		}
	}
	return nil
}

// MigrateLocal explicitly upgrades only local replica metadata. Wire catalogs,
// encrypted objects and file kits retain their formats. The v1 state is copied
// durably before any v2 publication. An interruption can leave extra catalogs;
// the previous state remains usable until the atomic final switch.
func MigrateLocal(ctx context.Context, dir string, t Trust, admit statefile.Admission) error {
	return migrateLocal(ctx, dir, t, admit, nil)
}
func migrateLocal(ctx context.Context, dir string, t Trust, admit statefile.Admission, fault func(string) error) error {
	r, e := migrationReplica(dir, t, admit)
	if e != nil {
		return e
	}
	defer r.Close()
	r.Fault = fault
	return r.exclusive(ctx, func() error {
		raw, e := read(r.root, "state.json", MaxState)
		if e != nil {
			return e
		}
		if s, err := r.load(); err == nil {
			for id := range s.Generations {
				if _, _, err = r.get(&s, id, true); err != nil {
					return err
				}
			}
			return nil
		} else if !errors.Is(err, ErrMigrationRequired) {
			return err
		}
		old, s, e := r.legacy(raw)
		if e != nil {
			return e
		}
		if e = r.verifyLegacyPayload(ctx, old); e != nil {
			return e
		}
		previous, e := read(r.root, "state.v1.json", MaxState)
		if e == nil {
			if !bytes.Equal(previous, raw) {
				return ErrConflict
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else if e = r.write("state.v1.json", raw); e != nil {
			return e
		}
		if e = r.point("migration-backup-durable"); e != nil {
			return e
		}
		if e = r.root.Mkdir("catalogs", 0700); e != nil && !os.IsExist(e) {
			return e
		}
		info, e := r.root.Lstat("catalogs")
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if e = syncDir(r.root, "."); e != nil {
			return e
		}
		for _, id := range sortedIDs(old.Generations) {
			if e = ctx.Err(); e != nil {
				return e
			}
			if e = r.putCatalog(id, old.Generations[id].Catalog); e != nil {
				return e
			}
		}
		if e = r.point("migration-before-switch"); e != nil {
			return e
		}
		return r.save(s)
	})
}

// RollbackLocal is permitted only before any v2 state change. The retained
// backup is not a perpetual recovery root or an authorization to discard new
// generations, pins or maintenance receipts. Payload is reverified first.
func RollbackLocal(ctx context.Context, dir string, t Trust, admit statefile.Admission) error {
	r, e := migrationReplica(dir, t, admit)
	if e != nil {
		return e
	}
	defer r.Close()
	return r.exclusive(ctx, func() error {
		raw, e := read(r.root, "state.v1.json", MaxState)
		if e != nil {
			return e
		}
		old, expected, e := r.legacy(raw)
		if e != nil {
			return e
		}
		current, e := read(r.root, "state.json", MaxState)
		if e != nil {
			return e
		}
		if bytes.Equal(raw, current) {
			return r.verifyLegacyPayload(ctx, old)
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		a, _ := json.Marshal(s)
		b, _ := json.Marshal(expected)
		if !bytes.Equal(a, b) {
			return ErrProtected
		}
		for id := range s.Generations {
			if _, _, e = r.get(&s, id, true); e != nil {
				return e
			}
		}
		if e = r.verifyLegacyPayload(ctx, old); e != nil {
			return e
		}
		return r.write("state.json", raw)
	})
}
