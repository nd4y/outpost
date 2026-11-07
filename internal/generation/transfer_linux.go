package generation

import (
	"context"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"os"
)

// CheckRecoveryDestination prevents a trusted executor from placing plaintext
// inside its ciphertext replica, or making that replica part of its output tree.
func (r *Replica) CheckRecoveryDestination(ctx context.Context, destination *os.Root) error {
	return localfs.Disjoint(ctx, r.root, destination)
}

// Trust returns public verification material only, detached from mutable state.
func (r *Replica) Trust() Trust {
	t := r.trust
	t.Writer = append([]byte(nil), t.Writer...)
	t.Maintenance = append([]byte(nil), t.Maintenance...)
	return t
}

// Dependencies validates the catalog before exposing its complete opaque closure.
func Dependencies(raw []byte, trust Trust) ([]Object, error) {
	c, err := VerifyCatalog(raw, trust)
	if err != nil {
		return nil, err
	}
	refs, err := closure(c)
	if err != nil {
		return nil, err
	}
	objects := make([]Object, 0, len(refs))
	for _, id := range sortedIDs(refs) {
		objects = append(objects, refs[id])
	}
	return objects, nil
}

// Missing reports absent objects of an accepted reception. Existing corrupt
// objects fail closed rather than being silently overwritten by a transfer.
func (r *Replica) Missing(ctx context.Context, id string) ([]Object, error) {
	return r.missing(ctx, id, false)
}

// MissingMetadata reports presence only, for protocols that subsequently
// require VerifyWindow. It never certifies hashes or publishes COMPLETE.
func (r *Replica) MissingMetadata(ctx context.Context, id string) ([]Object, error) {
	return r.missing(ctx, id, true)
}
func (r *Replica) missing(ctx context.Context, id string, metadataOnly bool) ([]Object, error) {
	missing := []Object{}
	err := r.locked(ctx, func(s *state) error {
		_, refs, err := r.get(s, id, true)
		if err != nil {
			return err
		}
		for _, key := range sortedIDs(refs) {
			if err = ctx.Err(); err != nil {
				return err
			}
			if metadataOnly {
				_, err = r.objectStamp(refs[key])
			} else {
				_, err = r.object(refs[key])
			}
			if errors.Is(err, os.ErrNotExist) {
				missing = append(missing, refs[key])
			} else if err != nil {
				return err
			}
		}
		return nil
	})
	return missing, err
}

// VerifyComplete is read-only. A status query must never publish an unfinished
// reception, even when its last object has arrived.
func (r *Replica) VerifyComplete(ctx context.Context, id string) error {
	return r.locked(ctx, func(s *state) error {
		if !s.Generations[id].Complete || s.Generations[id].Damaged {
			return ErrIncomplete
		}
		_, refs, err := r.get(s, id, true)
		if err != nil {
			return err
		}
		for _, key := range sortedIDs(refs) {
			if err = ctx.Err(); err != nil {
				return err
			}
			if _, err = r.object(refs[key]); err != nil {
				return ErrIncomplete
			}
		}
		return nil
	})
}
