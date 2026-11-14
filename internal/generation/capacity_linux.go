package generation

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/statefile"
)

type PublicationWrites struct {
	ObjectSizes   []int
	MetadataSizes []int
}

// EstimatePublication sizes a signed catalog and its verified unique closure.
// Object presence is a space observation. Publication verifies every digest.
func (r *Replica) EstimatePublication(ctx context.Context, raw []byte, refs []Object) (PublicationWrites, error) {
	id := Hash(raw)
	var writes PublicationWrites
	err := r.exclusive(ctx, func() error {
		s, err := r.load()
		if err != nil {
			return err
		}
		item, exists := s.Generations[id]
		if !exists {
			if len(s.Generations) >= MaxGenerations {
				return statefile.ErrCapacity
			}
			writes.MetadataSizes = append(writes.MetadataSizes, len(raw))
		}
		index, err := json.Marshal(s)
		if err != nil {
			return err
		}
		// The index gains one generation, one pin, and a new head. Its
		// atomic replacement coexists with the currently charged index.
		const indexGrowth = 512
		if len(index)+indexGrowth > MaxState {
			return statefile.ErrCapacity
		}
		writes.MetadataSizes = append(writes.MetadataSizes, len(index)+indexGrowth)
		if exists && item.Complete && !item.Damaged {
			return nil
		}
		var checkpoint verificationState
		if _, damaged := s.CatalogDamage[id]; exists && !item.Damaged && !damaged {
			dependencies := make(map[string]Object, len(refs))
			for _, ref := range refs {
				dependencies[ref.ID] = ref
			}
			if saved, _, err := r.verification(id, "", dependencies); err == nil {
				checkpoint = saved
			}
		}
		reuseCheckpoint := checkpoint.CompletedAt > 0
		for _, ref := range refs {
			if err := ctx.Err(); err != nil {
				return err
			}
			stamp, err := r.objectStamp(ref)
			if errors.Is(err, os.ErrNotExist) {
				writes.ObjectSizes = append(writes.ObjectSizes, ref.Bytes)
			} else if err != nil {
				return err
			}
			if reuseCheckpoint {
				checked, verified := checkpoint.Objects[ref.ID]
				_, damaged := s.Damage[ref.ID]
				reuseCheckpoint = err == nil && verified && !damaged && stamp == checked.Stamp
			}
		}
		if !reuseCheckpoint {
			// A new atomic checkpoint may need room for the journal
			// and its replacement. Each entry holds the ID and stamp.
			const verificationEntry = 384
			verificationSize := 512 + verificationEntry*len(refs)
			writes.MetadataSizes = append(writes.MetadataSizes, verificationSize, verificationSize)
		}
		return nil
	})
	return writes, err
}
