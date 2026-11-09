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
		// Each verification entry has a hex ID, two timespecs, device,
		// inode, length and timestamp. A later atomic checkpoint may hold
		// both the previous journal and its replacement.
		const verificationEntry = 384
		verificationSize := 512 + verificationEntry*len(refs)
		writes.MetadataSizes = append(writes.MetadataSizes, verificationSize, verificationSize)
		for _, ref := range refs {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := r.objectStamp(ref)
			if errors.Is(err, os.ErrNotExist) {
				writes.ObjectSizes = append(writes.ObjectSizes, ref.Bytes)
			} else if err != nil {
				return err
			}
		}
		return nil
	})
	return writes, err
}
