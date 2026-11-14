package generation

import (
	"context"
	"errors"
	"sort"
)

// RecordedGeneration summarizes the authenticated catalog and publication
// ledger. It deliberately makes no claim about present payload integrity.
type RecordedGeneration struct {
	Generation         string
	Sequence           uint64
	CreatedUnix        int64
	Objects            int
	Complete, Pinned   bool
	Damaged            bool
	CatalogUnavailable bool
	RepairToken        string
}

func (r *Replica) Recorded(ctx context.Context) ([]RecordedGeneration, error) {
	out := []RecordedGeneration{}
	e := r.locked(ctx, func(s *state) error {
		pins := map[string]bool{}
		for _, pin := range s.Pins {
			pins[pin.Generation] = true
		}
		for id, item := range s.Generations {
			if e := ctx.Err(); e != nil {
				return e
			}
			catalog, refs, e := r.get(s, id, false)
			if errors.Is(e, ErrCatalogUnavailable) {
				current := s.Generations[id]
				out = append(out, RecordedGeneration{Generation: id, Sequence: current.Sequence, Pinned: pins[id], Damaged: true, RepairToken: current.RepairToken, CatalogUnavailable: true})
				continue
			}
			if e != nil {
				return e
			}
			out = append(out, RecordedGeneration{Generation: id, Sequence: item.Sequence, CreatedUnix: catalog.SnapshotUnix, Objects: len(refs), Complete: item.Complete && !item.Damaged, Pinned: pins[id], Damaged: item.Damaged, RepairToken: item.RepairToken})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
