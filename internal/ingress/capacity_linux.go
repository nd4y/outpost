package ingress

import (
	"context"
	"encoding/json"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
)

func (s *Session) checkPublication(ctx context.Context, raw []byte, refs []generation.Object) error {
	if s.admitPublication == nil || s.state.Complete {
		return nil
	}
	id := generation.Hash(raw)
	if s.estimatedCatalog == id {
		return nil
	}
	writes, err := s.replica.EstimatePublication(ctx, raw, refs)
	if err != nil {
		return err
	}
	var peak diskbudget.Peak
	for _, size := range writes.ObjectSizes {
		peak.Data += diskbudget.WriteCharge(size)
	}
	for _, size := range writes.MetadataSizes {
		peak.Spool += diskbudget.WriteCharge(size)
	}
	stagedBytes, stagedObjects := s.bytes, len(s.refs)
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !s.has(ref) {
			stagedBytes += int64(ref.Bytes)
			stagedObjects++
			peak.Data += diskbudget.WriteCharge(ref.Bytes)
		}
	}
	if stagedBytes > s.intent.MaxBytes || stagedObjects > s.intent.MaxObjects {
		return statefile.ErrCapacity
	}
	// Existing staging remains charged until the full replica is accepted
	// and acknowledged. Budget one session rewrite including its receipt.
	state, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	size := len(state) + MaxReceiptDocument
	if len(s.state.Catalog) == 0 {
		size += len(raw)
	}
	if size > maxSessionDocument {
		return statefile.ErrCapacity
	}
	peak.Spool += diskbudget.WriteCharge(size)
	if err = s.admitPublication(ctx, peak); err != nil {
		return err
	}
	s.estimatedCatalog = id
	return nil
}
