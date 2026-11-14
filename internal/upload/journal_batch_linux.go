package upload

import "context"

const maxProgressBatch = 32

type partAcknowledgement struct {
	id               string
	round, submitted int64
}

// Intent batches authorize no network IO. Each part's current owner and lease
// are checked again after this transaction is durable.
func (j *Journal) beginParts(ctx context.Context, ids []string, round int64) error {
	if len(ids) == 0 || len(ids) > maxProgressBatch || round < 0 {
		return ErrDenied
	}
	if j.Guard != nil {
		if err := j.Guard(ctx); err != nil {
			return err
		}
	}
	return j.edit(ctx, func(s *State) error {
		seen := map[string]bool{}
		for _, id := range ids {
			p := s.Parts[id]
			if !j.tasks[id] || seen[id] || p.Complete || p.Attempts == ^uint64(0) {
				return ErrDenied
			}
			seen[id] = true
			p.Round, p.Attempts = round, p.Attempts+1
			s.Parts[id] = p
		}
		s.Phase = "TRANSFERRING"
		return nil
	})
}

// Only verified immutable acknowledgements enter this bounded transaction.
// A failed or interrupted write leaves intents pending, requiring actual target
// readback after reopening. No volatile acknowledgement is completion evidence.
func (j *Journal) doneParts(ctx context.Context, parts []partAcknowledgement) error {
	if len(parts) == 0 || len(parts) > maxProgressBatch {
		return ErrDenied
	}
	if j.Guard != nil {
		if err := j.Guard(ctx); err != nil {
			return err
		}
	}
	return j.edit(ctx, func(s *State) error {
		seen := map[string]bool{}
		for _, part := range parts {
			p, ok := s.Parts[part.id]
			if !ok || !j.tasks[part.id] || seen[part.id] || p.Complete || part.round < 0 || part.submitted < 0 || p.SubmittedBytes > int64(^uint64(0)>>1)-part.submitted {
				return ErrDenied
			}
			seen[part.id] = true
			p.Complete, p.Round = true, part.round
			p.SubmittedBytes += part.submitted
			s.Parts[part.id] = p
		}
		return nil
	})
}
