package upload

import (
	"context"

	"github.com/nd4y/outpost/internal/storage"
)

type StagingStatus struct {
	Format          string                   `json:"format"`
	Node            string                   `json:"node"`
	Operation       string                   `json:"operation"`
	Generation      string                   `json:"generation"`
	Plan            string                   `json:"plan"`
	Target          string                   `json:"target"`
	PlanExpiresUnix int64                    `json:"planExpiresUnix"`
	QueuePhase      string                   `json:"queuePhase"`
	State           string                   `json:"state"`
	RemotePresence  string                   `json:"remotePresence"`
	Move            *storage.MoveStagingPage `json:"move,omitempty"`
}

// InspectStaging reads only the selected upload and its existing MOVE book.
// Callers that page through a worker journal must keep its execution stopped.
func (q *Queue) InspectStaging(ctx context.Context, operation, after string) (StagingStatus, error) {
	var out StagingStatus
	if !storage.ID(operation) {
		return out, ErrDenied
	}
	if q.Guard != nil {
		if e := q.Guard(ctx); e != nil {
			return out, e
		}
	}
	s, e := q.Status(ctx)
	if e != nil {
		return out, e
	}
	job, ok := s.Jobs[operation]
	if !ok {
		return out, ErrDenied
	}
	p, e := Verify(job.Plan, q.authority)
	if e != nil {
		return out, e
	}
	out = StagingStatus{Format: "outpost-upload-staging-status-1", Node: q.worker, Operation: operation,
		Generation: p.Generation, Plan: storage.Hash(job.Plan), Target: p.Profile.ID(), PlanExpiresUnix: p.ExpiresUnix,
		QueuePhase: job.Phase, State: "NOT_APPLICABLE", RemotePresence: "NOT_CHECKED"}
	if p.Profile.WriteMode != storage.WebDAVMoveMode {
		if after != "" {
			return StagingStatus{}, ErrDenied
		}
		return out, nil
	}
	j, e := q.journal(job, false)
	if e != nil {
		return StagingStatus{}, e
	}
	defer j.Close()
	state, e := j.Status(ctx)
	if e != nil {
		return StagingStatus{}, e
	}
	if !state.MoveBookReady {
		if after != "" {
			return StagingStatus{}, ErrDenied
		}
		out.State = "NOT_STARTED"
		return out, nil
	}
	book, e := storage.OpenMoveBook(ctx, j.moveBookOptions())
	if e != nil {
		return StagingStatus{}, e
	}
	defer book.Close()
	page, e := book.InspectStaging(ctx, after)
	if e != nil {
		return StagingStatus{}, e
	}
	out.State, out.Move = "RECORDED", &page
	return out, nil
}
