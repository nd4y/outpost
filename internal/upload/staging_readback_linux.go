package upload

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

type StagingReadback struct {
	Format         string                     `json:"format"`
	Node           string                     `json:"node"`
	Operation      string                     `json:"operation"`
	Plan           string                     `json:"plan"`
	Target         string                     `json:"target"`
	Bucket         string                     `json:"bucket"`
	Attempt        storage.MoveStagingAttempt `json:"attempt"`
	RemotePresence string                     `json:"remotePresence"`
	ObservedUnix   int64                      `json:"observedUnix,omitempty"`
	ErrorCode      string                     `json:"errorCode,omitempty"`
}

// ReadStaging checks one exact name from the local page against its bound target.
func ReadStaging(ctx context.Context, status StagingStatus, temporary string, b *storage.Backend) (StagingReadback, error) {
	var out StagingReadback
	if b == nil || status.State != "RECORDED" || status.Move == nil || status.Move.State != "READY" ||
		b.Profile().ID() != status.Target {
		return out, ErrDenied
	}
	i := slices.IndexFunc(status.Move.Attempts, func(a storage.MoveStagingAttempt) bool { return a.Temporary == temporary })
	if i < 0 {
		return out, ErrDenied
	}
	a := status.Move.Attempts[i]
	out = StagingReadback{Format: "outpost-upload-staging-readback-1", Node: status.Node,
		Operation: status.Operation, Plan: status.Plan, Target: status.Target, Bucket: status.Move.Bucket, Attempt: a}
	if e := ctx.Err(); e != nil {
		return StagingReadback{}, e
	}
	if a.WriteStartedMillis == 0 {
		out.RemotePresence, out.ErrorCode = "NOT_CHECKED", "NO_WRITE_RECORDED"
		return out, nil
	}

	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	matches, e := b.VerifyMoveStage(bounded, a)
	if ctx.Err() != nil {
		return StagingReadback{}, ctx.Err()
	}
	out.ObservedUnix = time.Now().Unix()
	switch {
	case e == nil && matches:
		out.RemotePresence = "MATCHED"
	case e == nil:
		out.RemotePresence = "MISMATCH"
	case errors.Is(e, storage.ErrNotFound):
		out.RemotePresence = "MISSING_AT_READ"
	default:
		out.RemotePresence, out.ErrorCode = "UNAVAILABLE", stagingReadError(e)
	}
	return out, nil
}

func stagingReadError(e error) string {
	switch {
	case errors.Is(e, context.DeadlineExceeded):
		return "DEADLINE"
	case errors.Is(e, storage.ErrDenied):
		return "ACCESS_DENIED"
	case errors.Is(e, storage.ErrIntegrity), errors.Is(e, storage.ErrCapacity), errors.Is(e, storage.ErrUnsupported):
		return "INVALID_RESPONSE"
	default:
		return "READ_FAILED"
	}
}
