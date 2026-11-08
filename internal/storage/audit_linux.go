package storage

import (
	"context"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

const GenerationAuditFormat = "outpost-external-ciphertext-audit-1"

type GenerationAudit struct {
	Format          string `json:"format"`
	Target          string `json:"target"`
	Generation      string `json:"generation"`
	State           string `json:"state"`
	StartedUnix     int64  `json:"startedUnix"`
	FinishedUnix    int64  `json:"finishedUnix"`
	ExpectedObjects *int   `json:"expectedObjects"`
	VerifiedObjects int    `json:"verifiedObjects"`
	FailureStage    string `json:"failureStage,omitempty"`
	FailedObject    string `json:"failedObject,omitempty"`
}

// AuditGeneration reads an exact generation from the target with no writes
// or decryption key. It stops at the first dependency it cannot verify.
func (b *Backend) AuditGeneration(ctx context.Context, id string, trust generation.Trust) (GenerationAudit, error) {
	var report GenerationAudit
	if !ID(id) || b.profile.Namespace != Hash([]byte(trust.Domain+"/"+trust.Repository)) {
		return report, ErrDenied
	}
	report = GenerationAudit{
		Format: GenerationAuditFormat, Target: b.profile.ID(), Generation: id,
		StartedUnix: time.Now().Unix(), FailureStage: "CATALOG",
	}
	finish := func(err error) (GenerationAudit, error) {
		report.FinishedUnix = time.Now().Unix()
		if report.FinishedUnix < report.StartedUnix {
			return GenerationAudit{}, ErrUnavailable
		}
		switch {
		case err == nil:
			report.State = "VERIFIED_CIPHERTEXT"
			report.FailureStage = ""
		case errors.Is(err, context.Canceled):
			report.State = "CANCELED"
		case errors.Is(err, ErrDenied):
			report.State = "DENIED"
		case Missing(err):
			report.State = "MISSING"
		case errors.Is(err, ErrIntegrity), errors.Is(err, generation.ErrInvalid), errors.Is(err, generation.ErrRollback):
			report.State = "INVALID_CONTENT"
		default:
			report.State = "UNAVAILABLE"
		}
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	raw, err := b.Catalog(ctx, id, trust)
	if err != nil {
		return finish(err)
	}
	objects, err := generation.Dependencies(raw, trust)
	if err != nil {
		return finish(err)
	}
	expected := len(objects)
	report.ExpectedObjects = &expected
	report.FailureStage = "DEPENDENCY"
	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		if _, err := b.ReadBlob(ctx, object); err != nil {
			report.FailedObject = object.ID
			return finish(err)
		}
		report.VerifiedObjects++
	}
	return finish(ctx.Err())
}
