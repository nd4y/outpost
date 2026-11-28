package management

import (
	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/storage"
)

// CommandObservation is a bounded node observation separate from backup jobs
// and the management audit's signed execution acknowledgement. Results retain
// their original time; fresh transport cannot refresh an old integrity check.
type CommandObservation struct {
	Operation         string                         `json:"operationId"`
	EnvelopeDigest    string                         `json:"envelopeDigest"`
	Kind              string                         `json:"kind"`
	Phase             string                         `json:"phase"`
	Generation        string                         `json:"generation,omitempty"`
	StartedUnix       int64                          `json:"startedUnix"`
	FinishedUnix      int64                          `json:"finishedUnix"`
	Attempts          uint64                         `json:"attempts"`
	NextAttemptMillis int64                          `json:"nextAttemptMillis"`
	VerifiedObjects   uint64                         `json:"verifiedObjects"`
	TotalObjects      uint64                         `json:"totalObjects"`
	Verification      string                         `json:"verification,omitempty"`
	VerifiedUnix      int64                          `json:"verifiedUnix"`
	ResultDigest      string                         `json:"resultDigest,omitempty"`
	ErrorCode         string                         `json:"errorCode,omitempty"`
	Restore           *recovery.Receipt              `json:"restore,omitempty"`
	CleanupPending    bool                           `json:"cleanupPending,omitempty"`
	Maintenance       *generation.MaintenanceReceipt `json:"maintenance,omitempty"`
	RetentionProof    []byte                         `json:"retentionProof,omitempty"`
}

func (c CommandObservation) Validate(observed int64) error {
	if !storage.ID(c.Operation) || !storage.ID(c.EnvelopeDigest) || !command.Scheduled(c.Kind) || !oneOf(c.Phase, "QUEUED", "RUNNING", "RETRY_WAIT", "COMPLETE", "FAILED") || !validTime(c.StartedUnix) || c.StartedUnix > observed || c.FinishedUnix < 0 || c.FinishedUnix > observed || !safe(c.Attempts) || c.NextAttemptMillis < 0 || c.NextAttemptMillis > 1<<50 || !safe(c.VerifiedObjects) || !safe(c.TotalObjects) || c.VerifiedObjects > c.TotalObjects || !stableCode(c.ErrorCode) {
		return ErrInvalid
	}
	terminal := c.Phase == "COMPLETE" || c.Phase == "FAILED"
	if terminal && (c.FinishedUnix < c.StartedUnix || c.NextAttemptMillis != 0) || !terminal && c.FinishedUnix != 0 {
		return ErrInvalid
	}
	if (c.Phase == "COMPLETE") != (c.ResultDigest != "") || c.ResultDigest != "" && !storage.ID(c.ResultDigest) || c.Phase == "COMPLETE" && c.ErrorCode != "" || c.Phase == "FAILED" && c.ErrorCode == "" {
		return ErrInvalid
	}
	if c.Kind != "restore" && (c.Restore != nil || c.CleanupPending) {
		return ErrInvalid
	}
	if c.Kind == "retention" {
		if c.Generation != "" || c.Verification != "" || c.VerifiedUnix != 0 || c.VerifiedObjects != 0 || c.TotalObjects != 0 ||
			c.Maintenance != nil || (c.Phase == "COMPLETE") != (len(c.RetentionProof) > 0) ||
			len(c.RetentionProof) > generation.MaxRetentionProtection ||
			len(c.RetentionProof) > 0 && storage.Hash(c.RetentionProof) != c.ResultDigest {
			return ErrInvalid
		}
		return nil
	}
	if len(c.RetentionProof) != 0 {
		return ErrInvalid
	}
	if c.Kind == "scrub" {
		if !storage.ID(c.Generation) || c.Maintenance != nil {
			return ErrInvalid
		}
		if c.Phase == "COMPLETE" {
			if c.Verification != "CIPHERTEXT" || c.VerifiedUnix < c.StartedUnix || c.VerifiedUnix > c.FinishedUnix || c.VerifiedObjects != c.TotalObjects {
				return ErrInvalid
			}
		} else if c.Verification != "" || c.VerifiedUnix != 0 {
			return ErrInvalid
		}
	} else if c.Kind == "restore" {
		if !storage.ID(c.Generation) || c.Maintenance != nil || c.VerifiedObjects != 0 || c.TotalObjects != 0 {
			return ErrInvalid
		}
		if c.Phase == "COMPLETE" {
			if c.Restore == nil || c.Restore.Validate() != nil || c.Restore.Operation != c.Operation || c.Restore.Binding != c.EnvelopeDigest || c.Restore.Restored.Generation != c.Generation || c.Verification != "DECRYPTED" || c.VerifiedUnix != c.Restore.VerifiedUnix || c.VerifiedUnix < c.StartedUnix || c.VerifiedUnix > c.FinishedUnix {
				return ErrInvalid
			}
		} else if c.Restore != nil || c.Verification != "" || c.VerifiedUnix != 0 {
			return ErrInvalid
		}
	} else {
		if c.Generation != "" || c.Verification != "" || c.VerifiedUnix != 0 || c.VerifiedObjects != 0 || c.TotalObjects != 0 {
			return ErrInvalid
		}
		if c.Phase == "COMPLETE" {
			if c.Maintenance == nil || c.Maintenance.Validate() != nil || c.Maintenance.Operation != c.Operation || c.Maintenance.CompletedUnix > c.FinishedUnix {
				return ErrInvalid
			}
		} else if c.Maintenance != nil {
			return ErrInvalid
		}
	}
	return nil
}
