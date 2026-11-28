package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/storage"
)

const WriterFenceFormat = "outpost-source-writer-fence-1"
const MaxWriterFence = 128 << 10

var ErrWriterFenced = errors.New("the source writer epoch is fenced")

type WriterFence struct {
	Format               string            `json:"format"`
	Operation            string            `json:"operation"`
	Source               string            `json:"source"`
	Profile              string            `json:"profile"`
	PreviousCheckpoint   string            `json:"previousCheckpoint"`
	PreparationAuthority ed25519.PublicKey `json:"preparationAuthority,omitempty"`
	Preparation          []byte            `json:"preparation"`
	SuccessorCheckpoint  []byte            `json:"successorCheckpoint"`
	RestoreEvidence      string            `json:"restoreEvidence"`
	NotBefore            int64             `json:"notBefore"`
	ExpiresUnix          int64             `json:"expiresUnix"`
	Signature            []byte            `json:"signature,omitempty"`
}

type WriterFenceStatus struct {
	Operation           string `json:"operation"`
	PreviousCheckpoint  string `json:"previousCheckpoint"`
	SuccessorCheckpoint string `json:"successorCheckpoint"`
	RestoreEvidence     string `json:"restoreEvidence"`
	InstalledUnix       int64  `json:"installedUnix"`
}

func (f WriterFence) validate(owner ed25519.PublicKey, at int64) (recoverybundle.PriorEpoch, int, error) {
	var prior recoverybundle.PriorEpoch
	if f.Format != WriterFenceFormat || !storage.ID(f.Operation) || !storage.ID(f.Source) || !storage.ID(f.Profile) || !storage.ID(f.PreviousCheckpoint) || !storage.ID(f.RestoreEvidence) || f.NotBefore < 1 || f.ExpiresUnix <= f.NotBefore || f.ExpiresUnix-f.NotBefore > 86400 || at < f.NotBefore || at >= f.ExpiresUnix {
		return prior, 0, ErrInvalid
	}
	preparationAuthority := owner
	if len(f.PreparationAuthority) != 0 {
		preparationAuthority = f.PreparationAuthority
	}
	prepared, e := recoverybundle.VerifyEpochPreparation(f.Preparation, preparationAuthority)
	if e != nil || prepared.Prior == nil || prepared.CreatedUnix > at {
		return prior, 0, ErrInvalid
	}
	checkpoint, e := capture.VerifyCheckpoint(f.SuccessorCheckpoint, prepared.Trust)
	if e != nil || checkpoint.Generation == prepared.Prior.Generation {
		return prior, 0, ErrInvalid
	}
	seen := map[string]bool{}
	for _, copy := range checkpoint.Copies {
		if !storage.ID(copy.Target) || seen[copy.Target] || copy.Generation != checkpoint.Generation || copy.Verification != "ciphertext-readback" || copy.ObservedUnix < prepared.CreatedUnix || copy.ObservedUnix > at {
			return prior, 0, ErrInvalid
		}
		seen[copy.Target] = true
	}
	return *prepared.Prior, len(seen), nil
}

func SignWriterFence(f WriterFence, owner ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(owner) != ed25519.PrivateKeySize || len(f.Signature) != 0 {
		return nil, ErrInvalid
	}
	if _, _, e := f.validate(owner.Public().(ed25519.PublicKey), now.Unix()); e != nil {
		return nil, e
	}
	unsigned, e := json.Marshal(f)
	if e != nil {
		return nil, e
	}
	f.Signature = ed25519.Sign(owner, append([]byte(WriterFenceFormat+"\x00"), unsigned...))
	raw, e := json.Marshal(f)
	if e != nil || len(raw) > MaxWriterFence {
		return nil, ErrInvalid
	}
	return raw, nil
}

func (a *Agent) writerFence(s state, raw []byte, installed int64) (WriterFenceStatus, error) {
	var out WriterFenceStatus
	var f WriterFence
	if storage.Decode(raw, &f, MaxWriterFence) != nil {
		return out, ErrInvalid
	}
	canonical, e := json.Marshal(f)
	if e != nil || !bytes.Equal(canonical, raw) {
		return out, ErrInvalid
	}
	sig := f.Signature
	f.Signature = nil
	unsigned, e := json.Marshal(f)
	if e != nil || !ed25519.Verify(a.b.Local.Owner, append([]byte(WriterFenceFormat+"\x00"), unsigned...), sig) {
		return out, ErrInvalid
	}
	prior, copies, e := f.validate(a.b.Local.Owner, installed)
	trust := a.anchor.Trust
	if e != nil || s.Phase != "COMPLETE" || len(s.Reclaims) != 0 || len(s.Superseded) != 0 && !s.ReclaimRecorded ||
		f.Source != a.anchor.Source || f.Profile != a.b.Profile.ID || f.PreviousCheckpoint != storage.Hash(s.Checkpoint) ||
		prior.Domain != trust.Domain || prior.Repository != trust.Repository || prior.Epoch != trust.Epoch || prior.Generation != s.Generation || copies < a.b.Profile.MinimumCopies {
		return out, ErrInvalid
	}
	return WriterFenceStatus{Operation: f.Operation, PreviousCheckpoint: f.PreviousCheckpoint, SuccessorCheckpoint: storage.Hash(f.SuccessorCheckpoint), RestoreEvidence: f.RestoreEvidence, InstalledUnix: installed}, nil
}

// FenceWriter commits an irrevocable local stop at the exact complete head.
// The successor's recovery evidence is selected by the offline owner.
func (a *Agent) FenceWriter(ctx context.Context, raw []byte) (WriterFenceStatus, error) {
	var out WriterFenceStatus
	e := a.lease.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		if len(s.WriterFence) != 0 {
			if !bytes.Equal(s.WriterFence, raw) {
				return ErrWriterFenced
			}
			out, e = a.writerFence(s, raw, s.WriterFencedUnix)
			return e
		}
		installed := time.Now().Unix()
		out, e = a.writerFence(s, raw, installed)
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		s.WriterFence = bytes.Clone(raw)
		s.WriterFencedUnix = installed
		return a.save(s)
	})
	return out, e
}
