package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

const (
	TwoHolderCoverage   = "two-holder-coverage"
	PairedSplitCoverage = "paired-split-coverage"
)

type coverageSink interface {
	Coverage(context.Context, []byte) ([]ingress.CoverageReceipt, error)
	CoverageBindings() map[string]string
}

type coverageCheckpoint struct {
	Policy     string                    `json:"policy"`
	Binding    string                    `json:"binding"`
	Generation string                    `json:"generation"`
	Holders    []ingress.CoverageReceipt `json:"holders"`
	Signature  []byte                    `json:"signature,omitempty"`
}

func (j *Job) verifyCoverage(raw []byte, c coverageCheckpoint) error {
	if c.Policy != j.options.Profile.ReleasePolicy || c.Binding != j.binding || c.Generation != storage.Hash(raw) || len(c.Holders) != 2 {
		return ErrInvalid
	}
	refs, err := generation.Dependencies(raw, j.authority.Trust)
	if err != nil {
		return err
	}
	bindings := j.options.Sink.(coverageSink).CoverageBindings()
	seen := map[string]bool{}
	for _, holder := range c.Holders {
		var other string
		if c.Policy == PairedSplitCoverage {
			for target := range bindings {
				if target != holder.Holder {
					other = target
				}
			}
		}
		assigned := ingress.CoverageDependencies(refs, holder.Holder, other)
		if holder.Intent == "" || bindings[holder.Holder] != holder.Intent || seen[holder.Holder] ||
			holder.Generation != c.Generation || holder.Dependencies != ingress.DependencyDigest(assigned) || holder.Objects != len(assigned) ||
			holder.AcceptedUnix < j.intent.NotBefore || holder.AcceptedUnix >= j.intent.ExpiresUnix || holder.AcceptedUnix > time.Now().Unix() {
			return ErrInvalid
		}
		seen[holder.Holder] = true
	}
	return nil
}

func (j *Job) validateStagedRelease(s State) error {
	raw, err := j.state.Read("coverage-checkpoint.json")
	if err != nil {
		return err
	}
	var checkpoint coverageCheckpoint
	if storage.Decode(raw, &checkpoint, 4096) != nil || checkpoint.Generation != s.Generation {
		return ErrInvalid
	}
	canonical, _ := json.Marshal(checkpoint)
	sig := checkpoint.Signature
	checkpoint.Signature = nil
	payload, _ := json.Marshal(checkpoint)
	if !bytes.Equal(raw, canonical) || !ed25519.Verify(j.authority.Trust.Writer, payload, sig) {
		return ErrInvalid
	}
	catalog, err := j.state.Read("catalog.json")
	if err != nil {
		return err
	}
	return j.verifyCoverage(catalog, checkpoint)
}

func (j *Job) releaseWithCoverage(ctx context.Context, s *State, raw []byte) error {
	if s.StagedRelease == "" {
		holders, err := j.options.Sink.(coverageSink).Coverage(ctx, raw)
		if err != nil {
			return err
		}
		c := coverageCheckpoint{Policy: j.options.Profile.ReleasePolicy, Binding: j.binding, Generation: s.Generation, Holders: holders}
		if err = j.verifyCoverage(raw, c); err != nil {
			return err
		}
		payload, _ := json.Marshal(c)
		c.Signature = ed25519.Sign(j.options.Writer, payload)
		proof, _ := json.Marshal(c)
		if err = j.state.Write("coverage-checkpoint.json", proof); err != nil {
			return err
		}
		s.StagedRelease = "CHECKPOINTED"
		if err = j.save(s); err != nil {
			return err
		}
		if err = j.point("source-coverage-checkpoint-durable"); err != nil {
			return err
		}
	}
	if err := j.validateStagedRelease(*s); err != nil {
		return err
	}
	if s.StagedRelease == "RELEASED" {
		return nil
	}
	if err := j.guard(ctx); err != nil {
		return err
	}
	if s.StagedRelease == "CHECKPOINTED" {
		s.StagedRelease = "RELEASING"
		if err := j.save(s); err != nil {
			return err
		}
	}
	if err := j.options.Provider.Release(ctx, j.intent.Operation, j.options.Profile.View); err != nil {
		return err
	}
	if err := j.point("source-provider-released"); err != nil {
		return err
	}
	s.StagedRelease = "RELEASED"
	if err := j.save(s); err != nil {
		return err
	}
	return j.point("source-coverage-release-durable")
}
