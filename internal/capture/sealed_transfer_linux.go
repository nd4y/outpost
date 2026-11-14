package capture

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

// SealedTransfer carries only immutable catalog bytes and the authenticated
// local plan. The destination binds them to the new receiver intent.
type SealedTransfer struct {
	Plan, Catalog []byte
}

type sealedReceiver interface {
	RecoverSealed(context.Context, []generation.Object) error
}

func (j *Job) SealedTransfer(ctx context.Context) (*SealedTransfer, error) {
	var transfer *SealedTransfer
	err := j.lease.WithLock(ctx, func() error {
		s, err := j.Status(ctx)
		if err != nil {
			return err
		}
		if s.Phase != "CAPTURING" && s.Phase != "SEALED" {
			return nil
		}
		catalog, err := j.state.Read("catalog.json")
		if errors.Is(err, os.ErrNotExist) && s.Phase == "CAPTURING" {
			return nil
		}
		if err != nil {
			return err
		}
		id := s.Generation
		if s.Phase == "CAPTURING" {
			id = storage.Hash(catalog)
		}
		if s.CompletedFiles != len(j.plan.Files) {
			return ErrInvalid
		}
		if _, err = j.sealedHeads(catalog, id); err != nil {
			return err
		}
		plan, err := j.state.Read("plan.json")
		if err != nil {
			return err
		}
		if storage.Hash(plan) != s.Plan {
			return ErrInvalid
		}
		transfer = &SealedTransfer{Plan: plan, Catalog: catalog}
		return nil
	})
	return transfer, err
}

func (j *Job) sealedHeads(raw []byte, id string) (map[string]string, error) {
	i := j.intent
	c, err := generation.VerifyCatalog(raw, j.authority.Trust)
	if err != nil || storage.Hash(raw) != id || c.Sequence != i.Sequence || c.Parent != i.Parent ||
		c.SnapshotUnix != i.SnapshotUnix || c.Policy != i.Policy || len(c.Kits) != len(j.plan.Files) {
		return nil, ErrInvalid
	}
	heads := make(map[string]string, len(c.Kits))
	for _, kit := range c.Kits {
		heads[kit.File] = kit.Version
	}
	for _, file := range j.plan.Files {
		if heads[file.File] == "" {
			return nil, ErrInvalid
		}
	}
	return heads, nil
}

func (j *Job) prepareSealed(transfer *SealedTransfer) error {
	if transfer == nil || storage.Decode(transfer.Plan, &j.plan, maxPlan) != nil ||
		j.RoutePlanDigest() != j.options.RoutePlan {
		return ErrInvalid
	}
	if _, err := j.sealedHeads(transfer.Catalog, j.options.InheritedCatalog); err != nil {
		return err
	}
	j.plan.Profile = j.options.Profile
	plan, err := json.Marshal(j.plan)
	if err != nil || len(plan) > maxPlan {
		return ErrInvalid
	}
	if err = j.state.Write("plan.json", plan); err != nil {
		return err
	}
	if err = j.state.Write("catalog.json", transfer.Catalog); err != nil {
		return err
	}
	return j.save(&State{Format: Format, Binding: j.binding, Plan: storage.Hash(plan), Phase: "SEALED",
		CompletedFiles: len(j.plan.Files), Generation: j.options.InheritedCatalog})
}

// recoverCatalogState closes the crash gap between persisting the catalog
// bytes and committing the corresponding phase.
func (j *Job) recoverCatalogState(s *State) error {
	raw, err := j.state.Read("catalog.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	id := storage.Hash(raw)
	if s.CompletedFiles != len(j.plan.Files) {
		return ErrInvalid
	}
	if _, err = j.sealedHeads(raw, id); err != nil {
		return err
	}
	s.Phase, s.Generation = "SEALED", id
	return j.save(s)
}
