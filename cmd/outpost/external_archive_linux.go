package main

import (
	"context"
	"crypto/ed25519"
	"slices"
	"strings"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
	"github.com/nd4y/outpost/internal/worker"
)

type archiveReader struct {
	Planner ed25519.PublicKey     `json:"planner"`
	Policy  storage.ArchivePolicy `json:"policy"`
}

func (a archiveReader) valid(profile storage.Profile) bool {
	return profile.Kind == "s3" && profile.CredentialScope == "namespace" &&
		len(a.Planner) == ed25519.PublicKeySize && a.Policy.Validate() == nil
}

type archiveResult struct {
	Generation string                  `json:"generation"`
	Version    string                  `json:"version,omitempty"`
	PlanSHA256 string                  `json:"planSHA256"`
	Progress   storage.ArchiveProgress `json:"progress"`
}

func externalArchive(ctx context.Context, profileFile, trustFile, keyFile, planFile, planHash, expected, version string, maxRequests int) (archiveResult, error) {
	var result archiveResult
	if !storage.ID(expected) || !storage.ID(planHash) || version != "" && !storage.ID(version) || maxRequests < 0 {
		return result, errUsage
	}
	raw, err := worker.ReadPrivate(trustFile, 65536)
	if err != nil {
		return result, err
	}
	var trust generation.Trust
	if worker.DecodeInput(raw, &trust, 65536) != nil {
		return result, errUsage
	}
	profile, err := loadExternalReader(profileFile, trust)
	if err != nil {
		return result, err
	}
	if profile.Archive == nil {
		return result, storage.ErrUnsupported
	}
	if maxRequests > profile.Archive.Policy.MaxParts {
		return result, errUsage
	}
	owner, err := filekit.ReadOwner(keyFile)
	if err != nil {
		return result, err
	}
	owner.SigningKey = nil
	raw, err = worker.ReadPrivate(planFile, upload.MaxPlan)
	if err != nil {
		return result, err
	}
	if storage.Hash(raw) != planHash {
		return result, storage.ErrDenied
	}
	plan, err := upload.Verify(raw, upload.Authority{Generation: trust, Planner: profile.Archive.Planner})
	// A derived plan's delegation does not sign its physical part list.
	if err != nil || plan.Format != upload.Format || plan.Generation != expected ||
		plan.Profile != profile.Profile || owner.Domain != trust.Domain {
		return result, storage.ErrDenied
	}
	backend, err := profile.open(ctx)
	if err != nil {
		return result, err
	}
	defer backend.Close()

	parts, hot, err := archiveClosure(ctx, backend, plan, trust, owner, version)
	if err != nil {
		return result, externalRecoveryError(err)
	}
	progress, err := backend.RetrieveArchive(ctx, profile.Archive.Policy, parts, hot, maxRequests)
	if err != nil {
		return result, externalRecoveryError(err)
	}
	return archiveResult{Generation: expected, Version: version, PlanSHA256: planHash, Progress: progress}, nil
}

func archiveClosure(ctx context.Context, backend *storage.Backend, plan upload.Plan, trust generation.Trust, owner filekit.Owner, version string) ([]generation.Object, map[string]bool, error) {
	raw, err := backend.Catalog(ctx, plan.Generation, trust)
	if err != nil {
		return nil, nil, err
	}
	catalog, err := generation.VerifyCatalog(raw, trust)
	if err != nil {
		return nil, nil, err
	}
	catalogBlob, err := backend.Descriptor(ctx, generation.Object{ID: plan.Generation, Bytes: len(raw)})
	if err != nil {
		return nil, nil, err
	}
	blobs := make(map[string]storage.Blob, len(plan.Blobs))
	for _, blob := range plan.Blobs {
		blobs[blob.Object.ID] = blob
	}
	checked := make(map[string]bool)
	verifyDescriptor := func(ctx context.Context, ref generation.Object) (storage.Blob, error) {
		blob := blobs[ref.ID]
		if blob.Object != ref {
			return blob, storage.ErrIntegrity
		}
		if !checked[ref.ID] {
			stored, err := backend.Descriptor(ctx, ref)
			if err != nil {
				return blob, err
			}
			if !slices.Equal(stored.Parts, blob.Parts) {
				return blob, storage.ErrIntegrity
			}
			checked[ref.ID] = true
		}
		return blob, nil
	}
	parts := make(map[string]generation.Object)
	hot := make(map[string]bool)
	add := func(blob storage.Blob, metadata bool) error {
		for _, part := range blob.Parts {
			if old, exists := parts[part.ID]; exists && old != part {
				return storage.ErrIntegrity
			}
			parts[part.ID] = part
			if metadata {
				hot[part.ID] = true
			}
		}
		return nil
	}
	if err = add(catalogBlob, true); err != nil {
		return nil, nil, err
	}
	selection := generation.RecoverySelection{}
	if version != "" {
		selection.Versions = []string{version}
	}
	// Reads during planning are confined to authenticated kit metadata. Payload
	// is left unread until after the delayed access window is available.
	_, err = generation.PlanRecoveryCatalog(ctx, plan.Generation, raw, trust, owner, selection, func(ctx context.Context, ref generation.Object) ([]byte, error) {
		blob, err := verifyDescriptor(ctx, ref)
		if err != nil {
			return nil, err
		}
		if err := add(blob, true); err != nil {
			return nil, err
		}
		return backend.ReadDescribed(ctx, blob)
	})
	if err != nil {
		return nil, nil, err
	}
	for _, kit := range catalog.Kits {
		if version != "" && kit.Version != version {
			continue
		}
		for _, ref := range kit.Objects {
			blob, err := verifyDescriptor(ctx, ref)
			if err != nil {
				return nil, nil, err
			}
			if err := add(blob, false); err != nil {
				return nil, nil, err
			}
		}
	}
	ordered := make([]generation.Object, 0, len(parts))
	for _, part := range parts {
		ordered = append(ordered, part)
	}
	slices.SortFunc(ordered, func(a, b generation.Object) int { return strings.Compare(a.ID, b.ID) })
	return ordered, hot, nil
}
