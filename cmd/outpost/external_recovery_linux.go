package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

const externalRecoveryFormat = "outpost-external-recovery-1"

type externalRecoveryProfile struct {
	Format         string          `json:"format"`
	Target         string          `json:"target"`
	Profile        storage.Profile `json:"profile"`
	CredentialFile string          `json:"credentialFile"`
	CAFile         string          `json:"caFile,omitempty"`
}

func restoreExternal(ctx context.Context, profileFile, expected, dest string, trust generation.Trust, owner filekit.Owner, selection generation.RecoverySelection) (generation.RecoveryReceipt, error) {
	var result generation.RecoveryReceipt
	if !storage.ID(expected) || !filepath.IsAbs(dest) || filepath.Clean(dest) != dest || filepath.Base(dest) == "/" || owner.Domain != trust.Domain {
		return result, errUsage
	}
	raw, err := worker.ReadPrivate(profileFile, 65536)
	if err != nil {
		return result, err
	}
	var profile externalRecoveryProfile
	if worker.DecodeInput(raw, &profile, 65536) != nil || profile.Format != externalRecoveryFormat ||
		profile.Profile.Validate() != nil || profile.Profile.ID() != profile.Target || !filepath.IsAbs(profile.CredentialFile) ||
		(profile.CAFile != "" && !filepath.IsAbs(profile.CAFile)) {
		return result, errUsage
	}
	if profile.Profile.Namespace != storage.Hash([]byte(trust.Domain+"/"+trust.Repository)) {
		return result, storage.ErrDenied
	}
	parent, err := localfs.OpenRoot(filepath.Dir(dest))
	if err != nil {
		return result, err
	}
	defer parent.Close()
	name := filepath.Base(dest)
	if _, err = parent.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = os.ErrExist
		}
		return result, err
	}
	reader := worker.Bootstrap{StorageCAFile: profile.CAFile, Credentials: map[string]string{profile.Target: profile.CredentialFile}}
	backend, err := reader.Resolve(ctx, profile.Profile)
	if err != nil {
		return result, err
	}
	defer backend.Close()
	catalog, err := backend.Catalog(ctx, expected, trust)
	if err != nil {
		return result, externalRecoveryError(err)
	}
	result, err = generation.RecoverCatalogAt(ctx, expected, catalog, trust, owner, selection, backend.ReadBlob, parent, name)
	return result, externalRecoveryError(err)
}

func externalRecoveryError(err error) error {
	if storage.Missing(err) || errors.Is(err, generation.ErrInvalid) {
		return errors.Join(generation.ErrIncomplete, err)
	}
	return err
}
