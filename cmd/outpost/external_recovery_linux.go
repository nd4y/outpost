package main

import (
	"context"
	"encoding/json"
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

func openExternalReader(ctx context.Context, profileFile string, trust generation.Trust) (*storage.Backend, error) {
	raw, err := worker.ReadPrivate(profileFile, 65536)
	if err != nil {
		return nil, err
	}
	var profile externalRecoveryProfile
	if worker.DecodeInput(raw, &profile, 65536) != nil || profile.Format != externalRecoveryFormat ||
		profile.Profile.Validate() != nil || profile.Profile.ID() != profile.Target || !filepath.IsAbs(profile.CredentialFile) ||
		(profile.CAFile != "" && !filepath.IsAbs(profile.CAFile)) {
		return nil, errUsage
	}
	if profile.Profile.Namespace != storage.Hash([]byte(trust.Domain+"/"+trust.Repository)) {
		return nil, storage.ErrDenied
	}
	reader := worker.Bootstrap{StorageCAFile: profile.CAFile, Credentials: map[string]string{profile.Target: profile.CredentialFile}}
	return reader.Resolve(ctx, profile.Profile)
}

func restoreExternal(ctx context.Context, profileFile, expected, dest string, trust generation.Trust, owner filekit.Owner, selection generation.RecoverySelection) (generation.RecoveryReceipt, error) {
	var result generation.RecoveryReceipt
	if !storage.ID(expected) || !filepath.IsAbs(dest) || filepath.Clean(dest) != dest || filepath.Base(dest) == "/" || owner.Domain != trust.Domain {
		return result, errUsage
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
	backend, err := openExternalReader(ctx, profileFile, trust)
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

func auditExternal(ctx context.Context, profileFile, trustFile, expected, output string) (storage.GenerationAudit, error) {
	var report storage.GenerationAudit
	if !storage.ID(expected) {
		return report, errUsage
	}
	var parent *os.Root
	if output != "" {
		if !filepath.IsAbs(output) || filepath.Clean(output) != output || filepath.Base(output) == "/" {
			return report, errUsage
		}
		var err error
		parent, err = localfs.OpenRoot(filepath.Dir(output))
		if err != nil {
			return report, err
		}
		defer parent.Close()
		if _, err = parent.Lstat(filepath.Base(output)); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = os.ErrExist
			}
			return report, err
		}
	}
	raw, err := worker.ReadPrivate(trustFile, 65536)
	if err != nil {
		return report, err
	}
	var trust generation.Trust
	if worker.DecodeInput(raw, &trust, 65536) != nil {
		return report, errUsage
	}
	backend, err := openExternalReader(ctx, profileFile, trust)
	if err != nil {
		return report, err
	}
	defer backend.Close()
	report, auditErr := backend.AuditGeneration(ctx, expected, trust)
	if parent != nil && report.Format != "" {
		encoded, err := json.Marshal(report)
		if err != nil {
			return report, err
		}
		if err = writeNewAt(parent, filepath.Base(output), encoded); err != nil {
			return report, err
		}
	}
	return report, externalRecoveryError(auditErr)
}

func externalRecoveryError(err error) error {
	if storage.Missing(err) || errors.Is(err, generation.ErrInvalid) || errors.Is(err, generation.ErrRollback) {
		return errors.Join(generation.ErrIncomplete, err)
	}
	return err
}
