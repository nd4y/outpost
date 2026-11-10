package recoverybundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

const EpochProfileFormat = "outpost-owner-epoch-request-1"
const EpochPreparationFormat = "outpost-owner-epoch-preparation-1"
const MaxEpochDocument = 16384

type PriorPackage struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type EpochProfile struct {
	Format    string         `json:"format"`
	Volume    volume.Binding `json:"volume"`
	Directory string         `json:"directory"`
	Operation string         `json:"operationId"`
	Reason    string         `json:"reason"`
	Prior     *PriorPackage  `json:"prior,omitempty"`
}

type PriorEpoch struct {
	Domain        string `json:"domain"`
	Repository    string `json:"repository"`
	Epoch         uint64 `json:"epoch"`
	Generation    string `json:"generation"`
	VerifiedUnix  int64  `json:"verifiedUnix"`
	PackageSHA256 string `json:"packageSHA256"`
}

type EpochPreparation struct {
	Format      string           `json:"format"`
	State       string           `json:"state"`
	Actor       string           `json:"actor"`
	Operation   string           `json:"operationId"`
	Reason      string           `json:"reason"`
	CreatedUnix int64            `json:"createdUnix"`
	Trust       generation.Trust `json:"trust"`
	Prior       *PriorEpoch      `json:"prior,omitempty"`
	Signature   []byte           `json:"signature,omitempty"`
}

func validEpochReason(reason string, prior bool) bool {
	if !prior {
		return reason == "initial"
	}
	return reason == "scheduled-rotation" || reason == "key-compromise" || reason == "placement-change"
}

func VerifyEpochPreparation(raw []byte, owner ed25519.PublicKey) (EpochPreparation, error) {
	var result EpochPreparation
	if len(owner) != ed25519.PublicKeySize || document(raw, &result, MaxEpochDocument) != nil ||
		result.Format != EpochPreparationFormat || result.State != "PREPARED" || result.Actor != storage.Hash(owner) ||
		!storage.ID(result.Operation) || !validEpochReason(result.Reason, result.Prior != nil) || result.CreatedUnix < 1 ||
		!storage.ID(result.Trust.Domain) || !storage.ID(result.Trust.Repository) ||
		len(result.Trust.Writer) != ed25519.PublicKeySize || len(result.Trust.Maintenance) != ed25519.PublicKeySize ||
		bytes.Equal(result.Trust.Writer, result.Trust.Maintenance) {
		return EpochPreparation{}, ErrInvalid
	}
	if result.Prior == nil {
		if result.Trust.Epoch != 1 {
			return EpochPreparation{}, ErrInvalid
		}
	} else {
		prior := result.Prior
		if !storage.ID(prior.Domain) || !storage.ID(prior.Repository) || !storage.ID(prior.Generation) || !storage.ID(prior.PackageSHA256) ||
			prior.VerifiedUnix < 1 || prior.VerifiedUnix > result.CreatedUnix || prior.Epoch == 0 || prior.Epoch == math.MaxUint64 ||
			result.Trust.Epoch != prior.Epoch+1 || result.Trust.Domain == prior.Domain || result.Trust.Repository == prior.Repository {
			return EpochPreparation{}, ErrInvalid
		}
	}
	signature := result.Signature
	result.Signature = nil
	message, err := json.Marshal(result)
	if err != nil || !ed25519.Verify(owner, append([]byte(EpochPreparationFormat+"\x00"), message...), signature) {
		return EpochPreparation{}, ErrDenied
	}
	result.Signature = signature
	return result, nil
}

func readPriorEpoch(ctx context.Context, p *PriorPackage) (*PriorEpoch, error) {
	if p == nil {
		return nil, nil
	}
	f, err := Open(p.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	receipt, err := Inspect(ctx, f, p.SHA256)
	if err != nil {
		return nil, err
	}
	if !receipt.CheckpointPresent || receipt.Epoch == math.MaxUint64 {
		return nil, ErrInvalid
	}
	return &PriorEpoch{Domain: receipt.Domain, Repository: receipt.Repository, Epoch: receipt.Epoch,
		Generation: receipt.Generation, VerifiedUnix: receipt.VerifiedUnix, PackageSHA256: receipt.SHA256}, nil
}

// PrepareEpoch creates a distinct, offline data domain and repository. The
// result is an owner-signed preparation receipt, not an enrollment or grant.
func PrepareEpoch(ctx context.Context, p EpochProfile, authority ed25519.PrivateKey, output string) (EpochPreparation, error) {
	if len(authority) != ed25519.PrivateKeySize || !bytes.Equal(authority, ed25519.NewKeyFromSeed(authority[:ed25519.SeedSize])) ||
		p.Format != EpochProfileFormat || !storage.ID(p.Operation) || !validEpochReason(p.Reason, p.Prior != nil) ||
		filepath.Dir(output) != p.Directory {
		return EpochPreparation{}, ErrInvalid
	}
	ownerPublic := authority.Public().(ed25519.PublicKey)
	actor := storage.Hash(ownerPublic)
	if p.Volume.Scope != actor {
		return EpochPreparation{}, ErrDenied
	}
	root, name, err := privateParent(output)
	if err != nil {
		return EpochPreparation{}, err
	}
	defer root.Close()
	guard := func() error { return p.Volume.CheckHandle(ctx, p.Directory, root) }
	if err = guard(); err != nil {
		return EpochPreparation{}, err
	}
	prior, err := readPriorEpoch(ctx, p.Prior)
	if err != nil {
		return EpochPreparation{}, err
	}
	epoch := uint64(1)
	created := time.Now().Unix()
	if prior != nil {
		if prior.VerifiedUnix > created {
			return EpochPreparation{}, ErrInvalid
		}
		epoch = prior.Epoch + 1
	}
	stage, err := reserve(ctx, root, name, true)
	if err != nil {
		return EpochPreparation{}, err
	}
	destination, err := localfs.OpenAt(root, stage, false)
	if err != nil {
		return EpochPreparation{}, err
	}
	defer destination.Close()
	data, err := filekit.NewOwner()
	if err != nil {
		return EpochPreparation{}, err
	}
	writer, writerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return EpochPreparation{}, err
	}
	maintenance, maintenanceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return EpochPreparation{}, err
	}
	var repository [32]byte
	if _, err = rand.Read(repository[:]); err != nil {
		return EpochPreparation{}, err
	}
	trust := generation.Trust{Domain: data.Domain, Repository: storage.Hash(repository[:]), Epoch: epoch, Writer: writer, Maintenance: maintenance}
	result := EpochPreparation{Format: EpochPreparationFormat, State: "PREPARED", Actor: actor, Operation: p.Operation,
		Reason: p.Reason, CreatedUnix: created, Trust: trust, Prior: prior}
	message, err := json.Marshal(result)
	if err != nil {
		return EpochPreparation{}, err
	}
	result.Signature = ed25519.Sign(authority, append([]byte(EpochPreparationFormat+"\x00"), message...))
	type privateKey struct {
		PrivateKey ed25519.PrivateKey `json:"privateKey"`
	}
	for _, artifact := range []struct {
		name  string
		value any
	}{
		{"data-owner.json", data},
		{"writer-key.json", privateKey{writerKey}},
		{"maintenance-key.json", privateKey{maintenanceKey}},
		{"trust.json", trust},
		{"preparation.json", result},
	} {
		if err = guard(); err != nil {
			return EpochPreparation{}, err
		}
		if err = writeEpochArtifact(destination, artifact.name, artifact.value); err != nil {
			return EpochPreparation{}, err
		}
	}
	if err = syncRoot(destination); err != nil {
		return EpochPreparation{}, err
	}
	if err = guard(); err != nil {
		return EpochPreparation{}, err
	}
	if err = publishPrivateDirectory(ctx, root, destination, output, stage, name); err != nil {
		return EpochPreparation{}, err
	}
	return result, nil
}

func writeEpochArtifact(root *os.Root, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := localfs.OpenFile(root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	return errors.Join(err, syncedFile{f}.Close())
}
