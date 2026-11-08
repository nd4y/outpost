package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
	"github.com/nd4y/outpost/internal/worker"
)

const uploadPlanRequestFormat = "outpost-upload-plan-request-1"

type uploadPlanRequest struct {
	Format  string            `json:"format"`
	Planner ed25519.PublicKey `json:"planner"`
	Plan    upload.Plan       `json:"plan"`
}

func buildUploadPlan(ctx context.Context, replica, trustFile, keyFile, input, id, output string) (any, error) {
	if !storage.ID(id) || !filepath.IsAbs(replica) || filepath.Clean(replica) != replica {
		return nil, errUsage
	}
	parent, name, err := openNewDestination(output)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	raw, err := worker.ReadPrivate(trustFile, 65536)
	if err != nil {
		return nil, err
	}
	var trust generation.Trust
	if worker.DecodeInput(raw, &trust, 65536) != nil {
		return nil, errUsage
	}
	raw, err = worker.ReadPrivate(input, 65536)
	if err != nil {
		return nil, err
	}
	var request uploadPlanRequest
	if worker.DecodeInput(raw, &request, 65536) != nil || request.Format != uploadPlanRequestFormat {
		return nil, errUsage
	}
	p := request.Plan
	suppliedCatalog := len(p.Catalog) != 0 && !bytes.Equal(bytes.TrimSpace(p.Catalog), []byte("null"))
	if (p.Generation != "" && p.Generation != id) || suppliedCatalog || len(p.Blobs) != 0 || len(p.Signature) != 0 || len(p.Delegation) != 0 {
		return nil, errUsage
	}
	raw, err = worker.ReadPrivate(keyFile, 4096)
	if err != nil {
		return nil, err
	}
	var signer struct {
		PrivateKey ed25519.PrivateKey `json:"privateKey"`
	}
	if worker.DecodeInput(raw, &signer, 4096) != nil || len(signer.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errUsage
	}
	if !bytes.Equal(request.Planner, signer.PrivateKey.Public().(ed25519.PublicKey)) ||
		bytes.Equal(request.Planner, trust.Writer) || bytes.Equal(request.Planner, trust.Maintenance) ||
		time.Now().Unix() >= p.ExpiresUnix {
		return nil, upload.ErrDenied
	}
	root, err := localfs.OpenRoot(replica)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	catalog, err := worker.ReadPrivateAt(root, "catalogs/"+id, generation.MaxCatalog)
	if errors.Is(err, os.ErrNotExist) {
		return nil, generation.ErrIncomplete
	}
	if err != nil {
		return nil, err
	}
	signed, err := upload.BuildFromCatalog(ctx, trust, id, catalog, p, signer.PrivateKey, func(ctx context.Context, object generation.Object) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return worker.ReadPrivateAt(root, "objects/"+object.ID, generation.MaxObject)
	})
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if time.Now().Unix() >= p.ExpiresUnix {
		return nil, upload.ErrDenied
	}
	if err = writeNewAt(parent, name, signed); err != nil {
		return nil, err
	}
	return map[string]any{"format": upload.Format, "generation": id, "operationId": p.Operation, "target": p.Profile.ID(), "digest": storage.Hash(signed)}, nil
}
