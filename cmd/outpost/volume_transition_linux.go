package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"

	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

func readVolumeOwner(path string) (ed25519.PrivateKey, error) {
	raw, e := worker.ReadPrivate(path, 4096)
	if e != nil {
		return nil, e
	}
	var key struct {
		PrivateKey ed25519.PrivateKey `json:"privateKey"`
	}
	if worker.DecodeInput(raw, &key, 4096) != nil ||
		len(key.PrivateKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(key.PrivateKey, ed25519.NewKeyFromSeed(key.PrivateKey.Seed())) {
		return nil, errUsage
	}
	return key.PrivateKey, nil
}

func transitionWorkerVolume(ctx context.Context, bootstrap, input, output string) (map[string]any, error) {
	b, e := worker.LoadBootstrap(bootstrap)
	if e != nil {
		return nil, e
	}
	if b.Volume.Format != volume.FencedFormat || filepath.Dir(output) != b.VolumeAuthority {
		return nil, errUsage
	}
	root, name, e := openNewDestination(output)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	raw, e := worker.ReadPrivate(input, 4096)
	if e != nil {
		return nil, e
	}
	permit, e := volume.VerifyMove(raw, b.Owner)
	if e != nil {
		return nil, e
	}
	relative, e := filepath.Rel(b.Volume.Root, b.Directory)
	if e != nil {
		return nil, e
	}
	next, e := volume.MoveFenced(ctx, b.Volume, b.Directory, b.VolumeAuthority, b.Owner, raw)
	if e != nil {
		return nil, e
	}
	b.Volume = next
	b.Directory = filepath.Join(next.Root, relative)
	raw, e = json.Marshal(b)
	if e != nil {
		return nil, e
	}
	if e = writeNewAt(root, name, raw); e != nil {
		return nil, e
	}
	return map[string]any{"format": volume.FencedFormat, "operation": permit.Request.Operation, "epoch": next.Epoch, "completed": true}, nil
}

func signVolumeTransition(input, keyPath, output string) (map[string]any, error) {
	raw, e := worker.ReadPrivate(input, 4096)
	if e != nil {
		return nil, e
	}
	var request volume.MoveRequest
	if worker.DecodeInput(raw, &request, 4096) != nil {
		return nil, errUsage
	}
	key, e := readVolumeOwner(keyPath)
	if e != nil {
		return nil, e
	}
	signed, e := volume.SignMove(request, key)
	if e != nil {
		return nil, e
	}
	if e = writeNew(output, signed); e != nil {
		return nil, e
	}
	return map[string]any{"format": volume.MoveFormat, "operation": request.Operation, "signed": true}, nil
}
