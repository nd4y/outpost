package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
	"golang.org/x/sys/unix"
)

func nativeBtrfsExport(ctx context.Context, input, keyFile, output string) (map[string]any, error) {
	raw, err := worker.ReadPrivate(input, 65536)
	if err != nil {
		return nil, err
	}
	var request capture.BtrfsProducerRequest
	if worker.DecodeInput(raw, &request, 65536) != nil || !filepath.IsAbs(output) ||
		filepath.Clean(output) != output || filepath.Base(output) == "/" {
		return nil, errUsage
	}
	raw, err = worker.ReadPrivate(keyFile, 4096)
	if err != nil {
		return nil, err
	}
	var producer struct {
		PrivateKey ed25519.PrivateKey `json:"privateKey"`
	}
	if worker.DecodeInput(raw, &producer, 4096) != nil {
		return nil, errUsage
	}
	parent, err := localfs.OpenRoot(filepath.Dir(output))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	info, err := parent.Stat(".")
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, capture.ErrInvalid
	}
	for _, path := range []string{request.Profile.Source.Path, request.Profile.Staging.Path, request.Profile.StateDirectory} {
		tree, err := localfs.OpenRoot(path)
		if err != nil {
			return nil, err
		}
		err = errors.Join(localfs.Disjoint(ctx, tree, parent), tree.Close())
		if err != nil {
			return nil, err
		}
	}
	manifest, err := capture.ProduceBtrfsExport(ctx, request, producer.PrivateKey)
	if err != nil {
		return nil, err
	}
	current, err := localfs.OpenRoot(filepath.Dir(output))
	if err != nil {
		return nil, err
	}
	defer current.Close()
	observed, err := current.Stat(".")
	if err != nil || !os.SameFile(info, observed) || observed.Mode().Perm()&0077 != 0 {
		return nil, capture.ErrInvalid
	}
	if err = publishBtrfsManifest(parent, filepath.Base(output), manifest); err != nil {
		return nil, err
	}
	return map[string]any{"format": capture.PreparedExportFormat, "operation": storage.Hash(manifest), "producerOperation": request.Operation, "attestation": "producer-signed"}, nil
}

func publishBtrfsManifest(parent *os.Root, name string, manifest []byte) error {
	dir, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	existing := func() error {
		raw, err := worker.ReadPrivateAt(parent, name, capture.MaxPreparedExport)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, manifest) {
			return os.ErrExist
		}
		return dir.Sync()
	}
	if err := existing(); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	stage := ".outpost-prepared-" + hex.EncodeToString(nonce[:])
	if err := writeNewAt(parent, stage, manifest); err != nil {
		return err
	}
	defer parent.Remove(stage)
	if err = unix.Renameat2(int(dir.Fd()), stage, int(dir.Fd()), name, unix.RENAME_NOREPLACE); errors.Is(err, os.ErrExist) {
		return existing()
	}
	if err != nil {
		return err
	}
	return dir.Sync()
}
