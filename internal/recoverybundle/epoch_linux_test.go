package recoverybundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
)

func TestOwnerEpochInitialPreparationRequiresPrivateVolumeAndSeparateKeys(t *testing.T) {
	ctx := context.Background()
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	base := teststore.Root(t)
	observed, err := volume.Probe(ctx, base)
	must(t, err)
	binding, err := volume.Enroll(ctx, base, observed, storage.Hash(pub), 1)
	must(t, err)
	directory := privateDir(t, base, "private")
	profile := EpochProfile{Format: EpochProfileFormat, Volume: binding, Directory: directory,
		Operation: storage.Hash([]byte("initial-key-epoch")), Reason: "initial"}
	out := filepath.Join(directory, "epoch-one")
	_, wrong, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	if _, err = PrepareEpoch(ctx, profile, wrong, out); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong owner opened epoch directory", err)
	}
	receipt, err := PrepareEpoch(ctx, profile, signer, out)
	must(t, err)
	if receipt.Trust.Epoch != 1 || receipt.Prior != nil || receipt.State != "PREPARED" {
		t.Fatal("invalid initial epoch receipt", receipt)
	}
	if _, err = PrepareEpoch(ctx, profile, signer, out); !errors.Is(err, ErrConflict) {
		t.Fatal("existing epoch directory was not protected", err)
	}
	owner, err := filekit.ReadOwner(filepath.Join(out, "data-owner.json"))
	must(t, err)
	if owner.Domain != receipt.Trust.Domain || bytes.Equal(owner.VerifyKey, pub) ||
		bytes.Equal(owner.VerifyKey, receipt.Trust.Writer) || bytes.Equal(owner.VerifyKey, receipt.Trust.Maintenance) {
		t.Fatal("data-owner key was not separated")
	}
	for _, name := range []string{"data-owner.json", "writer-key.json", "maintenance-key.json", "preparation.json", "trust.json"} {
		info, err := os.Stat(filepath.Join(out, name))
		must(t, err)
		if info.Mode().Perm() != 0600 {
			t.Fatal("epoch artifact is not private", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(out, "preparation.json"))
	must(t, err)
	_, err = VerifyEpochPreparation(raw, pub)
	must(t, err)
	if bytes.Contains(raw, []byte(`"master"`)) || bytes.Contains(raw, []byte(`"privateKey"`)) {
		t.Fatal("preparation receipt contains a private key field")
	}
}
