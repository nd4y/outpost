package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

func TestOwnerEpochCLIProducesIndependentOldAndNewRecovery(t *testing.T) {
	if os.Getenv("OUTPOST_RECOVERY_DISTRIBUTION") == "" {
		t.Skip("selected built distribution required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 270*time.Second)
	defer cancel()
	old := newFixture(t)
	profile := ownerExportProfile(t, old)
	toolManifest, err := os.ReadFile(filepath.Join(profile.ToolsDirectory, "manifest.json"))
	must(t, err)
	var tool struct {
		Revision string `json:"revision"`
	}
	must(t, json.Unmarshal(toolManifest, &tool))
	write := func(path string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		must(t, err)
		must(t, os.WriteFile(path, raw, 0600))
	}
	export := func(f *fixture, p RecoveryExportProfile, suffix string) (string, string, recoverybundle.Receipt) {
		t.Helper()
		path := filepath.Join(p.Directory, suffix+".tar")
		must(t, f.a.Next(ctx))
		must(t, f.a.Run(ctx))
		t.Logf("%s fixture capture published", suffix)
		receipt, err := f.a.ExportRecovery(ctx, p, tool.Revision, path)
		must(t, err)
		if !receipt.CheckpointPresent || receipt.Sequence != 1 || receipt.VerifiedUnix < 1 {
			t.Fatal("missing authentic epoch checkpoint")
		}
		input, err := recoverybundle.Open(path)
		must(t, err)
		out := filepath.Join(p.Directory, suffix+"-read")
		_, err = recoverybundle.Extract(ctx, input, receipt.SHA256, out)
		must(t, errors.Join(err, input.Close()))
		t.Logf("%s package verified and extracted", suffix)
		return path, out, receipt
	}
	oldBytes, err := os.ReadFile(filepath.Join(old.tree, "private.bin"))
	must(t, err)
	oldArchive, oldKit, oldReceipt := export(old, profile, "old-epoch")
	binary := packagedReader(t, oldKit)
	command := func(wantSuccess bool, args ...string) []byte {
		t.Helper()
		raw, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if (err == nil) != wantSuccess || bytes.Contains(raw, []byte(`"privateKey"`)) ||
			bytes.Contains(raw, []byte(`"master"`)) || bytes.Contains(raw, []byte(old.base)) {
			t.Fatalf("unexpected or unredacted owner CLI result: %v", err)
		}
		return raw
	}
	ownerPublic := old.ownerSigner.Public().(ed25519.PublicKey)
	ownerRoot := filepath.Join(old.base, "epoch-owner")
	must(t, os.Mkdir(ownerRoot, 0700))
	observed, err := volume.Probe(ctx, ownerRoot)
	must(t, err)
	binding, err := volume.Enroll(ctx, ownerRoot, observed, storage.Hash(ownerPublic), 1)
	must(t, err)
	private := filepath.Join(ownerRoot, "private")
	must(t, os.Mkdir(private, 0700))
	secret := filepath.Join(private, "owner-authority.json")
	trust := filepath.Join(private, "owner-public.json")
	request := filepath.Join(private, "request.json")
	write(secret, map[string]any{"privateKey": old.ownerSigner})
	write(trust, map[string]any{"publicKey": ownerPublic})
	p := recoverybundle.EpochProfile{Format: recoverybundle.EpochProfileFormat, Volume: binding, Directory: private,
		Operation: storage.Hash([]byte("owner-rotation-fixture")), Reason: "scheduled-rotation",
		Prior: &recoverybundle.PriorPackage{Path: oldArchive, SHA256: storage.Hash([]byte("wrong receipt digest"))}}
	write(request, p)
	prepared := filepath.Join(private, "prepared")
	create := []string{"owner-epoch-create", "--input", request, "--key", secret, "--output", prepared}
	command(false, create...)
	if _, err = os.Stat(prepared); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong previous package caused a key write", err)
	}
	p.Prior.SHA256 = oldReceipt.SHA256
	write(request, p)
	var receipt struct {
		Format string
		Result recoverybundle.EpochPreparation
	}
	must(t, json.Unmarshal(command(true, create...), &receipt))
	if receipt.Format != "outpost-cli-1" || receipt.Result.State != "PREPARED" || receipt.Result.Prior == nil ||
		receipt.Result.Prior.PackageSHA256 != oldReceipt.SHA256 || receipt.Result.Prior.Generation != oldReceipt.Generation ||
		receipt.Result.Prior.VerifiedUnix != oldReceipt.VerifiedUnix || receipt.Result.Trust.Epoch != oldReceipt.Epoch+1 {
		t.Fatal("preparation did not bind the exact prior epoch")
	}
	receiptPath := filepath.Join(prepared, "preparation.json")
	before, err := os.ReadFile(receiptPath)
	must(t, err)
	command(false, create...)
	after, err := os.ReadFile(receiptPath)
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("a repeated command changed prepared material")
	}
	command(true, "owner-epoch-inspect", "--input", receiptPath, "--trust", trust)
	changed := receipt.Result
	changed.Operation = storage.Hash([]byte("different operation"))
	wrong := filepath.Join(private, "changed-receipt.json")
	write(wrong, changed)
	command(false, "owner-epoch-inspect", "--input", wrong, "--trust", trust)
	data, err := filekit.ReadOwner(filepath.Join(prepared, "data-owner.json"))
	must(t, err)
	raw, err := os.ReadFile(filepath.Join(prepared, "writer-key.json"))
	must(t, err)
	var writer struct {
		PrivateKey ed25519.PrivateKey `json:"privateKey"`
	}
	must(t, json.Unmarshal(raw, &writer))
	if data.Domain == old.owner.Domain || bytes.Equal(data.Master, old.owner.Master) ||
		bytes.Equal(data.VerifyKey, old.owner.VerifyKey) || bytes.Equal(writer.PrivateKey, old.writer) {
		t.Fatal("prepared epoch reused old key material")
	}
	next := newFixtureWithKeys(t, 1800, nil, &fixtureEpoch{data, receipt.Result.Trust, writer.PrivateKey})
	nextBytes := bytes.Repeat([]byte("second epoch payload"), 14000)
	must(t, os.WriteFile(filepath.Join(next.tree, "private.bin"), nextBytes, 0640))
	_, nextKit, nextReceipt := export(next, ownerExportProfile(t, next), "next-epoch")
	if nextReceipt.Epoch != receipt.Result.Trust.Epoch || nextReceipt.Repository != receipt.Result.Trust.Repository {
		t.Fatal("successor package was not bound to the prepared epoch")
	}
	for _, f := range []*fixture{old, next} {
		must(t, f.a.Close())
		f.a = nil
		f.server.Close()
		must(t, os.Rename(f.tree, f.tree+"-unavailable"))
		must(t, os.Rename(f.b.Local.Volume.Root, f.b.Local.Volume.Root+"-unavailable"))
	}
	restore := func(f *fixture, kit, id, output string, wantSuccess bool) {
		t.Helper()
		command(wantSuccess, "restore-replica", "--store", f.replicaPath, "--generation", id, "--output", output,
			"--key", filepath.Join(kit, "recovery-owner.json"), "--trust", filepath.Join(kit, "trust.json"))
	}
	oldOut, nextOut := filepath.Join(private, "old-restored"), filepath.Join(private, "next-restored")
	restore(old, oldKit, oldReceipt.Generation, oldOut, true)
	restore(next, nextKit, nextReceipt.Generation, nextOut, true)
	for _, check := range []struct {
		output string
		want   []byte
	}{{oldOut, oldBytes}, {nextOut, nextBytes}} {
		got, err := os.ReadFile(filepath.Join(check.output, "private.bin"))
		must(t, err)
		if !bytes.Equal(got, check.want) {
			t.Fatal("wrong bytes in independently restored epoch")
		}
	}
	cross := filepath.Join(private, "cross-epoch")
	restore(next, oldKit, nextReceipt.Generation, cross, false)
	if _, err = os.Stat(cross); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cross-epoch restore published output", err)
	}
	t.Log("both distinct key epochs restored with their exact packages after source and receiver shutdown")
}
