package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func exerciseNativeRemoval(t *testing.T, ctx context.Context, profile BtrfsProducerProfile, producerKey ed25519.PrivateKey, first, second, original []byte) {
	t.Helper()
	runtime := teststore.Root(t)
	root, err := localfs.OpenRoot(runtime)
	must(t, err)
	defer root.Close()
	makeOptions := func(manifest []byte, directory string) PreparedProviderOptions {
		return PreparedProviderOptions{Parent: root, Directory: directory, Operation: storage.Hash(manifest), Tree: profile.Staging,
			Trust: profile.Trust, Manifest: manifest, Initialize: true, NativeReleaseTickets: true}
	}
	firstManifest, err := VerifyPreparedExport(first, profile.Trust, time.Now())
	must(t, err)
	secondManifest, err := VerifyPreparedExport(second, profile.Trust, time.Now())
	must(t, err)
	firstPath := filepath.Join(profile.Staging.Path, firstManifest.Root)
	secondPath := filepath.Join(profile.Staging.Path, secondManifest.Root)
	owner, err := filekit.NewOwner()
	must(t, err)
	store, err := filekit.OpenStore(filepath.Join(runtime, "kits"), owner, true)
	must(t, err)
	defer store.Close()
	kit, err := store.Backup(ctx, filepath.Join(firstPath, "sample"), filekit.BackupOptions{Names: []string{"sample"}})
	must(t, err)
	writer, signing, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	maintenance, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("release-proof-fixture")), Epoch: 1, Writer: writer, Maintenance: maintenance}
	replicaDir := filepath.Join(runtime, "replica")
	must(t, os.Mkdir(replicaDir, 0700))
	replica, err := generation.Open(replicaDir, trust, true)
	must(t, err)
	defer replica.Close()
	id, err := generation.Seal(ctx, store, []string{kit.Version}, replica, generation.Catalog{Format: generation.Format,
		Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: firstManifest.SnapshotUnix, Policy: 1}, signing)
	must(t, err)
	must(t, replica.VerifyComplete(ctx, id))
	firstOptions := makeOptions(first, "first-provider")
	provider, err := OpenPreparedProvider(ctx, firstOptions)
	must(t, err)
	defer provider.Close()
	if err = provider.recordNativeRelease(ctx, trust, signing, 1, id, "complete-copy"); !errors.Is(err, ErrInvalid) {
		t.Fatal("unreleased view allowed a native ticket", err)
	}
	must(t, provider.Release(ctx, firstOptions.Operation, firstOptions.Operation))
	raw, _, err := provider.NativeRelease(ctx, trust)
	must(t, err)
	if len(raw) != 0 {
		t.Fatal("ordinary release issued a native ticket")
	}
	if _, err = os.Stat(firstPath); err != nil {
		t.Fatal("ordinary release modified a native snapshot", err)
	}
	must(t, provider.recordNativeRelease(ctx, trust, signing, 1, id, "complete-copy"))
	ticket, status, err := provider.NativeRelease(ctx, trust)
	must(t, err)
	if status == nil || status.TicketSHA256 != storage.Hash(ticket) || status.Generation != id {
		t.Fatal("signed native ticket was not retained")
	}
	if _, err = DisposeBtrfsSnapshot(ctx, profile, second, ticket, trust, producerKey); !errors.Is(err, ErrInvalid) {
		t.Fatal("a valid ticket was accepted for a different snapshot", err)
	}
	moved := firstPath + "-fixture-moved"
	must(t, os.Rename(firstPath, moved))
	must(t, os.Mkdir(firstPath, 0700))
	if _, err = DisposeBtrfsSnapshot(ctx, profile, first, ticket, trust, producerKey); !errors.Is(err, ErrInvalid) {
		t.Fatal("replacement directory was accepted for deletion", err)
	}
	if _, err = os.Stat(moved); err != nil {
		t.Fatal("original snapshot was removed while its path was substituted", err)
	}
	must(t, os.Remove(firstPath))
	must(t, os.Rename(moved, firstPath))
	var removed NativeDisposalReceipt
	if executable := os.Getenv("OUTPOST_BTRFS_CLI"); executable != "" {
		write := func(name string, raw []byte) string {
			t.Helper()
			path := filepath.Join(runtime, name)
			must(t, os.WriteFile(path, raw, 0600))
			return path
		}
		manifestFile := write("first-manifest.json", first)
		ticketFile := write("first-ticket.json", ticket)
		raw, err := json.Marshal(trust)
		must(t, err)
		trustFile := write("source-trust.json", raw)
		raw, err = json.Marshal(map[string]any{"privateKey": producerKey})
		must(t, err)
		keyFile := write("producer-key.json", raw)
		raw, err = json.Marshal(map[string]any{"format": "outpost-btrfs-disposal-request-1", "profile": profile,
			"manifestFile": manifestFile, "ticketFile": ticketFile})
		must(t, err)
		input := write("dispose.json", raw)
		out, err := exec.CommandContext(ctx, executable, "source-native-btrfs-dispose", "--input", input, "--trust", trustFile, "--key", keyFile).CombinedOutput()
		if err != nil {
			t.Fatalf("native producer disposal CLI: %v: %s", err, out)
		}
		var envelope struct{ Result NativeDisposalReceipt }
		must(t, json.Unmarshal(out, &envelope))
		removed = envelope.Result
	} else {
		removed, err = DisposeBtrfsSnapshot(ctx, profile, first, ticket, trust, producerKey)
		must(t, err)
	}
	again, err := DisposeBtrfsSnapshot(ctx, profile, first, ticket, trust, producerKey)
	must(t, err)
	if removed.TicketSHA256 != storage.Hash(ticket) || removed.RemovedUnix != again.RemovedUnix ||
		removed.PathAbsentUnix != again.PathAbsentUnix || !bytes.Equal(removed.Signature, again.Signature) {
		t.Fatal("disposal replay changed its signed receipt")
	}
	if removed.RemovedUnix < removed.IntentUnix || removed.PathAbsentUnix < removed.RemovedUnix {
		t.Fatal("durable native removal observation missing")
	}
	if _, err = os.Stat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removed snapshot remains visible", err)
	}
	if _, err = os.Stat(secondPath); err != nil {
		t.Fatal("unrelated snapshot was affected", err)
	}
	dest := filepath.Join(runtime, "restored")
	_, err = generation.RecoverMaterialized(ctx, replicaDir, id, trust, owner, generation.RecoverySelection{}, dest)
	must(t, err)
	got, err := os.ReadFile(filepath.Join(dest, "sample"))
	must(t, err)
	if !bytes.Equal(got, original) {
		t.Fatal("independent restore after native disposal differs")
	}
	lost := errors.New("native disposal response lost")
	secondOptions := makeOptions(second, "second-provider")
	pending, err := OpenPreparedProvider(ctx, secondOptions)
	must(t, err)
	defer pending.Close()
	must(t, pending.Release(ctx, secondOptions.Operation, secondOptions.Operation))
	must(t, pending.recordNativeRelease(ctx, trust, signing, 2, id, PairedSplitCoverage))
	secondTicket, _, err := pending.NativeRelease(ctx, trust)
	must(t, err)
	if _, err = disposeBtrfsSnapshot(ctx, profile, second, secondTicket, trust, producerKey, func(point string) error {
		if point == "native-snapshot-kernel-removed" {
			return lost
		}
		return nil
	}); !errors.Is(err, lost) {
		t.Fatal("missing interruption at native disposal", err)
	}
	absence, err := DisposeBtrfsSnapshot(ctx, profile, second, secondTicket, trust, producerKey)
	must(t, err)
	if absence.RemovedUnix != 0 || absence.PathAbsentUnix < absence.IntentUnix {
		t.Fatal("lost removal reply invented a success time or failed to reconcile absence")
	}
	t.Log("real kernel removal fenced the exact snapshot; interruption recorded only observed absence on restart")
}
