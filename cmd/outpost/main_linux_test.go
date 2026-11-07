package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/sourceagent"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

func TestCLISourceProbeAndCapabilityErrors(t *testing.T) {
	ctx := context.Background()
	base := teststore.Root(t)
	source := filepath.Join(base, "источник с пробелами")
	if e := os.Mkdir(source, 0700); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(base, "source-binding.json")
	args := []string{"source-probe", "--store", source, "--node", storage.Hash([]byte("origin")), "--output", out}
	if _, e := run(ctx, args); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	var b capture.TreeBinding
	if e = json.Unmarshal(raw, &b); e != nil || b.Path != source || b.Format != capture.TreeFormat {
		t.Fatal("invalid source binding", e)
	}
	if _, e = run(ctx, args); !errors.Is(e, os.ErrExist) {
		t.Fatal("probe overwritten", e)
	}
	names, e := os.ReadDir(source)
	if e != nil || len(names) != 0 {
		t.Fatal("probe modified source", e)
	}
	if code, exit := failure(sourceagent.ErrUnsupported); code != "CAPABILITY_UNAVAILABLE" || exit != 5 {
		t.Fatal(code, exit)
	}
	if code, exit := failure(capture.ErrCopies); code != "COPY_THRESHOLD_PENDING" || exit != 5 {
		t.Fatal(code, exit)
	}
}

func TestCLIVolumeProbeAndEnrollmentBindExactEmptyTarget(t *testing.T) {
	ctx := context.Background()
	base := teststore.Root(t)
	root := filepath.Join(base, "volume")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	probe := filepath.Join(base, "probe.json")
	binding := filepath.Join(base, "binding.json")
	node := storage.Hash([]byte("node"))
	if _, e := run(ctx, []string{"volume-probe", "--store", root, "--output", probe}); e != nil {
		t.Fatal(e)
	}
	args := []string{"volume-enroll", "--store", root, "--input", probe, "--node", node, "--epoch", "1", "--output", binding}
	if _, e := run(ctx, args); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(binding)
	if e != nil {
		t.Fatal(e)
	}
	var enrolled volume.Binding
	if e = json.Unmarshal(raw, &enrolled); e != nil || enrolled.Scope != node || enrolled.Epoch != 1 {
		t.Fatal("wrong binding", e)
	}
	state, e := enrolled.Open(ctx, filepath.Join(root, "worker"), true)
	if e != nil {
		t.Fatal(e)
	}
	state.Close()
	if _, e = run(ctx, args); e == nil {
		t.Fatal("overwrote binding")
	}
	if e = os.Remove(filepath.Join(root, volume.Sentinel)); e != nil {
		t.Fatal(e)
	}
	args[len(args)-1] = filepath.Join(base, "different-binding.json")
	if _, e = run(ctx, args); !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("missing marker reinitialized", e)
	}
}

func TestCLIRestoresMaterializedReplicaWithoutIndexOrSource(t *testing.T) {
	root := teststore.Root(t)
	ctx := context.Background()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	owner, e := filekit.NewOwner()
	must(e)
	writer, key, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	maintenance, _, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("repository")), Epoch: 1, Writer: writer, Maintenance: maintenance}
	sourceDir := filepath.Join(root, "source-cache")
	s, e := filekit.OpenStore(sourceDir, owner, true)
	must(e)
	input := filepath.Join(root, "input")
	must(os.WriteFile(input, []byte("independent whole replica"), 0600))
	stats, e := s.Backup(ctx, input, filekit.BackupOptions{Names: []string{"private/данные", "outside-alias"}})
	must(e)
	replicaDir := filepath.Join(root, "replica")
	must(os.Mkdir(replicaDir, 0700))
	replica, e := generation.Open(replicaDir, trust, true)
	must(e)
	id, e := generation.Seal(ctx, s, []string{stats.Version}, replica, generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1}, key)
	must(e)
	must(s.Close())
	must(replica.Close())
	must(os.RemoveAll(sourceDir))
	must(os.Remove(input))
	must(os.Remove(filepath.Join(replicaDir, "state.json")))
	owner.SigningKey = nil
	ownerFile := filepath.Join(root, "recovery-owner.json")
	must(filekit.WriteOwner(ownerFile, owner))
	trustFile := filepath.Join(root, "public-trust.json")
	raw, e := json.Marshal(trust)
	must(e)
	must(os.WriteFile(trustFile, raw, 0600))
	selectionFile := filepath.Join(root, "selection.json")
	raw, e = json.Marshal(generation.RecoverySelection{Directory: "private"})
	must(e)
	must(os.WriteFile(selectionFile, raw, 0600))
	out := filepath.Join(root, "restore")
	value, e := run(ctx, []string{"restore-replica", "--key", ownerFile, "--trust", trustFile, "--store", replicaDir, "--generation", id, "--input", selectionFile, "--output", out})
	must(e)
	receipt := value.(generation.RecoveryReceipt)
	if receipt.Restored.Files != 1 || receipt.Restored.Aliases != 0 || receipt.Generation != id || !receipt.CheckpointMatch {
		t.Fatal("incorrect receipt", receipt)
	}
	body, e := os.ReadFile(filepath.Join(out, "private/данные"))
	must(e)
	if string(body) != "independent whole replica" {
		t.Fatal("wrong content")
	}
	if _, e = os.Lstat(filepath.Join(out, "outside-alias")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unselected alias restored")
	}
	raw, e = json.Marshal(value)
	must(e)
	if bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte("данные")) {
		t.Fatal("private names in summary")
	}
}

func TestCLIVerifiesFrozenIndependentV1Kit(t *testing.T) {
	root := teststore.Root(t)
	base, e := filepath.Abs("../../internal/filekit/testdata/v1")
	if e != nil {
		t.Fatal(e)
	}
	raw := teststore.PublicV1Owner()
	key := filepath.Join(root, "recovery.json")
	if e = os.WriteFile(key, raw, 0600); e != nil {
		t.Fatal(e)
	}
	raw, e = os.ReadFile(filepath.Join(base, "manifest.fixture"))
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct{ Version string }
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	kit := filepath.Join(root, "kit")
	if e = os.CopyFS(kit, os.DirFS(filepath.Join(base, "kit"))); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(kit, "root.fixture"), filepath.Join(kit, "kit.json")); e != nil {
		t.Fatal(e)
	}
	value, e := run(context.Background(), []string{"verify-kit", "--key", key, "--store", kit, "--version", fixture.Version})
	if e != nil {
		t.Fatal(e)
	}
	result := value.(map[string]any)
	if result["version"] != fixture.Version || result["fileKitFormat"] != filekit.Format || result["aliases"] != 2 {
		t.Fatal("wrong reference result", result)
	}
	encoded, _ := json.Marshal(value)
	if bytes.Contains(encoded, []byte("старый файл")) {
		t.Fatal("plaintext path in shared result")
	}
}

func TestCLIConfigSigningAndNoOverwriteWithUnicodePaths(t *testing.T) {
	root := teststore.Root(t)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	private := filepath.Join(root, "ключ владельца.json")
	raw, _ := json.Marshal(map[string]any{"privateKey": key})
	if e = os.WriteFile(private, raw, 0600); e != nil {
		t.Fatal(e)
	}
	node := storage.Hash([]byte("node"))
	config := control.Config{Format: control.Format, Node: node, Revision: 1, NotBefore: 1, ExpiresUnix: 4102444800, Limits: control.Limits{Parallel: 1, AttemptMillis: 1000, PollSeconds: 1, CapacityBytes: 1 << 30, ReserveBytes: 1 << 28, SpoolBytes: 1 << 26, TelemetryBytes: 1 << 20}}
	// Unknown recipients and absent registry entries cannot be signed even by an owner.
	input := filepath.Join(root, "input.json")
	raw, _ = json.Marshal(config)
	if e = os.WriteFile(input, raw, 0600); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(root, "signed.json")
	args := []string{"config-sign", "--key", private, "--input", input, "--output", output}
	if _, e = run(context.Background(), args); e == nil {
		t.Fatal("signed unknown node")
	}
	if _, e = os.Stat(output); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("failed signing published an output")
	}
	config.Nodes = []policy.Node{{ID: node, Class: "trusted"}}
	raw, _ = json.Marshal(config)
	if e = os.WriteFile(input, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = run(context.Background(), args); e != nil {
		t.Fatal(e)
	}
	signed, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = control.Verify(signed, pub, node); e != nil {
		t.Fatal(e)
	}
	// A second signing command must not replace an already distributed result.
	config.Revision++
	raw, _ = json.Marshal(config)
	if e = os.WriteFile(input, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = run(context.Background(), args); !errors.Is(e, os.ErrExist) {
		t.Fatal("overwrote signed output")
	}
	got, e := os.ReadFile(output)
	if e != nil || string(got) != string(signed) {
		t.Fatal("existing signed output changed")
	}
}
func TestCLIStableErrorsDoNotExposeSensitivePaths(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
		exit int
	}{{errUsage, "INVALID_ARGUMENT", 2}, {worker.ErrDenied, "DENIED", 3}, {control.ErrRollback, "CONFLICT", 5}, {worker.ErrCapacity, "CAPACITY_BLOCKED", 6}, {context.Canceled, "CANCELED", 130}, {&os.PathError{Op: "open", Path: "private/source/name", Err: os.ErrNotExist}, "UNAVAILABLE", 7}} {
		code, exit := failure(test.err)
		if code != test.code || exit != test.exit {
			t.Fatalf("wrong public error %s %d", code, exit)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"worker-run", "--unexpected", "secret"}, {"worker-status", "extra"}} {
		if _, e := run(context.Background(), args); !errors.Is(e, errUsage) {
			t.Fatal("invalid command accepted")
		}
	}
}
