package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerReplicaMetadataCheckpointActualCLI(t *testing.T) {
	binary := os.Getenv("OUTPOST_METADATA_CHECKPOINT_CLI")
	if binary == "" {
		t.Skip("selected built CLI required")
	}
	executable, err := os.ReadFile(binary)
	must(t, err)
	if expected := os.Getenv("OUTPOST_METADATA_CHECKPOINT_CLI_SHA256"); !storage.ID(expected) || storage.Hash(executable) != expected {
		t.Fatal("selected CLI hash differs")
	}
	f := newFixture(t)
	f.endpoint(t, nil)
	ctx := context.Background()
	source, err := generation.Open(filepath.Join(DomainDirectory(f.nodes[0].dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, err)
	defer source.Close()
	b := boundBootstrapFixture(t, f)
	w, close, err := b.Open(true)
	must(t, err)
	defer close()
	f.nodes[0] = w
	// Seed the new, independently enrolled runtime before its first policy.
	// The maintenance fixture installs the first signed command authority.
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	must(t, os.MkdirAll(dir, 0700))
	seed, err := generation.Open(dir, f.domain.Trust, true)
	must(t, err)
	raw, err := source.Catalog(ctx, f.generation)
	must(t, err)
	_, err = seed.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) { return source.ReadObject(ctx, f.generation, ref) })
	must(t, err)
	must(t, seed.Close())
	r, head, _ := maintenanceCommandFixture(t, f)
	must(t, w.EnableReplicaIndexCopy(ctx, f.domain.Trust.Domain))
	r, err = w.openReplicaAt(w.relative(dir), f.domain.Trust, false)
	must(t, err)
	defer r.Close()
	operation := storage.Hash([]byte("CLI pending plan"))
	permission := maintenancePermit(t, f, r, operation, f.maintenance, f.generation)
	interrupted := errors.New("stop after durable retirement")
	r.Fault = func(point string) error {
		if point == "retirement-durable" {
			return interrupted
		}
		return nil
	}
	if _, err := r.Maintain(ctx, permission); !errors.Is(err, interrupted) {
		t.Fatal("pending operation not reached", err)
	}
	r.Fault = nil
	bootstrap, err := json.Marshal(b)
	must(t, err)
	profile := filepath.Join(f.base, "bootstrap.json")
	must(t, os.WriteFile(profile, bootstrap, 0600))
	checkpoint := filepath.Join(f.base, "plan-checkpoint.json")
	run := func(args []string, success bool) map[string]any {
		t.Helper()
		command := exec.CommandContext(t.Context(), binary, args...)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		if (err == nil) != success {
			t.Fatalf("unexpected CLI result %v: stdout=%s stderr=%s", err, &stdout, &stderr)
		}
		if !success {
			return nil
		}
		var response struct {
			Format string         `json:"format"`
			Result map[string]any `json:"result"`
		}
		must(t, json.Unmarshal(stdout.Bytes(), &response))
		if response.Format != "outpost-cli-1" || response.Result == nil {
			t.Fatal("unexpected CLI envelope", stdout.String())
		}
		return response.Result
	}
	common := []string{"--bootstrap", profile, "--domain", f.domain.Trust.Domain}
	export := append([]string{"replica-metadata-export"}, common...)
	export = append(export, "--output", checkpoint)
	result := run(export, true)
	plan, err := os.ReadFile(checkpoint)
	must(t, err)
	if result["sha256"] != storage.Hash(plan) || result["format"] != generation.MetadataCheckpointFormat {
		t.Fatal("export did not identify the exact plan", result)
	}
	run(export, false)
	name := filepath.Join(dir, "state.json")
	before, err := os.ReadFile(name)
	must(t, err)
	for _, file := range []string{"state.json", "retention.json", "gc-" + operation + ".json"} {
		must(t, os.Remove(filepath.Join(dir, file)))
	}
	restore := append([]string{"replica-metadata-restore"}, common...)
	restore = append(restore, "--input", checkpoint, "--sha256", storage.Hash(plan))
	must(t, w.lease.WithLock(ctx, func() error { run(restore, false); return nil }))
	wrong := append([]string(nil), restore...)
	wrong[len(wrong)-1] = storage.Hash([]byte("wrong checkpoint"))
	run(wrong, false)
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CLI refusal published a primary index", err)
	}
	foreign := append([]string(nil), restore...)
	for i, value := range foreign {
		if value == "--domain" {
			foreign[i+1] = storage.Hash([]byte("foreign domain"))
			break
		}
	}
	run(foreign, false)
	result = run(restore, true)
	if result["restored"] != true || result["completed"] != true {
		t.Fatal("CLI did not restore combined metadata", result)
	}
	result = run(restore, true)
	if result["restored"] != false || result["completed"] != true {
		t.Fatal("CLI replay rewrote metadata", result)
	}
	after, err := os.ReadFile(filepath.Join(dir, "state.json"))
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("CLI restore changed index")
	}
	_, err = r.Maintain(ctx, permission)
	must(t, err)
	must(t, r.VerifyComplete(ctx, head))
}
