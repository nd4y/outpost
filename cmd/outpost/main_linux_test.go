package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/worker"
)

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
