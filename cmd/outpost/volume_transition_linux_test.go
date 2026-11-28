package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

func TestCLIFencedVolumePermitKeepsPrivateOwnerKeyOffline(t *testing.T) {
	owner, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	work := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		path := filepath.Join(work, name)
		body, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	key := write("owner.json", map[string]any{"privateKey": signer})
	req := volume.MoveRequest{Format: volume.MoveFormat, Operation: storage.Hash([]byte("example transition")),
		Current:   volume.Binding{Format: volume.FencedFormat, Root: "/original", Epoch: 3, FSID: [2]int32{4, 5}},
		Directory: "/original/worker", NextRoot: "/target", Probe: volume.Observation{FSID: [2]int32{6, 7}}}
	input := write("request.json", req)
	permit := filepath.Join(work, "permit.json")
	if _, e = run(t.Context(), []string{"worker-volume-transition-sign", "--input", input, "--key", key, "--output", permit}); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(key); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(permit)
	if e != nil {
		t.Fatal(e)
	}
	checked, e := volume.VerifyMove(raw, owner)
	if e != nil || checked.Request != req {
		t.Fatal("signed request changed", e)
	}
	output := filepath.Join(work, "worker-moved.json")
	if _, e = run(t.Context(), []string{"worker-volume-transition", "--bootstrap", filepath.Join(work, "absent.json"),
		"--input", permit, "--output", output}); e == nil {
		t.Fatal("transition admitted when bootstrap was unavailable")
	}
	if _, e = os.Lstat(output); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("failed transition created a bootstrap", e)
	}
}
