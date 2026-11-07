package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIRecoveryInitializationIsExplicitPrivateAndNoOverwrite(t *testing.T) {
	ctx := context.Background()
	base := teststore.Root(t)
	vol := filepath.Join(base, "volume")
	if e := os.Mkdir(vol, 0700); e != nil {
		t.Fatal(e)
	}
	probe, e := volume.Probe(ctx, vol)
	if e != nil {
		t.Fatal(e)
	}
	node := storage.Hash([]byte("trusted"))
	binding, e := volume.Enroll(ctx, vol, probe, node, 1)
	if e != nil {
		t.Fatal(e)
	}
	p := recovery.Profile{Format: recovery.ProfileFormat, Node: node, Directory: filepath.Join(vol, "recovery"), Volume: binding, Limits: recovery.Limits{Bytes: 32 << 20, Entries: 256, FreeBytes: 1 << 20, FreeInodes: 32}, Presets: []recovery.Preset{{ID: storage.Hash([]byte("preset")), Domain: storage.Hash([]byte("domain")), Repository: storage.Hash([]byte("repository")), Epoch: 1, OwnerFile: filepath.Join(base, "not-loaded-key.json")}}}
	raw, _ := json.Marshal(p)
	file := filepath.Join(base, "private-profile.json")
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	args := []string{"recovery-init", "--input", file}
	out, e := run(ctx, args)
	if e != nil {
		t.Fatal(e)
	}
	result, _ := json.Marshal(out)
	if bytes.Contains(result, []byte(base)) {
		t.Fatal("private path leaked")
	}
	if _, e = run(ctx, args); e == nil {
		t.Fatal("existing output initialized again")
	}
	x, e := recovery.OpenExecutor(ctx, p, false)
	if e != nil {
		t.Fatal(e)
	}
	x.Close()
	if e = os.Chmod(file, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = run(ctx, args); e == nil {
		t.Fatal("public-readable recovery profile accepted")
	}
}
