package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestCLIMoveProfileFencesPreviousWriter(t *testing.T) {
	current, previous := os.Getenv("OUTPOST_MOVE_CURRENT_CLI"), os.Getenv("OUTPOST_MOVE_PREVIOUS_CLI")
	if current == "" && previous == "" {
		t.Skip("selected current and previous CLI required")
	}
	if !filepath.IsAbs(current) || !filepath.IsAbs(previous) {
		t.Fatal("expected absolute selected CLI paths")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(previous)
	check(err)
	const maxExecutable = 64 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxExecutable+1))
	check(err)
	check(f.Close())
	if len(data) > maxExecutable || storage.Hash(data) != os.Getenv("OUTPOST_MOVE_PREVIOUS_SHA256") {
		t.Fatal("previous CLI hash or size mismatch")
	}
	// The fixture disk is mounted noexec. Copy only the verified executable.
	copyFile, err := os.CreateTemp("/tmp", "outpost-previous-move-*")
	check(err)
	t.Cleanup(func() { _ = os.Remove(copyFile.Name()) })
	_, err = copyFile.Write(data)
	check(err)
	check(copyFile.Chmod(0700))
	check(copyFile.Close())

	root := teststore.Root(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	write := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		check(err)
		path := filepath.Join(root, name)
		check(os.WriteFile(path, raw, 0600))
		return path
	}
	key := write("owner.json", map[string]any{"privateKey": private})
	node := storage.Hash([]byte("move CLI node"))
	now := time.Now()
	profile := storage.Profile{Kind: "webdav", Endpoint: "https://example.invalid/objects", Namespace: storage.Hash([]byte("move CLI namespace")), MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 10, Attempts: 1, TimeoutMillis: 1000, CredentialScope: "namespace", NoDelete: true}
	config := control.Config{Format: control.Format, Node: node, Revision: 1, NotBefore: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(time.Minute).Unix(), Nodes: []policy.Node{{ID: node, Class: "trusted"}}, Limits: control.Limits{Parallel: 1, AttemptMillis: 1000, PollSeconds: 1, CapacityBytes: 1 << 30, ReserveBytes: 1 << 28, SpoolBytes: 1 << 26, TelemetryBytes: 1 << 20}}
	config.Targets = []control.Target{{ID: profile.ID(), Profile: profile}}
	sign := func(binary, input, name string, wantSuccess bool) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path := filepath.Join(root, name)
		out, err := exec.CommandContext(ctx, binary, "config-sign", "--key", key, "--input", input, "--output", path).CombinedOutput()
		if ctx.Err() != nil || (err == nil) != wantSuccess {
			t.Fatalf("unexpected selected CLI result: %v %s", err, out)
		}
		if !wantSuccess {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("previous CLI did not run", err)
			}
			if _, err = os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("refused configuration produced output", err)
			}
			return nil
		}
		raw, err := os.ReadFile(path)
		check(err)
		return raw
	}
	legacy := write("legacy.json", config)
	old := sign(copyFile.Name(), legacy, "previous-legacy.json", true)
	if next := sign(current, legacy, "current-legacy.json", true); !bytes.Equal(old, next) {
		t.Fatal("legacy signed configuration changed")
	}
	profile.WriteMode, profile.MaxStagingAttempts = storage.WebDAVMoveMode, 3
	config.Targets[0] = control.Target{ID: profile.ID(), Profile: profile}
	move := write("move.json", config)
	sign(copyFile.Name(), move, "previous-move.json", false)
	signed := sign(current, move, "current-move.json", true)
	verified, err := control.Verify(signed, public, node)
	check(err)
	if len(verified.Targets) != 1 || verified.Targets[0].Profile != profile || verified.Targets[0].ID != profile.ID() {
		t.Fatal("signed MOVE profile changed")
	}
	t.Log("current native CLI signed MOVE profile, previous native CLI refused without output, legacy signed bytes identical")
}
