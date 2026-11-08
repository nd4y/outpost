package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/storage"
)

func TestPreparedSourceCLIExportsNativeApplicationAndRejectsPreviousBootstrapReader(t *testing.T) {
	current, previous := os.Getenv("OUTPOST_PREPARED_CURRENT_CLI"), os.Getenv("OUTPOST_PREPARED_PREVIOUS_CLI")
	if current == "" && previous == "" {
		t.Skip("selected current and previous native CLI artifacts required")
	}
	expected := os.Getenv("OUTPOST_PREPARED_PREVIOUS_SHA256")
	if !filepath.IsAbs(current) || !filepath.IsAbs(previous) || !storage.ID(expected) {
		t.Fatal("incomplete CLI selection")
	}
	fp, e := os.Open(previous)
	must(t, e)
	bin, e := io.ReadAll(io.LimitReader(fp, (64<<20)+1))
	must(t, e)
	must(t, fp.Close())
	if len(bin) > 64<<20 || storage.Hash(bin) != expected {
		t.Fatal("previous CLI digest mismatch")
	}
	old, e := os.CreateTemp("/tmp", "outpost-prepared-previous-*")
	must(t, e)
	oldCLI := old.Name()
	t.Cleanup(func() { os.Remove(oldCLI) })
	_, e = old.Write(bin)
	must(t, e)
	must(t, old.Chmod(0700))
	must(t, old.Close())
	f := newFixture(t)
	must(t, f.a.Close())
	f.a = nil
	write := func(name string, v any) string {
		t.Helper()
		raw, e := json.Marshal(v)
		must(t, e)
		p := filepath.Join(f.base, name)
		must(t, os.WriteFile(p, raw, 0600))
		return p
	}
	run := func(binary string, success bool, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, e := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if ctx.Err() != nil || (e == nil) != success {
			t.Fatalf("CLI %s success=%v: %v %s", args[0], success, e, out)
		}
		return out
	}
	legacy := write("legacy-bootstrap.json", f.b)
	run(oldCLI, true, "source-status", "--bootstrap", legacy)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.b.Format = PreparedAgentFormat
	f.b.Profile.Consistency = "application"
	f.b.Local.Directory += "-prepared-cli"
	f.b.Prepared = &PreparedSource{Trust: capture.PreparedTrust{Profile: f.b.Profile.ID, Origin: f.b.Profile.Origin, Method: "sqlite-online-backup-v1", Producer: pub, MaxBytes: f.b.Profile.MaxSourceBytes, MaxFiles: 16}, ManifestFile: filepath.Join(f.base, "cli-current-export.json")}
	sourcePath := write("prepared-source.json", f.b)
	producerKey := write("producer-key.json", map[string]any{"privateKey": key})
	// Producer signing requires no source runtime, encryption key or writer key.
	producerBootstrap := f.b
	producerBootstrap.DataKeyFile = filepath.Join(f.base, "absent-data-key")
	producerBootstrap.WriterKeyFile = filepath.Join(f.base, "absent-writer-key")
	producerPath := write("producer-bootstrap.json", producerBootstrap)
	live := filepath.Join(f.base, "cli-live.sqlite")
	var versions []Status
	var digests []string
	for index, root := range []string{"cli-export-1", "cli-export-2"} {
		marker := strconv.Itoa(index + 1)
		proofRaw := nativePreparedCommand(t, preparedSQLiteProducer, live, filepath.Join(f.tree, root), marker)
		var proof struct {
			SnapshotUnix  int64 `json:"snapshotUnix"`
			CompletedUnix int64 `json:"completedUnix"`
		}
		must(t, json.Unmarshal(proofRaw, &proof))
		claim := write("claim-"+marker+".json", capture.PreparedClaim{Sequence: uint64(index + 1), SnapshotUnix: proof.SnapshotUnix, CompletedUnix: proof.CompletedUnix, Root: root})
		manifestPath := filepath.Join(f.base, "manifest-"+marker+".json")
		args := []string{"source-prepared-export-create", "--bootstrap", producerPath, "--key", producerKey, "--input", claim, "--output", manifestPath}
		run(oldCLI, false, args...)
		if _, e = os.Lstat(manifestPath); !os.IsNotExist(e) {
			t.Fatal("previous CLI created unsupported manifest", e)
		}
		result := run(current, true, args...)
		if bytes.Contains(result, []byte("application.sqlite")) {
			t.Fatal("producer command leaked private inventory")
		}
		manifest, e := os.ReadFile(manifestPath)
		must(t, e)
		m, e := capture.VerifyPreparedExport(manifest, f.b.Prepared.Trust, time.Now())
		must(t, e)
		run(current, false, args...)
		after, e := os.ReadFile(manifestPath)
		must(t, e)
		if !bytes.Equal(after, manifest) {
			t.Fatal("producer command overwrote accepted manifest")
		}
		must(t, os.WriteFile(f.b.Prepared.ManifestFile, manifest, 0600))
		if index == 0 {
			run(oldCLI, false, "source-init", "--bootstrap", sourcePath)
			if _, e = os.Lstat(f.b.Local.Directory); !os.IsNotExist(e) {
				t.Fatal("old reader created prepared runtime", e)
			}
			run(current, true, "source-init", "--bootstrap", sourcePath)
		}
		run(current, true, "source-next", "--bootstrap", sourcePath)
		run(current, true, "source-run", "--bootstrap", sourcePath)
		var status struct {
			Result Status `json:"result"`
		}
		must(t, json.Unmarshal(run(current, true, "source-status", "--bootstrap", sourcePath), &status))
		if status.Result.Phase != "COMPLETE" || status.Result.Sequence != uint64(index+1) || status.Result.Prepared == nil || status.Result.Prepared.SnapshotUnix != proof.SnapshotUnix || status.Result.Prepared.ProducerSequence != uint64(index+1) {
			t.Fatal("wrong prepared CLI completion", status)
		}
		versions = append(versions, status.Result)
		digests = append(digests, m.Files[0].SHA256)
		statePath := filepath.Join(f.b.Local.Directory, "state/agent.json")
		before, e := os.ReadFile(statePath)
		must(t, e)
		for _, command := range []string{"source-status", "source-next", "source-run"} {
			run(oldCLI, false, command, "--bootstrap", sourcePath)
		}
		unchanged := run(current, false, "source-next", "--bootstrap", sourcePath)
		if !bytes.Contains(unchanged, []byte("EXPORT_NOT_ADVANCED")) {
			t.Fatal("unchanged export lost stable CLI error", string(unchanged))
		}
		after, e = os.ReadFile(statePath)
		must(t, e)
		if !bytes.Equal(before, after) {
			t.Fatal("refused downgrade or unchanged export changed durable head")
		}
	}
	must(t, os.Rename(live, filepath.Join(f.base, "retained-cli-live.sqlite")))
	for _, root := range []string{"cli-export-1", "cli-export-2"} {
		must(t, os.Rename(filepath.Join(f.tree, root), filepath.Join(f.tree, "retained-"+root)))
	}
	trust := write("restore-trust.json", f.grant.Trust)
	for index, status := range versions {
		out := filepath.Join(f.base, "cli-restore-"+strconv.Itoa(index+1))
		reader := current
		if index == 0 {
			reader = oldCLI
		}
		run(reader, true, "restore-replica", "--key", f.b.DataKeyFile, "--trust", trust, "--store", f.replicaPath, "--generation", status.Generation, "--output", out)
		file := filepath.Join(out, "application.sqlite")
		raw, e := os.ReadFile(file)
		must(t, e)
		if storage.Hash(raw) != digests[index] {
			t.Fatal("CLI restored wrong native export")
		}
		nativePreparedCommand(t, preparedSQLiteRestore, file, strconv.Itoa(index+1))
	}
	t.Log("actual CLI measured and signed two native SQLite exports, captured both; previous bootstrap reader refused without head mutation; previous/current recovery readers independently restored committed native application versions")
}
