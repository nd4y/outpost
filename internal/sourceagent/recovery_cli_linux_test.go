package sourceagent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/storage"
)

func packagedReader(t *testing.T, directory string) string {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(directory, "tools/manifest.json"))
	must(t, e)
	var manifest struct {
		Files map[string]recoverybundle.File `json:"files"`
	}
	must(t, json.Unmarshal(raw, &manifest))
	f, e := os.Open(filepath.Join(directory, "tools/outpost-linux-"+runtime.GOARCH+".tar.gz"))
	must(t, e)
	defer f.Close()
	z, e := gzip.NewReader(f)
	must(t, e)
	defer z.Close()
	r := tar.NewReader(z)
	var binary []byte
	for {
		h, e := r.Next()
		if e == io.EOF {
			break
		}
		must(t, e)
		if h.Name == "outpost" {
			binary, e = io.ReadAll(io.LimitReader(r, recoverybundle.MaxToolBytes+1))
			must(t, e)
		}
	}
	expected := manifest.Files["linux_"+runtime.GOARCH+"/outpost"]
	if storage.Hash(binary) != expected.SHA256 || int64(len(binary)) != expected.Bytes {
		t.Fatal("selected reader differs")
	}
	// HDD datasets stay noexec; only the selected verified executable is copied
	// into the disposable isolated container tmpfs for this bounded test.
	executable, e := os.CreateTemp("/tmp", "outpost-offline-recovery-")
	must(t, e)
	name := executable.Name()
	t.Cleanup(func() { os.Remove(name) })
	_, e = executable.Write(binary)
	must(t, e)
	must(t, executable.Chmod(0700))
	must(t, executable.Close())
	return name
}

func TestSourceRecoveryPackageActualReaderRestoresCompleteReplicaAfterSourceLoss(t *testing.T) {
	if os.Getenv("OUTPOST_RECOVERY_DISTRIBUTION") == "" {
		t.Skip("selected built distribution required")
	}
	f := newFixture(t)
	ctx := context.Background()
	p := ownerExportProfile(t, f)
	raw, e := os.ReadFile(filepath.Join(p.ToolsDirectory, "manifest.json"))
	must(t, e)
	var tools struct {
		Revision string `json:"revision"`
	}
	must(t, json.Unmarshal(raw, &tools))
	first, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	checkpoint, e := f.a.Checkpoint(ctx)
	must(t, e)
	one, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	second := append([]byte(nil), first...)
	copy(second[2048:], []byte("new source bytes"))
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), second, 0640))
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	checkpoint, e = f.a.Checkpoint(ctx)
	must(t, e)
	two, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	path := filepath.Join(p.Directory, "replica-recovery.tar")
	receipt, e := f.a.ExportRecovery(ctx, p, tools.Revision, path)
	must(t, e)
	input, e := recoverybundle.Open(path)
	must(t, e)
	unpacked := filepath.Join(p.Directory, "selected-reader")
	_, e = recoverybundle.Extract(ctx, input, receipt.SHA256, unpacked)
	input.Close()
	must(t, e)
	binary := packagedReader(t, unpacked)
	run := func(args ...string) []byte {
		t.Helper()
		result, e := exec.Command(binary, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("selected CLI: %v: %s", e, result)
		}
		return result
	}
	if os.Getenv("OUTPOST_RECOVERY_REQUIRE_CLI") == "1" {
		bootstrap := filepath.Join(f.base, "bootstrap.json")
		raw, e := json.Marshal(f.b)
		must(t, e)
		must(t, os.WriteFile(bootstrap, raw, 0600))
		profile := filepath.Join(f.base, "owner-export-profile.json")
		raw, e = json.Marshal(p)
		must(t, e)
		must(t, os.WriteFile(profile, raw, 0600))
		cliPackage := filepath.Join(p.Directory, "cli-export.tar")
		result := run("source-recovery-export", "--bootstrap", bootstrap, "--input", profile, "--output", cliPackage)
		var response struct {
			Result recoverybundle.Receipt `json:"result"`
		}
		must(t, json.Unmarshal(result, &response))
		if response.Result.Generation != two.Generation || response.Result.ToolRevision != tools.Revision {
			t.Fatal("wrong CLI export receipt")
		}
		run("recovery-package-inspect", "--input", cliPackage, "--sha256", response.Result.SHA256)
		unpacked = filepath.Join(p.Directory, "cli-unpacked")
		run("recovery-package-extract", "--input", cliPackage, "--sha256", response.Result.SHA256, "--output", unpacked)
		if result, e := exec.Command(binary, "recovery-package-inspect", "--input", cliPackage, "--sha256", storage.Hash([]byte("wrong anchor"))).CombinedOutput(); e == nil || bytes.Contains(result, []byte(p.Directory)) || bytes.Contains(result, []byte("master")) {
			t.Fatal("CLI failed to reject or redact wrong anchor")
		}
	}
	must(t, f.a.Close())
	f.a = nil
	f.server.Close()
	// Delete only this fixture's source, runtime and source private authority.
	must(t, os.RemoveAll(f.tree))
	must(t, os.RemoveAll(f.b.Local.Volume.Root))
	for _, path := range []string{f.b.DataKeyFile, f.b.WriterKeyFile, f.b.AuthorityFile, f.b.Local.CertificateFile, f.b.Local.PrivateKeyFile, f.b.Local.CAFile} {
		must(t, os.Remove(path))
	}
	for index, id := range []string{one.Generation, two.Generation} {
		out := filepath.Join(f.base, "offline-"+id)
		run("restore-replica", "--key", filepath.Join(unpacked, "recovery-owner.json"), "--trust", filepath.Join(unpacked, "trust.json"), "--store", f.replicaPath, "--generation", id, "--output", out)
		got, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		want := first
		if index == 1 {
			want = second
		}
		if !bytes.Equal(got, want) {
			t.Fatal("wrong retained replica generation")
		}
	}
	t.Logf("packaged reader restored two complete %d-byte replica generations after source/runtime/private-authority removal and receiver shutdown; current-package CLI required=%t", len(first), os.Getenv("OUTPOST_RECOVERY_REQUIRE_CLI") == "1")
}
