package recoverybundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func encoded(t *testing.T, v any) []byte { t.Helper(); b, e := json.Marshal(v); must(t, e); return b }
func privateDir(t *testing.T, parent, name string) string {
	t.Helper()
	p := filepath.Join(parent, name)
	must(t, os.Mkdir(p, 0700))
	return p
}

type fixture struct {
	base, ownerDir string
	material       Material
	options        Options
	fullOwner      filekit.Owner
}

// These tiny ELF-shaped bytes exercise archive validation only. Actual reader
// execution is a separate test against a selected built distribution.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{base: teststore.Root(t)}
	f.ownerDir = privateDir(t, f.base, "owner-private")
	var e error
	f.fullOwner, e = filekit.NewOwner()
	must(t, e)
	f.material.Owner, e = f.fullOwner.RecoveryMaterial()
	must(t, e)
	writer, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	maint, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.material.Trust = generation.Trust{Domain: f.fullOwner.Domain, Repository: storage.Hash([]byte("repository")), Epoch: 1, Writer: writer, Maintenance: maint}
	dir := privateDir(t, f.base, "tools")
	m := toolManifest{Format: "outpost-distribution-1", Revision: strings.Repeat("a", 40), Source: map[string]string{"go.mod": storage.Hash([]byte("source"))}, GoVersion: "go1.27.3", GoOS: "linux", Architectures: []string{"amd64", "arm64"}, Files: map[string]File{}}
	m.SourceDigest = storage.Hash(encoded(t, m.Source))
	license := []byte("synthetic test license\n")
	for _, name := range []string{"Dockerfile", "compose.yaml", ".dockerignore", "licenses/LICENSE", "licenses/THIRD_PARTY_NOTICES.md", "licenses/GO_LICENSE"} {
		m.Files[name] = File{storage.Hash(license), int64(len(license))}
	}
	for _, arch := range m.Architectures {
		elf := make([]byte, 120)
		copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
		machine := uint16(62)
		if arch == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(elf[18:], machine)
		binary.LittleEndian.PutUint64(elf[32:], 64)
		binary.LittleEndian.PutUint16(elf[54:], 56)
		binary.LittleEndian.PutUint16(elf[56:], 1)
		for _, name := range []string{"outpost", "outpost-kit"} {
			m.Files["linux_"+arch+"/"+name] = File{storage.Hash(elf), int64(len(elf))}
		}
		var compressed bytes.Buffer
		z := gzip.NewWriter(&compressed)
		w := tar.NewWriter(z)
		for _, name := range []string{"licenses/GO_LICENSE", "licenses/LICENSE", "licenses/THIRD_PARTY_NOTICES.md", "outpost", "outpost-kit"} {
			raw, mode := license, int64(0644)
			if !strings.HasPrefix(name, "licenses/") {
				raw, mode = elf, 0755
			}
			must(t, w.WriteHeader(&tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeReg, Size: int64(len(raw)), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}))
			_, e = w.Write(raw)
			must(t, e)
		}
		must(t, w.Close())
		must(t, z.Close())
		name := "outpost-linux-" + arch + ".tar.gz"
		raw := compressed.Bytes()
		m.Files[name] = File{storage.Hash(raw), int64(len(raw))}
		must(t, os.WriteFile(filepath.Join(dir, name), raw, 0600))
	}
	raw, e := json.MarshalIndent(m, "", "  ")
	must(t, e)
	raw = append(raw, '\n')
	must(t, os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600))
	f.options = Options{ToolsDirectory: dir, ManifestSHA256: storage.Hash(raw), Revision: m.Revision}
	return f
}

func (f *fixture) export(t *testing.T, name string) (string, Receipt) {
	t.Helper()
	p := filepath.Join(f.ownerDir, name)
	r, e := Export(context.Background(), f.material, f.options, p)
	must(t, e)
	return p, r
}
func inspect(t *testing.T, p, digest string) (Receipt, error) {
	t.Helper()
	f, e := Open(p)
	if e != nil {
		return Receipt{}, e
	}
	defer f.Close()
	return Inspect(context.Background(), f, digest)
}

func TestRecoveryPackageRoundTripHasOnlyReadOnlySecrets(t *testing.T) {
	f := newFixture(t)
	path, receipt := f.export(t, "recovery.tar")
	if receipt.CheckpointPresent || receipt.Generation != "" || receipt.VerifiedUnix != 0 || len(receipt.Architectures) != 2 {
		t.Fatal("invented freshness or missing tools")
	}
	got, e := inspect(t, path, receipt.SHA256)
	must(t, e)
	if !bytes.Equal(encoded(t, got), encoded(t, receipt)) {
		t.Fatal("inspection receipt changed")
	}
	input, e := Open(path)
	must(t, e)
	defer input.Close()
	dest := filepath.Join(f.ownerDir, "unpacked")
	_, e = Extract(context.Background(), input, receipt.SHA256, dest)
	must(t, e)
	owner, e := filekit.ReadOwner(filepath.Join(dest, "recovery-owner.json"))
	must(t, e)
	if len(owner.SigningKey) != 0 || !bytes.Equal(owner.Master, f.fullOwner.Master) || !bytes.Equal(owner.VerifyKey, f.fullOwner.VerifyKey) {
		t.Fatal("wrong recovery capabilities")
	}
	owner.Master[0] ^= 1
	if bytes.Equal(owner.Master, f.fullOwner.Master) {
		t.Fatal("recovery copy aliases owner")
	}
	raw, e := os.ReadFile(path)
	must(t, e)
	if bytes.Contains(raw, encoded(t, f.fullOwner.SigningKey)) || bytes.Contains(encoded(t, receipt), encoded(t, f.fullOwner.Master)) {
		t.Fatal("private signing key or result leaked")
	}
	want := storage.Hash(raw)
	if _, e = Export(context.Background(), f.material, f.options, path); e == nil {
		t.Fatal("overwrote package")
	}
	if _, e = Extract(context.Background(), input, receipt.SHA256, dest); e == nil {
		t.Fatal("overwrote extraction")
	}
	after, e := os.ReadFile(path)
	must(t, e)
	if storage.Hash(after) != want {
		t.Fatal("existing package changed")
	}
	f.material.Owner = f.fullOwner
	if _, e = Export(context.Background(), f.material, f.options, filepath.Join(f.ownerDir, "unsafe.tar")); !errors.Is(e, ErrInvalid) {
		t.Fatal("accepted signing key", e)
	}
}

func rewriteArchive(t *testing.T, raw []byte, change func(*tar.Header, []byte) (*tar.Header, []byte)) []byte {
	t.Helper()
	r := tar.NewReader(bytes.NewReader(raw))
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for {
		h, e := r.Next()
		if e == io.EOF {
			break
		}
		must(t, e)
		data, e := io.ReadAll(r)
		must(t, e)
		h, data = change(h, data)
		h.Size = int64(len(data))
		must(t, w.WriteHeader(h))
		_, e = w.Write(data)
		must(t, e)
	}
	must(t, w.Close())
	return out.Bytes()
}

func TestRecoveryPackageRejectsTamperingEvenWithCallerSelectedDigest(t *testing.T) {
	f := newFixture(t)
	path, receipt := f.export(t, "original.tar")
	raw, e := os.ReadFile(path)
	must(t, e)
	if _, e = inspect(t, path, strings.Repeat("0", 64)); !errors.Is(e, ErrInvalid) {
		t.Fatal("wrong anchor accepted", e)
	}
	for _, name := range []string{"manifest.json", "recovery-owner.json", "trust.json", "instructions.en.txt", "tools/manifest.json", "tools/outpost-linux-amd64.tar.gz"} {
		t.Run(name, func(t *testing.T) {
			altered := rewriteArchive(t, raw, func(h *tar.Header, b []byte) (*tar.Header, []byte) {
				if h.Name == name {
					b[len(b)/2] ^= 1
				}
				return h, b
			})
			p := filepath.Join(f.ownerDir, storage.Hash([]byte(name))+".tar")
			must(t, os.WriteFile(p, altered, 0600))
			if _, e := inspect(t, p, storage.Hash(altered)); e == nil {
				t.Fatal("tampered entry accepted")
			}
		})
	}
	for _, kind := range []string{"truncated", "trailing", "traversal", "duplicate", "symlink", "mode", "duplicate-json"} {
		t.Run(kind, func(t *testing.T) {
			changed := append([]byte(nil), raw...)
			switch kind {
			case "truncated":
				changed = changed[:len(changed)-1024]
			case "trailing":
				changed = append(changed, 0)
			default:
				changed = rewriteArchive(t, raw, func(h *tar.Header, b []byte) (*tar.Header, []byte) {
					if h.Name == "instructions.en.txt" {
						switch kind {
						case "traversal":
							h.Name = "../escaped"
						case "duplicate":
							h.Name = "manifest.json"
						case "symlink":
							h.Typeflag = tar.TypeSymlink
							h.Linkname = "/tmp/escaped"
							b = nil
						case "mode":
							h.Mode = 0644
						}
					}
					if kind == "duplicate-json" && h.Name == manifestName {
						b = append([]byte(`{"format":"outpost-owner-recovery-1",`), b[1:]...)
					}
					return h, b
				})
			}
			p := filepath.Join(f.ownerDir, kind+".tar")
			must(t, os.WriteFile(p, changed, 0600))
			input, e := Open(p)
			must(t, e)
			defer input.Close()
			out := filepath.Join(f.ownerDir, kind+"-out")
			if _, e = Extract(context.Background(), input, storage.Hash(changed), out); e == nil {
				t.Fatal("malformed archive accepted")
			}
			if _, e = os.Stat(out); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("published malformed result", e)
			}
		})
	}
	if _, e = inspect(t, path, receipt.SHA256); e != nil {
		t.Fatal("original changed", e)
	}
}

func TestRecoveryPackagePrivateBoundariesCancellationAndCandidateAdmission(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Export(ctx, f.material, f.options, filepath.Join(f.ownerDir, "cancel.tar")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	public := privateDir(t, f.base, "public")
	must(t, os.Chmod(public, 0755))
	if _, e := Export(context.Background(), f.material, f.options, filepath.Join(public, "secret.tar")); !errors.Is(e, ErrDenied) {
		t.Fatal("public destination", e)
	}
	alias := filepath.Join(f.base, "alias")
	must(t, os.Symlink(f.ownerDir, alias))
	if _, e := Export(context.Background(), f.material, f.options, filepath.Join(alias, "secret.tar")); e == nil {
		t.Fatal("symlink parent accepted")
	}
	path, r := f.export(t, "original.tar")
	must(t, os.Chmod(path, 0644))
	if _, e := inspect(t, path, r.SHA256); e == nil {
		t.Fatal("public package accepted")
	}
	must(t, os.Chmod(path, 0600))
	stopped := errors.New("synthetic stop")
	opt := f.options
	opt.Fault = func(point string) error {
		if point == "recovery-export-file-durable" {
			return stopped
		}
		return nil
	}
	output := filepath.Join(f.ownerDir, "bounded.tar")
	for i := 0; i < 4; i++ {
		if _, e := Export(context.Background(), f.material, opt, output); !errors.Is(e, stopped) {
			t.Fatal("fault not reached", e)
		}
	}
	if _, e := Export(context.Background(), f.material, f.options, output); !errors.Is(e, ErrCapacity) {
		t.Fatal("unbounded partial retention", e)
	}
	if _, e := os.Stat(output); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("partial package published", e)
	}
	opt = f.options
	opt.Fault = func(point string) error {
		if point == "recovery-export-published" {
			return stopped
		}
		return nil
	}
	lost := filepath.Join(f.ownerDir, "lost-reply.tar")
	if _, e := Export(context.Background(), f.material, opt, lost); !errors.Is(e, stopped) {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(lost)
	must(t, e)
	if _, e = inspect(t, lost, storage.Hash(raw)); e != nil {
		t.Fatal("durable result lost", e)
	}
	if _, e = Export(context.Background(), f.material, f.options, lost); !errors.Is(e, ErrConflict) {
		t.Fatal("lost reply overwrote result", e)
	}
	opt = f.options
	opt.Guard = func(context.Context) error { return ErrDenied }
	if _, e = Export(context.Background(), f.material, opt, filepath.Join(f.ownerDir, "denied.tar")); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
}

func TestRecoveryPackageConcurrentPublishHasOneWinner(t *testing.T) {
	f := newFixture(t)
	output := filepath.Join(f.ownerDir, "concurrent.tar")
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := Export(context.Background(), f.material, f.options, output)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrConflict) && !errors.Is(e, ErrCapacity) && !errors.Is(e, os.ErrExist) {
			t.Fatal(e)
		}
	}
	if wins != 1 {
		t.Fatal("publication winners", wins)
	}
	raw, e := os.ReadFile(output)
	must(t, e)
	_, e = inspect(t, output, storage.Hash(raw))
	must(t, e)
}

func TestRecoveryPackageActualPackagedReaderAfterSourceLoss(t *testing.T) {
	dir := os.Getenv("OUTPOST_RECOVERY_DISTRIBUTION")
	if dir == "" {
		t.Skip("selected built distribution required for executable acceptance")
	}
	f := newFixture(t)
	raw, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(t, e)
	var manifest toolManifest
	must(t, json.Unmarshal(raw, &manifest))
	f.options = Options{ToolsDirectory: dir, ManifestSHA256: os.Getenv("OUTPOST_RECOVERY_MANIFEST_SHA256"), Revision: manifest.Revision}
	path, receipt := f.export(t, "actual.tar")
	sourceRoot := privateDir(t, f.base, "source-to-lose")
	source := filepath.Join(sourceRoot, "source.bin")
	first := bytes.Repeat([]byte("original ciphertext input"), 8192)
	second := append([]byte(nil), first...)
	copy(second[1234:], []byte("changed few bytes"))
	store, e := filekit.OpenStore(filepath.Join(sourceRoot, "journal"), f.fullOwner, true)
	must(t, e)
	must(t, os.WriteFile(source, first, 0600))
	one, e := store.Backup(context.Background(), source, filekit.BackupOptions{Names: []string{"restored.bin"}})
	must(t, e)
	must(t, os.WriteFile(source, second, 0600))
	two, e := store.Backup(context.Background(), source, filekit.BackupOptions{Names: []string{"restored.bin"}, File: one.File, Previous: one.Version})
	must(t, e)
	for _, version := range []string{one.Version, two.Version} {
		must(t, store.Export(context.Background(), version, filepath.Join(f.base, "kit-"+version)))
	}
	must(t, store.Close())
	must(t, os.RemoveAll(sourceRoot)) // exactly this owned synthetic fixture
	input, e := Open(path)
	must(t, e)
	defer input.Close()
	unpacked := filepath.Join(f.ownerDir, "offline")
	_, e = Extract(context.Background(), input, receipt.SHA256, unpacked)
	must(t, e)
	archive, e := os.Open(filepath.Join(unpacked, "tools/outpost-linux-"+runtime.GOARCH+".tar.gz"))
	must(t, e)
	defer archive.Close()
	z, e := gzip.NewReader(archive)
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
			binary, e = io.ReadAll(r)
			must(t, e)
		}
	}
	if int64(len(binary)) != manifest.Files["linux_"+runtime.GOARCH+"/outpost"].Bytes || storage.Hash(binary) != manifest.Files["linux_"+runtime.GOARCH+"/outpost"].SHA256 {
		t.Fatal("packaged executable differs")
	}
	// The test HDD is noexec. Only this already verified executable goes into
	// the isolated container's disposable tmpfs; datasets stay on the HDD.
	executable, e := os.CreateTemp("/tmp", "outpost-recovery-reader-")
	must(t, e)
	binaryPath := executable.Name()
	t.Cleanup(func() { os.Remove(binaryPath) })
	_, e = executable.Write(binary)
	must(t, e)
	must(t, executable.Chmod(0700))
	must(t, executable.Close())
	for index, version := range []string{one.Version, two.Version} {
		out := filepath.Join(f.base, "restored-"+version)
		command := exec.Command(binaryPath, "restore-kit", "--key", filepath.Join(unpacked, "recovery-owner.json"), "--store", filepath.Join(f.base, "kit-"+version), "--version", version, "--output", out)
		result, e := command.CombinedOutput()
		if e != nil {
			t.Fatalf("packaged reader failed: %v: %s", e, result)
		}
		got, e := os.ReadFile(filepath.Join(out, "restored.bin"))
		must(t, e)
		want := first
		if index == 1 {
			want = second
		}
		if !bytes.Equal(got, want) {
			t.Fatal("independent restore differs")
		}
	}
	t.Logf("independent packaged reader restored %d-byte old and new versions after synthetic source/journal loss; tool revision %s", len(first), manifest.Revision)
}
