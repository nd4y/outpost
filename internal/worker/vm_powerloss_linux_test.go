package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

// TestVMKernelFixture is run only by the explicit networkless VM harness. It
// never boots a VM or touches a host device itself. Default unit checks skip it.
func TestVMKernelFixture(t *testing.T) {
	if os.Getenv("OUTPOST_VM_GUEST") != "1" {
		t.Skip("explicit isolated guest-kernel fixture required")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	must(t, err)
	if !slices.Contains(strings.Fields(string(cmdline)), "outpost_vm_fixture=1") || os.Getuid() != 0 {
		t.Fatal("refusing to operate outside the explicitly marked guest")
	}
	phase := os.Getenv("OUTPOST_VM_PHASE")
	switch {
	case phase == "setup":
		vmFixtureSetup(t)
	case strings.HasPrefix(phase, "cut:"):
		vmFixtureCut(t, strings.TrimPrefix(phase, "cut:"))
	case strings.HasPrefix(phase, "verify:"):
		vmFixtureVerify(t, strings.TrimPrefix(phase, "verify:"))
	case phase == "volume-refuse", phase == "volume-initialize", phase == "volume-status":
		vmFixtureVolume(t, phase)
	default:
		t.Fatal("unknown VM fixture phase")
	}
}

var vmCutPoints = []string{"object-durable", "before-complete", "state-durable", "retirement-durable"}

type vmGenerationFixture struct {
	Trust                  generation.Trust
	Old, New               string
	OldVersion, NewVersion string
	OldSHA256, NewSHA256   string
	Permit                 []byte
}

func vmCaseRoot(t *testing.T, point string) string {
	t.Helper()
	for _, allowed := range vmCutPoints {
		if point == allowed {
			return filepath.Join("/mnt/data/fixture", point)
		}
	}
	t.Fatal("unrecognized power-cut boundary")
	return ""
}

func vmWriteJSON(t *testing.T, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	must(t, err)
	must(t, os.WriteFile(name, raw, 0600))
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	must(t, err)
	must(t, f.Sync())
	must(t, f.Close())
	d, err := os.Open(filepath.Dir(name))
	must(t, err)
	must(t, d.Sync())
	must(t, d.Close())
}

func vmLoadCase(t *testing.T, point string) (string, vmGenerationFixture) {
	t.Helper()
	root := vmCaseRoot(t, point)
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	must(t, err)
	var data vmGenerationFixture
	must(t, json.Unmarshal(raw, &data))
	return root, data
}

func vmFixtureSetup(t *testing.T) {
	ctx := context.Background()
	must(t, os.Mkdir("/mnt/data/fixture", 0700))
	for _, point := range vmCutPoints {
		root := vmCaseRoot(t, point)
		must(t, os.Mkdir(root, 0700))
		owner, err := filekit.NewOwner()
		must(t, err)
		store, err := filekit.OpenStore(filepath.Join(root, "source-store"), owner, true)
		must(t, err)
		writer, writerKey, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		maintenance, maintenanceKey, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("vm-" + point)), Epoch: 1, Writer: writer, Maintenance: maintenance}
		for _, name := range []string{"donor", "target"} {
			must(t, os.Mkdir(filepath.Join(root, name), 0700))
		}
		donor, err := generation.Open(filepath.Join(root, "donor"), trust, true)
		must(t, err)
		target, err := generation.Open(filepath.Join(root, "target"), trust, true)
		must(t, err)
		input := filepath.Join(root, "plaintext")
		old := make([]byte, 2<<20)
		_, err = rand.Read(old)
		must(t, err)
		must(t, os.WriteFile(input, old, 0640))
		first, err := store.Backup(ctx, input, filekit.BackupOptions{Names: []string{"private/данные.bin", "alias.bin"}})
		must(t, err)
		catalog := generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}
		one, err := generation.Seal(ctx, store, []string{first.Version}, donor, catalog, writerKey)
		must(t, err)
		raw, err := donor.Catalog(ctx, one)
		must(t, err)
		_, err = target.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) { return donor.ReadObject(ctx, one, ref) })
		must(t, err)
		changed := append([]byte(nil), old...)
		copy(changed[1<<20:], bytes.Repeat([]byte{71}, 8192))
		must(t, os.WriteFile(input, changed, 0640))
		second, err := store.Backup(ctx, input, filekit.BackupOptions{File: first.File, Previous: first.Version, Names: []string{"private/данные.bin", "alias.bin"}})
		must(t, err)
		catalog.Sequence, catalog.Parent = 2, one
		two, err := generation.Seal(ctx, store, []string{second.Version}, donor, catalog, writerKey)
		must(t, err)
		newRaw, err := donor.Catalog(ctx, two)
		must(t, err)
		data := vmGenerationFixture{Trust: trust, Old: one, New: two, OldVersion: first.Version, NewVersion: second.Version, OldSHA256: storage.Hash(old), NewSHA256: storage.Hash(changed)}
		if point != "object-durable" {
			_, err = target.Begin(ctx, newRaw)
			must(t, err)
			parsed, err := generation.VerifyCatalog(newRaw, trust)
			must(t, err)
			refs := map[string]generation.Object{}
			for _, kit := range parsed.Kits {
				refs[kit.Root.ID] = kit.Root
				for _, ref := range kit.Objects {
					refs[ref.ID] = ref
				}
			}
			for _, ref := range refs {
				payload, err := donor.ReadObject(ctx, two, ref)
				must(t, err)
				must(t, target.Put(ctx, two, ref.ID, payload))
			}
		}
		if point == "retirement-durable" {
			must(t, target.Complete(ctx, two))
			must(t, target.ExportKit(ctx, one, first.Version, filepath.Join(root, "saved-old-kit")))
			status, err := target.Status(ctx)
			must(t, err)
			data.Permit, err = generation.SignPermit(generation.Permit{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Revision: status.Revision, Operation: storage.Hash([]byte("vm-retire-" + point)), Retire: []string{one}}, maintenanceKey)
			must(t, err)
		}
		recovery, err := owner.RecoveryMaterial()
		must(t, err)
		must(t, filekit.WriteOwner(filepath.Join(root, "recovery-owner.json"), recovery))
		vmWriteJSON(t, filepath.Join(root, "trust.json"), trust)
		vmWriteJSON(t, filepath.Join(root, "manifest.json"), data)
		must(t, store.Close())
		must(t, donor.Close())
		must(t, target.Close())
		must(t, os.RemoveAll(filepath.Join(root, "source-store")))
		must(t, os.Remove(input))
	}
	vmFixtureBootIdentity(t)
	fmt.Println("OUTPOST_VM_SETUP_PASS retained-cases=4 source-plaintext-and-cache-removed=true")
}

func vmFixtureCut(t *testing.T, point string) {
	root, data := vmLoadCase(t, point)
	ctx := context.Background()
	target, err := generation.Open(filepath.Join(root, "target"), data.Trust, false)
	must(t, err)
	defer target.Close()
	target.Fault = func(name string) error {
		if name == point {
			// Deliberately no fsync: the host must observe loss of this control
			// after terminating QEMU, rather than just killing a Go process.
			must(t, os.WriteFile(filepath.Join(root, "volatile-control"), bytes.Repeat([]byte{83}, 64<<10), 0600))
			fmt.Printf("OUTPOST_VM_CUT_READY point=%s\n", point)
			for {
				time.Sleep(time.Hour)
			}
		}
		return nil
	}
	switch point {
	case "object-durable":
		donor, err := generation.Open(filepath.Join(root, "donor"), data.Trust, false)
		must(t, err)
		defer donor.Close()
		raw, err := donor.Catalog(ctx, data.New)
		must(t, err)
		_, err = target.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) { return donor.ReadObject(ctx, data.New, ref) })
		must(t, err)
	case "before-complete", "state-durable":
		must(t, target.Complete(ctx, data.New))
	case "retirement-durable":
		_, err := target.Maintain(ctx, data.Permit)
		must(t, err)
	}
	t.Fatal("expected VM power-cut boundary was not reached")
}

func vmCLI(t *testing.T, binary string, args ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("selected CLI failed: %v: %.1000s", err, out)
	}
	return out
}

func vmFixtureVerify(t *testing.T, point string) {
	root, data := vmLoadCase(t, point)
	if _, err := os.Stat(filepath.Join(root, "volatile-control")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unflushed guest control survived; volatile-kernel loss is not established", err)
	}
	for _, name := range []string{"plaintext", "source-store"} {
		if _, err := os.Stat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("original source survived")
		}
	}
	ctx := context.Background()
	target, err := generation.Open(filepath.Join(root, "target"), data.Trust, false)
	must(t, err)
	status, err := target.Status(ctx)
	must(t, err)
	expected := data.Old
	if point == "state-durable" || point == "retirement-durable" {
		expected = data.New
	}
	if status.LatestComplete != expected {
		t.Fatal("wrong complete generation after guest kernel loss")
	}
	must(t, target.VerifyComplete(ctx, expected))
	if point != "retirement-durable" {
		must(t, target.VerifyComplete(ctx, data.Old))
		vmRestoreGeneration(t, root, data, "old", data.Old, data.OldSHA256)
		donor, err := generation.Open(filepath.Join(root, "donor"), data.Trust, false)
		must(t, err)
		raw, err := donor.Catalog(ctx, data.New)
		must(t, err)
		_, err = target.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) { return donor.ReadObject(ctx, data.New, ref) })
		must(t, err)
		must(t, donor.Close())
	} else {
		_, err := target.Maintain(ctx, data.Permit)
		must(t, err)
		vmCLI(t, "/tools/outpost-kit", "restore", "--owner", filepath.Join(root, "recovery-owner.json"), "--store", filepath.Join(root, "saved-old-kit"), "--version", data.OldVersion, "--dest", filepath.Join(root, "restored-old"))
		vmCheckRestored(t, filepath.Join(root, "restored-old"), data.OldSHA256)
	}
	must(t, target.Close())
	vmRestoreGeneration(t, root, data, "new", data.New, data.NewSHA256)
	fmt.Printf("OUTPOST_VM_KERNEL_RECOVERY_PASS point=%s unflushed-control-lost=true source-absent=true retained-old-new-restored=true\n", point)
}

func vmRestoreGeneration(t *testing.T, root string, data vmGenerationFixture, name, id, expected string) {
	t.Helper()
	out := filepath.Join(root, "restored-"+name)
	vmCLI(t, "/tools/outpost", "restore-replica", "--key", filepath.Join(root, "recovery-owner.json"), "--trust", filepath.Join(root, "trust.json"), "--store", filepath.Join(root, "target"), "--generation", id, "--output", out)
	vmCheckRestored(t, out, expected)
}

func vmCheckRestored(t *testing.T, out, expected string) {
	t.Helper()
	name := filepath.Join(out, "private/данные.bin")
	payload, err := os.ReadFile(name)
	must(t, err)
	a, err := os.Stat(name)
	must(t, err)
	b, err := os.Stat(filepath.Join(out, "alias.bin"))
	must(t, err)
	if len(payload) != 2<<20 || storage.Hash(payload) != expected || !os.SameFile(a, b) || a.Mode().Perm() != 0640 {
		t.Fatal("restored bytes or supported metadata differ")
	}
	fmt.Printf("OUTPOST_VM_RESTORED bytes=%d sha256=%s hardlink=true mode=0640\n", len(payload), expected)
}

func vmFixtureBootIdentity(t *testing.T) {
	ctx := context.Background()
	must(t, os.Mkdir("/mnt/data/volume", 0700))
	owner, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	valid := time.Now().Add(48 * time.Hour)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: valid}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	must(t, err)
	issuer, err := x509.ParseCertificate(caDER)
	must(t, err)
	certPub, certKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: valid, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, certPub, caKey)
	must(t, err)
	leaf, err := x509.ParseCertificate(der)
	must(t, err)
	privateKey, err := x509.MarshalPKCS8PrivateKey(certKey)
	must(t, err)
	// peer identity uses the public certificate SPKI hash.
	node := storage.Hash(leaf.RawSubjectPublicKeyInfo)
	observed, err := volume.Probe(ctx, "/mnt/data/volume")
	must(t, err)
	binding, err := volume.Enroll(ctx, "/mnt/data/volume", observed, node, 1)
	must(t, err)
	private := "/mnt/data/boot-private"
	must(t, os.Mkdir(private, 0700))
	for name, raw := range map[string][]byte{"node.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "node.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), "ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})} {
		must(t, os.WriteFile(filepath.Join(private, name), raw, 0600))
	}
	bootstrap := Bootstrap{Format: BootstrapFormat, Volume: binding, Directory: "/mnt/data/volume/worker", Node: node, Owner: owner, CertificateFile: "/private/node.crt", PrivateKeyFile: "/private/node.key", CAFile: "/private/ca.crt"}
	vmWriteJSON(t, filepath.Join(private, "bootstrap.json"), bootstrap)
}

func vmFixtureVolume(t *testing.T, phase string) {
	bootstrap, err := LoadBootstrap("/private/bootstrap.json")
	must(t, err)
	ctx := context.Background()
	if phase == "volume-refuse" {
		if err := bootstrap.Volume.Check(ctx, bootstrap.Directory, true); !errors.Is(err, volume.ErrUnavailable) {
			t.Fatal("negative volume control did not reach the required volume guard", err)
		}
		out, err := exec.CommandContext(t.Context(), "/tools/outpost", "worker-init", "--bootstrap", "/private/bootstrap.json").CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 5 || !bytes.Contains(out, []byte(`"VOLUME_UNAVAILABLE"`)) {
			t.Fatalf("actual CLI did not refuse unavailable volume: %v %.1000s", err, out)
		}
		if _, err := os.Stat(bootstrap.Directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unavailable volume created fallback state", err)
		}
		fmt.Println("OUTPOST_VM_VOLUME_REFUSED actual-cli=true fallback-state=false")
		return
	}
	must(t, bootstrap.Volume.Check(ctx, bootstrap.Directory, true))
	if phase == "volume-initialize" {
		vmCLI(t, "/tools/outpost", "worker-init", "--bootstrap", "/private/bootstrap.json")
	}
	var response struct {
		Format string `json:"format"`
		Result Status `json:"result"`
	}
	must(t, json.Unmarshal(vmCLI(t, "/tools/outpost", "worker-status", "--bootstrap", "/private/bootstrap.json"), &response))
	if response.Format != "outpost-cli-1" || response.Result.Node != bootstrap.Node {
		t.Fatal("cold-boot node identity changed")
	}
	fmt.Printf("OUTPOST_VM_VOLUME_ACCEPTED phase=%s identity-stable=true\n", phase)
}
