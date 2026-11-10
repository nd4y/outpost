package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
)

const stagedImportCrashMarker = "queued-import: capture-object-durable"

type stagedImportChild struct {
	Registry, Replica                             string
	Authority, Owner, Certificate, PrivateKey, CA []byte
	Trust                                         generation.Trust
	Staging                                       *StagingRoutes
	Limits                                        peer.Limits
}

func killStagedImportAfterWrite(t *testing.T, ctx context.Context, o RegistryOptions, replica string, ca []byte) {
	t.Helper()
	input := stagedImportChild{
		Registry: o.Directory, Replica: replica, Authority: o.Authority, Owner: o.Owner,
		Certificate: o.Certificate.Certificate[0], PrivateKey: o.Certificate.PrivateKey.(ed25519.PrivateKey),
		CA: ca, Trust: o.Replica.Trust(), Staging: o.Staging, Limits: o.Limits,
	}
	raw, err := json.Marshal(input)
	must(t, err)
	file := filepath.Join(filepath.Dir(o.Directory), "staged-import-child.json")
	must(t, os.WriteFile(file, raw, 0600))

	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestStagedImportSIGKILLChild$")
	cmd.Env = append(os.Environ(), "OUTPOST_STAGED_IMPORT_KILL="+file)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if bounded.Err() != nil || !errors.As(err, &exit) {
		t.Fatalf("import child did not reach the crash point: %v %s", err, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || !bytes.Contains(output, []byte(stagedImportCrashMarker)) {
		t.Fatalf("import child did not receive SIGKILL: %v %s", err, output)
	}
	t.Log("import child received SIGKILL at capture-object-durable")
}

func TestStagedImportSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_STAGED_IMPORT_KILL")
	if file == "" {
		t.Skip("child only")
	}
	raw, err := os.ReadFile(file)
	must(t, err)
	var input stagedImportChild
	must(t, json.Unmarshal(raw, &input))
	ca, err := x509.ParseCertificate(input.CA)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	replica, err := generation.Open(input.Replica, input.Trust, false)
	must(t, err)
	defer replica.Close()
	opts := RegistryOptions{
		Directory: input.Registry, Authority: input.Authority, Owner: input.Owner, Replica: replica,
		Certificate: tls.Certificate{Certificate: [][]byte{input.Certificate}, PrivateKey: ed25519.PrivateKey(input.PrivateKey)},
		Roots:       roots, Limits: input.Limits, Staging: input.Staging,
	}
	registry, err := OpenRegistry(t.Context(), opts)
	must(t, err)
	defer registry.Close()
	registry.Fault = func(point string) error {
		if point == "capture-object-durable" {
			_, err := io.WriteString(os.Stderr, stagedImportCrashMarker+"\n")
			must(t, err)
			must(t, syscall.Kill(os.Getpid(), syscall.SIGKILL))
			select {}
		}
		return nil
	}
	advanced, err := registry.AdvanceStagedImport(t.Context(), func(string) bool { return false })
	t.Fatalf("queued import returned before the crash point: advanced=%v error=%v", advanced, err)
}
