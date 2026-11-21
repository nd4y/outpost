package ingress

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

type registryRenewalChild struct {
	Directory, Replica, Point                             string
	Trust                                                 generation.Trust
	Authority, Intent, Owner, Certificate, PrivateKey, CA []byte
	Recovery                                              *ReceiptRecoveryAdmission
}

func killRenewedSlot(t *testing.T, f *registryFixture, intent []byte, point string, recovery ...ReceiptRecoveryAdmission) {
	t.Helper()
	input := registryRenewalChild{Directory: f.options.Directory, Replica: filepath.Join(f.base, "replica"), Point: point, Trust: f.authority.Trust,
		Authority: f.options.Authority, Intent: intent, Owner: f.options.Owner, Certificate: f.options.Certificate.Certificate[0],
		PrivateKey: []byte(f.options.Certificate.PrivateKey.(ed25519.PrivateKey)), CA: f.ca.cert.Raw}
	if len(recovery) == 1 {
		input.Recovery = &recovery[0]
	}
	if len(recovery) > 1 {
		t.Fatal("ambiguous recovery admission")
	}
	raw, e := json.Marshal(input)
	must(t, e)
	file := filepath.Join(f.base, point+".json")
	must(t, os.WriteFile(file, raw, 0600))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistryRenewalSIGKILLChild$")
	cmd.Env = append(os.Environ(), "OUTPOST_REGISTRY_RENEWAL_KILL="+file)
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || ctx.Err() != nil {
		t.Fatalf("child %s: %v %s", point, err, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("child not killed: %v %s", err, output)
	}
	if input.Recovery != nil {
		t.Log("actual SIGKILL during receipt recovery", point)
	} else {
		t.Log("actual SIGKILL after renewal", point)
	}
}

func TestRegistryRenewalSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_REGISTRY_RENEWAL_KILL")
	if file == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var input registryRenewalChild
	must(t, json.Unmarshal(raw, &input))
	ca, e := x509.ParseCertificate(input.CA)
	must(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	r, e := generation.Open(input.Replica, input.Trust, false)
	must(t, e)
	defer r.Close()
	opts := RegistryOptions{Directory: input.Directory, Authority: input.Authority, Owner: input.Owner, Replica: r,
		Certificate: tls.Certificate{Certificate: [][]byte{input.Certificate}, PrivateKey: ed25519.PrivateKey(input.PrivateKey)}, Roots: roots, Limits: httpLimits}
	fault := func(point string) error {
		if point == input.Point {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	if input.Recovery != nil {
		_, e = RecoverReceipt(context.Background(), opts, *input.Recovery, nil, fault)
		must(t, e)
		t.Fatal("recovery kill not reached")
	}
	g, e := OpenRegistry(context.Background(), opts)
	must(t, e)
	defer g.Close()
	g.Fault = fault
	_, e = g.begin(context.Background(), input.Intent)
	must(t, e)
	t.Fatal("kill not reached")
}
