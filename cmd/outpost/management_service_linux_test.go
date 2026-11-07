package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/managementservice"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

func TestCLIManagementPrivateEnrollmentProfileRevisionAndTLSRun(t *testing.T) {
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	ctx := context.Background()
	base := teststore.Root(t)
	owner, _, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	must(e)
	leaf, e := x509.ParseCertificate(der)
	must(e)
	node := storage.Hash(leaf.RawSubjectPublicKeyInfo)
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	must(e)
	certFile, keyFile := filepath.Join(base, "tls.pem"), filepath.Join(base, "tls-key.pem")
	must(os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	must(os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))
	root := filepath.Join(base, "volume")
	must(os.Mkdir(root, 0700))
	probe, e := volume.Probe(ctx, root)
	must(e)
	binding, e := volume.Enroll(ctx, root, probe, node, 1)
	must(e)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	address := listener.Addr().String()
	must(listener.Close())
	profile := managementservice.Profile{Format: managementservice.Format, Revision: 1, Local: worker.Bootstrap{Format: worker.BootstrapFormat, Node: node, Owner: owner, Directory: filepath.Join(root, "management"), Volume: binding, CertificateFile: certFile, PrivateKeyFile: keyFile, CAFile: certFile}, Listen: address, Origin: "https://" + address, Principals: []management.Principal{{Actor: node, Roles: []string{"owner"}, Scopes: []management.Scope{{Tenant: storage.Hash([]byte("tenant")), Domain: storage.Hash([]byte("domain"))}}}}, Limits: diskbudget.Limits{Capacity: 64 << 20, Reserve: 8 << 20, Spool: 16 << 20, Telemetry: 1 << 20}, Concurrency: 1, TimeoutMillis: 500, ReportMaxAgeSeconds: 30, ReconcileSeconds: 1}
	file := filepath.Join(base, "private-profile.json")
	write := func() { raw, e := json.Marshal(profile); must(e); must(os.WriteFile(file, raw, 0600)) }
	write()
	invoke := func(name string) any {
		t.Helper()
		value, e := run(ctx, []string{name, "--input", file})
		must(e)
		raw, e := json.Marshal(value)
		must(e)
		if bytes.Contains(raw, []byte(base)) {
			t.Fatal("private path leaked")
		}
		return value
	}
	invoke("management-init")
	invoke("management-status")
	invoke("management-reconcile")
	if _, e = run(ctx, []string{"management-init", "--input", file}); e == nil {
		t.Fatal("runtime reinitialized")
	}
	profile.Revision = 2
	write()
	invoke("management-profile-set")
	invoke("management-profile-set")
	invoke("management-status")
	profile.Revision = 1
	write()
	if _, e = run(ctx, []string{"management-status", "--input", file}); e == nil {
		t.Fatal("old profile admitted")
	}
	profile.Revision = 2
	write()
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	running, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := run(running, []string{"management-run", "--input", file}); done <- e }()
	ready := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		response, e := client.Get(profile.Origin + "/api/v1/session")
		if e == nil {
			response.Body.Close()
			ready = response.StatusCode == 200
			if ready {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case e := <-done:
		must(e)
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not join")
	}
	if !ready {
		t.Fatal("CLI did not serve authenticated session")
	}
	must(os.Chmod(file, 0644))
	if _, e = run(ctx, []string{"management-status", "--input", file}); e == nil {
		t.Fatal("public profile accepted")
	}
}
