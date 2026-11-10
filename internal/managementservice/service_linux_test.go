package managementservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func id(s string) string { return storage.Hash([]byte(s)) }

func TestManagementServiceJournalEnableResumesAfterRegistryCommit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, e := Open(ctx, f.p, true)
	must(t, e)
	// Simulate the durable registry commit followed by a lost process before
	// the new profile receipt. Only the exact old profile can authorize retry.
	must(t, s.lease.WithLock(ctx, func() error {
		r, e := management.EnableRegistryJournal(ctx, management.Options{Root: s.root, Directory: "registry", Owner: f.p.Local.Owner, Signer: s.signer, JournalCopy: true, Guard: s.guard, Admission: s.admission("registry")})
		if e != nil {
			return e
		}
		return r.Close()
	}))
	must(t, s.Close())
	candidate := f.p
	candidate.RegistryJournalCopy = true
	candidate.Revision++
	changed := candidate
	changed.ReconcileSeconds++
	if _, e = EnableRegistryJournal(ctx, changed); !errors.Is(e, management.ErrConflict) {
		t.Fatal("migration accepted unrelated profile changes", e)
	}
	status, e := EnableRegistryJournal(ctx, candidate)
	must(t, e)
	if status.ProfileRevision != candidate.Revision || status.ProfileDigest != candidate.digest() {
		t.Fatal(status)
	}
	repeated, e := EnableRegistryJournal(ctx, candidate)
	must(t, e)
	if repeated.ProfileDigest != status.ProfileDigest {
		t.Fatal("retry changed admitted profile", repeated)
	}
}

type fixture struct {
	p                      Profile
	owner                  ed25519.PrivateKey
	client, unknown, plain *http.Client
	root                   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := teststore.Root(t)
	makeKey := func() ed25519.PrivateKey { _, k, e := ed25519.GenerateKey(rand.Reader); must(t, e); return k }
	caKey, serverKey, clientKey, unknownKey, owner := makeKey(), makeKey(), makeKey(), makeKey(), makeKey()
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	must(t, e)
	ca, e = x509.ParseCertificate(der)
	must(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cert := func(k ed25519.PrivateKey, n int64, server bool) tls.Certificate {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, e := x509.CreateCertificate(rand.Reader, leaf, ca, k.Public(), caKey)
		must(t, e)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	server := cert(serverKey, 2, true)
	certPath, keyPath, caPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem"), filepath.Join(root, "ca.pem")
	keyDER, e := x509.MarshalPKCS8PrivateKey(serverKey)
	must(t, e)
	must(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate[0]}), 0600))
	must(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))
	must(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	vol := filepath.Join(root, "volume")
	must(t, os.Mkdir(vol, 0700))
	obs, e := volume.Probe(context.Background(), vol)
	must(t, e)
	serviceID := command.Identity(serverKey.Public().(ed25519.PublicKey))
	binding, e := volume.Enroll(context.Background(), vol, obs, serviceID, 1)
	must(t, e)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	must(t, e)
	address := listener.Addr().String()
	must(t, listener.Close())
	p := Profile{Format: Format, Revision: 1, Local: worker.Bootstrap{Format: worker.BootstrapFormat, Node: serviceID, Owner: owner.Public().(ed25519.PublicKey), Directory: filepath.Join(vol, "management"), Volume: binding, CertificateFile: certPath, PrivateKeyFile: keyPath, CAFile: caPath}, Listen: address, Origin: "https://" + address, Principals: []management.Principal{{Actor: command.Identity(clientKey.Public().(ed25519.PublicKey)), Roles: []string{"owner"}, Scopes: []management.Scope{{Tenant: id("tenant"), Domain: id("domain")}}}}, Limits: diskbudget.Limits{Capacity: 64 << 20, Reserve: 8 << 20, Spool: 16 << 20, Telemetry: 1 << 20}, Concurrency: 2, TimeoutMillis: 500, ReportMaxAgeSeconds: 60, ReconcileSeconds: 1}
	client := func(pair *tls.Certificate) *http.Client {
		config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
		if pair != nil {
			config.Certificates = []tls.Certificate{*pair}
		}
		transport := &http.Transport{TLSClientConfig: config, Proxy: nil}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	c, u := cert(clientKey, 3, false), cert(unknownKey, 4, false)
	return &fixture{p: p, owner: owner, client: client(&c), unknown: client(&u), plain: client(nil), root: root}
}
func start(t *testing.T, s *Service, client *http.Client) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(cancel)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, e := client.Get(s.p.Origin + "/api/v1/session")
		if e == nil {
			response.Body.Close()
			return cancel, done
		}
		select {
		case e := <-done:
			t.Fatalf("service stopped before admission: %v", e)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("listener did not start")
	return cancel, done
}
func stop(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case e := <-done:
		must(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("service did not join")
	}
}

func TestManagementServiceRealTLSAutomaticallyReconcilesSavedIntent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, e := Open(ctx, f.p, true)
	must(t, e)
	_, node, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	now := time.Now().Unix()
	enrollment := management.Enrollment{Format: management.EnrollmentFormat, Tenant: id("tenant"), Node: command.Identity(node.Public().(ed25519.PublicKey)), PublicKey: node.Public().(ed25519.PublicKey), Class: "trusted", Revision: 1, NotBefore: now - 30, ExpiresUnix: now + 3600, Domains: []management.DomainAdmission{{Domain: id("domain"), Repository: id("repo"), Epoch: 1}}}
	raw, e := management.SignEnrollment(enrollment, f.owner)
	must(t, e)
	s.registry.Fault = func(point string) error {
		if point == "management-enrollment-intent-durable" {
			return errors.New("lost response")
		}
		return nil
	}
	_, e = s.registry.ApplyEnrollment(ctx, f.p.Principals[0], id("enroll"), "INITIAL_ENROLLMENT", raw, 0)
	if e == nil {
		t.Fatal("missing fault")
	}
	must(t, s.Close())
	s, e = Open(ctx, f.p, false)
	must(t, e)
	defer s.Close()
	cancel, done := start(t, s, f.client)
	defer stop(t, cancel, done)
	path := f.p.Origin + "/api/v1/tenants/" + id("tenant") + "/operations/" + id("enroll")
	deadline := time.Now().Add(4 * time.Second)
	var receipt management.Receipt
	for time.Now().Before(deadline) {
		response, e := f.client.Get(path)
		must(t, e)
		data, e := io.ReadAll(response.Body)
		response.Body.Close()
		must(t, e)
		must(t, json.Unmarshal(data, &receipt))
		if receipt.State == "COMPLETE" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if receipt.State != "COMPLETE" || receipt.ResultDigest != storage.Hash(raw) {
		t.Fatal("saved intent not reconciled", receipt)
	}
	response, e := f.unknown.Get(f.p.Origin + "/api/v1/session")
	must(t, e)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("unknown actor admitted")
	}
	if response, e = f.plain.Get(f.p.Origin + "/api/v1/session"); e == nil {
		response.Body.Close()
		t.Fatal("unauthenticated TLS admitted")
	}
	status, e := s.Status(ctx)
	must(t, e)
	if status.ProfileRevision != 1 || status.Service != f.p.Local.Node || status.Space.Used["spool"] <= 0 {
		t.Fatal("status missing actual budget", status)
	}
}

func TestManagementServiceProfileChangeRequiresStoppedLeaseAndFencesOldReaders(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, e := Open(ctx, f.p, true)
	must(t, e)
	defer s.Close()
	cancel, done := start(t, s, f.client)
	updated := f.p
	updated.Revision = 2
	updated.Principals = []management.Principal{{Actor: id("replacement-actor"), Roles: []string{"owner"}, Scopes: append([]management.Scope(nil), f.p.Principals[0].Scopes...)}}
	other, e := Open(ctx, updated, false)
	must(t, e)
	defer other.Close()
	bounded, end := context.WithTimeout(ctx, 100*time.Millisecond)
	e = other.ApplyProfile(bounded)
	end()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("active profile changed", e)
	}
	stop(t, cancel, done)
	must(t, other.ApplyProfile(ctx))
	must(t, other.ApplyProfile(ctx))
	if _, e = s.Status(ctx); !errors.Is(e, management.ErrConflict) {
		t.Fatal("old profile used", e)
	}
	if e = s.ApplyProfile(ctx); !errors.Is(e, management.ErrConflict) {
		t.Fatal("profile rollback accepted", e)
	}
	cancel, done = start(t, other, f.client)
	defer stop(t, cancel, done)
	response, e := f.client.Get(updated.Origin + "/api/v1/session")
	must(t, e)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("revoked actor still admitted")
	}
}

func TestManagementServiceStatusPreservesForeignReservationAndVolumeLossStopsListener(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, e := Open(ctx, f.p, true)
	must(t, e)
	defer s.Close()
	finish, e := s.budget.Reserve(ctx, "registry/foreign.json", 4096)
	must(t, e)
	other, e := Open(ctx, f.p, false)
	must(t, e)
	status, e := other.Status(ctx)
	must(t, e)
	must(t, other.Close())
	if len(status.Space.Pending) != 1 {
		t.Fatal("status reconciled foreign reservation")
	}
	must(t, finish(false))
	cancel, done := start(t, s, f.client)
	defer cancel()
	marker := filepath.Join(f.p.Local.Volume.Root, volume.Sentinel)
	raw, e := os.ReadFile(marker)
	must(t, e)
	must(t, os.Remove(marker))
	defer os.WriteFile(marker, raw, 0600)
	select {
	case e := <-done:
		if !errors.Is(e, volume.ErrUnavailable) {
			t.Fatal("volume loss ignored", e)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("listener kept running after volume loss")
	}
	if response, e := f.client.Get(f.p.Origin + "/api/v1/session"); e == nil {
		response.Body.Close()
		t.Fatal("lost-volume service still served")
	}
}

func TestManagementServiceRejectsUnsafeProfileAndTamperedEnrollment(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, alter := range []func(*Profile){func(p *Profile) { p.TimeoutMillis = 1 << 62 }, func(p *Profile) { p.ReportMaxAgeSeconds = 1 << 62 }, func(p *Profile) { p.Limits.Spool = 1 }, func(p *Profile) { p.Listen = "0.0.0.0:0" }, func(p *Profile) { p.Origin = "http://127.0.0.1" }, func(p *Profile) { p.Origin = "https://wrong.invalid" }, func(p *Profile) { p.Local.Owner = p.Local.Owner[:1] }, func(p *Profile) { p.Local.Credentials = map[string]string{id("target"): "/private/key"} }, func(p *Profile) { p.Principals = append(p.Principals, p.Principals[0]) }} {
		p := f.p
		alter(&p)
		if s, e := Open(ctx, p, true); e == nil {
			s.Close()
			t.Fatal("unsafe profile admitted")
		}
		if _, e := os.Lstat(f.p.Local.Directory); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("invalid profile created runtime", e)
		}
	}
	s, e := Open(ctx, f.p, true)
	must(t, e)
	must(t, s.Close())
	path := filepath.Join(f.p.Local.Directory, "service", "profile.json")
	raw, e := os.ReadFile(path)
	must(t, e)
	raw = bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":2`), 1)
	must(t, os.WriteFile(path, raw, 0600))
	if s, e = Open(ctx, f.p, false); e == nil {
		s.Close()
		t.Fatal("tampered local state accepted")
	}
	if s, e = Open(ctx, f.p, true); e == nil {
		s.Close()
		t.Fatal("existing journal silently initialized")
	}
}

func TestManagementServiceProfileOwnsNestedMemoryAfterOpen(t *testing.T) {
	f := newFixture(t)
	f.p.Relays = map[string][]string{}
	ctx := context.Background()
	s, e := Open(ctx, f.p, true)
	must(t, e)
	defer s.Close()
	expected := s.p.digest()
	f.p.Local.Owner[0] ^= 1
	f.p.Principals[0].Roles[0] = "viewer"
	f.p.Principals[0].Scopes[0].Domain = id("changed-by-caller")
	f.p.Relays[id("new-relay")] = []string{id("changed-by-caller")}
	if s.p.digest() != expected {
		t.Fatal("caller mutated admitted profile")
	}
	status, e := s.Status(ctx)
	must(t, e)
	if status.ProfileDigest != expected {
		t.Fatal(status)
	}
}
