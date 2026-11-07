package sourceagent

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
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/source"
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

type fixture struct {
	base, tree, replicaPath string
	b                       Bootstrap
	a                       *Agent
	owner                   filekit.Owner
	grant                   ingress.Authority
	authority               []byte
	writer                  ed25519.PrivateKey
	intercept               func(http.ResponseWriter, *http.Request) bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{base: teststore.Root(t)}
	write := func(name string, raw []byte) string {
		p := filepath.Join(f.base, name)
		must(t, os.WriteFile(p, raw, 0600))
		return p
	}
	marshal := func(v any) []byte { b, e := json.Marshal(v); must(t, e); return b }
	pub, caKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, caKey)
	must(t, e)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	caFile := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	newCert := func(serial int64) (tls.Certificate, []byte, []byte) {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
		must(t, e)
		private, e := x509.MarshalPKCS8PrivateKey(key)
		must(t, e)
		cp, kp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		cert, e := tls.X509KeyPair(cp, kp)
		must(t, e)
		return cert, cp, kp
	}
	src, cp, kp := newCert(2)
	dst, _, _ := newCert(3)
	id := func(c tls.Certificate) string {
		leaf, e := x509.ParseCertificate(c.Certificate[0])
		must(t, e)
		return peer.Identity(leaf)
	}
	ownerPub, ownerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	writer, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.writer = key
	maint, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.owner, e = filekit.NewOwner()
	must(t, e)
	trust := generation.Trust{Domain: f.owner.Domain, Repository: storage.Hash([]byte("repo")), Epoch: 1, Writer: writer, Maintenance: maint}
	f.grant = ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: id(src), Ingress: id(dst), Revision: 1, NotBefore: now.Unix() - 10, ExpiresUnix: now.Unix() + 1800, Trust: trust, MaxBytes: 32 << 20, MaxObjects: 128}
	f.authority, e = ingress.SignAuthority(f.grant, ownerKey)
	must(t, e)
	f.replicaPath = filepath.Join(f.base, "replica")
	must(t, os.Mkdir(f.replicaPath, 0700))
	r, e := generation.Open(f.replicaPath, trust, true)
	must(t, e)
	t.Cleanup(func() { r.Close() })
	g, e := ingress.OpenRegistry(ctx, ingress.RegistryOptions{Directory: filepath.Join(f.base, "registry"), Authority: f.authority, Owner: ownerPub, Replica: r, Certificate: dst, Roots: roots, Limits: peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1}, Initialize: true})
	must(t, e)
	t.Cleanup(func() { g.Close() })
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.intercept != nil && f.intercept(w, r) {
			return
		}
		g.ServeHTTP(w, r)
	}))
	s.TLS, e = peer.AuthenticatedServerTLS(dst, roots, id(dst))
	must(t, e)
	s.StartTLS()
	t.Cleanup(s.Close)
	vol := filepath.Join(f.base, "volume")
	must(t, os.Mkdir(vol, 0700))
	obs, e := volume.Probe(ctx, vol)
	must(t, e)
	binding, e := volume.Enroll(ctx, vol, obs, id(src), 1)
	must(t, e)
	f.tree = filepath.Join(f.base, "source")
	must(t, os.Mkdir(f.tree, 0700))
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), bytes.Repeat([]byte("source"), 65536), 0640))
	origin := storage.Hash([]byte("origin"))
	tree, e := capture.ProbeTree(ctx, f.tree, origin)
	must(t, e)
	f.b = Bootstrap{Format: Format, Local: worker.Bootstrap{Format: worker.BootstrapFormat, Volume: binding, Directory: filepath.Join(vol, "agent"), Node: id(src), Owner: ownerPub, CertificateFile: write("source.pem", cp), PrivateKeyFile: write("source-key.pem", kp), CAFile: caFile}, Profile: capture.Profile{ID: f.grant.Profile, Origin: origin, Consistency: "best-effort", Selection: source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: f.owner.Domain}}, Domains: map[string]bool{f.owner.Domain: true}, EntryLimit: 128}, MaxSourceBytes: 32 << 20, MinimumCopies: 1, CopyTargets: []string{id(dst)}}, Tree: tree, DataKeyFile: write("data-key.json", marshal(f.owner)), WriterKeyFile: write("writer-key.json", marshal(map[string]any{"privateKey": key})), AuthorityFile: write("authority.json", f.authority), Endpoint: s.URL, Limits: diskbudget.Limits{Capacity: 128 << 20, Reserve: 8 << 20, Spool: 64 << 20, Telemetry: 1 << 20}}
	f.a, e = Open(ctx, f.b, true)
	must(t, e)
	t.Cleanup(func() {
		if f.a != nil {
			f.a.Close()
		}
	})
	return f
}
func (f *fixture) intent(t *testing.T, seq uint64, parent string) []byte {
	t.Helper()
	a := f.grant
	now := time.Now().Unix()
	i := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte(parent + "operation")), Authority: storage.Hash(f.authority), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: 1, Sequence: seq, Parent: parent, Policy: 1, SnapshotUnix: now, NotBefore: now - 1, ExpiresUnix: now + 600, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	raw, e := ingress.SignIntent(i, f.authority, f.b.Local.Owner, f.writer, time.Now())
	must(t, e)
	return raw
}
func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	must(t, f.a.Close())
	f.a = nil
	var e error
	f.a, e = Open(context.Background(), f.b, false)
	must(t, e)
}

func TestExecutableSourceRuntimeResumesAndPreservesIndependentHistory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	intent := f.intent(t, 1, "")
	f.a.Fault = func(p string) error {
		if p == "source-agent-intent-durable" {
			return errors.New("process stopped")
		}
		return nil
	}
	if e := f.a.Prepare(ctx, intent); e == nil {
		t.Fatal("missing intent interruption")
	}
	f.reopen(t)
	wrong := f.intent(t, 2, storage.Hash([]byte("wrong")))
	if e := f.a.Prepare(ctx, wrong); !errors.Is(e, ingress.ErrConflict) {
		t.Fatal("fenced intent replaced", e)
	}
	must(t, f.a.Prepare(ctx, intent))
	f.a.Fault = func(p string) error {
		if p == "source-agent-before-head" {
			return errors.New("head not committed")
		}
		return nil
	}
	if e := f.a.Run(ctx); e == nil {
		t.Fatal("missing head interruption")
	}
	f.reopen(t)
	must(t, f.a.Run(ctx))
	checkpoint, e := f.a.Checkpoint(ctx)
	must(t, e)
	first, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	status, e := f.a.Status(ctx)
	must(t, e)
	if status.Phase != "COMPLETE" || status.Sequence != 1 {
		t.Fatal(status)
	}
	if bytes.Contains(checkpoint, []byte("private.bin")) {
		t.Fatal("plaintext name in checkpoint")
	}
	firstBytes, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	next := bytes.Repeat([]byte("changed"), 40000)
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), next, 0640))
	must(t, f.a.Next(ctx))
	pending, e := f.a.Status(ctx)
	must(t, e)
	must(t, f.a.Next(ctx))
	repeated, e := f.a.Status(ctx)
	must(t, e)
	if repeated.Operation != pending.Operation {
		t.Fatal("repeated next replaced pending operation")
	}
	f.reopen(t)
	must(t, f.a.Run(ctx))
	checkpoint, e = f.a.Checkpoint(ctx)
	must(t, e)
	second, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	if second.Sequence != 2 || second.Generation == first.Generation {
		t.Fatal("head not advanced", second)
	}
	// Only the test removes its source. The installed provider never does so.
	must(t, os.RemoveAll(f.tree))
	for name, item := range map[string]struct {
		id      string
		content []byte
	}{"first": {first.Generation, firstBytes}, "second": {second.Generation, next}} {
		out := filepath.Join(f.base, name)
		_, e = generation.RecoverMaterialized(ctx, f.replicaPath, item.id, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		if !bytes.Equal(got, item.content) {
			t.Fatal("wrong independent version", name)
		}
	}
	f.reopen(t)
	must(t, f.a.Run(ctx))
}

func TestSourceRuntimeRejectsProfileDowngradeStateTamperAndVolumeLoss(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.b
	b.Profile.MinimumCopies = 2
	if _, e := Open(ctx, b, false); !errors.Is(e, ErrUnsupported) {
		t.Fatal("copy policy downgraded", e)
	}
	b = f.b
	b.Profile.Consistency = "filesystem"
	if _, e := Open(ctx, b, false); !errors.Is(e, ErrUnsupported) {
		t.Fatal("consistency downgraded", e)
	}
	must(t, f.a.Prepare(ctx, f.intent(t, 1, "")))
	marker := filepath.Join(f.b.Local.Volume.Root, volume.Sentinel)
	must(t, os.Rename(marker, marker+"-held"))
	if e := f.a.Run(ctx); !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("missing volume admitted", e)
	}
	must(t, os.Rename(marker+"-held", marker))
	must(t, f.a.Close())
	f.a = nil
	name := filepath.Join(f.b.Local.Directory, "state", "agent.json")
	raw, e := os.ReadFile(name)
	must(t, e)
	var stored state
	must(t, json.Unmarshal(raw, &stored))
	stored.Phase = "COMPLETE"
	raw, e = json.Marshal(stored)
	must(t, e)
	must(t, os.WriteFile(name, raw, 0600))
	if a, e := Open(ctx, f.b, false); e == nil {
		a.Close()
		t.Fatal("unsigned phase change accepted")
	}
}

func TestSourceVolumeLossCancelsInflightHTTPSAndJoins(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.Prepare(ctx, f.intent(t, 1, "")))
	entered := make(chan struct{})
	released := make(chan struct{})
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		close(entered)
		// Reading the request body lets net/http observe a disconnected peer.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		close(released)
		return true
	}
	done := make(chan error, 1)
	go func() { done <- f.a.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request not reached")
	}
	marker := filepath.Join(f.b.Local.Volume.Root, volume.Sentinel)
	must(t, os.Rename(marker, marker+"-held"))
	select {
	case e := <-done:
		if !errors.Is(e, volume.ErrUnavailable) {
			t.Fatal("lost volume cause missing", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("source did not cancel inflight request")
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("server request not joined")
	}
	f.intercept = nil
}

func TestSourceInitRejectsOverlapBeforeCreatingRuntime(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.b
	var e error
	b.Tree, e = capture.ProbeTree(ctx, f.base, b.Profile.Origin)
	must(t, e)
	b.Local.Directory = filepath.Join(b.Local.Volume.Root, "never-created")
	if a, e := Open(ctx, b, true); e == nil {
		a.Close()
		t.Fatal("runtime created inside source")
	}
	if _, e := os.Lstat(b.Local.Directory); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("init mutated source", e)
	}
}
