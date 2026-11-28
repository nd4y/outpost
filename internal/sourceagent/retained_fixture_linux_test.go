package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

// Only synthetic test fixtures use this private file. Its keys never belong in
// logs, receipts, source archives or an independently provisioned reader.
type retainedFixtureContext struct {
	Format                                                string
	Bootstrap                                             Bootstrap
	Authority                                             []byte
	DataOwner                                             filekit.Owner
	ControlOwnerKey, WriterKey                            ed25519.PrivateKey
	SourceCertificate, SourceKey                          []byte
	DestinationCertificate, DestinationKey, CertificateCA []byte
}

func reopenRetainedFixture(t *testing.T, directory, digest string) *fixture {
	t.Helper()
	ctx := t.Context()
	admitted := os.Getenv("OUTPOST_TEST_ROOT")
	resolved, err := filepath.EvalSymlinks(directory)
	must(t, err)
	if !storage.ID(digest) || !filepath.IsAbs(admitted) || filepath.Dir(directory) != admitted || resolved != directory {
		t.Fatal("retained fixture escaped its admitted root")
	}
	path := filepath.Join(directory, "fixture-context.json")
	info, err := os.Lstat(path)
	must(t, err)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 64<<10 {
		t.Fatal("unsafe retained synthetic context")
	}
	raw, err := os.ReadFile(path)
	must(t, err)
	if storage.Hash(raw) != digest {
		t.Fatal("retained synthetic context changed")
	}
	var saved retainedFixtureContext
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	must(t, d.Decode(&saved))
	if err = d.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("retained context has trailing data")
	}
	b := saved.Bootstrap
	if saved.Format != "outpost-private-synthetic-fixture-1" || len(saved.ControlOwnerKey) != ed25519.PrivateKeySize || len(saved.WriterKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(saved.ControlOwnerKey.Public().(ed25519.PublicKey), b.Local.Owner) {
		t.Fatal("retained synthetic owner is invalid")
	}
	paths := map[string]string{
		b.Local.Volume.Root: "volume", b.Local.Directory: "volume/agent", b.Tree.Path: "source",
		b.DataKeyFile: "data-key.json", b.WriterKeyFile: "writer-key.json", b.AuthorityFile: "authority.json",
		b.Local.CertificateFile: "source.pem", b.Local.PrivateKeyFile: "source-key.pem", b.Local.CAFile: "ca.pem",
	}
	if len(paths) != 9 {
		t.Fatal("retained fixture paths alias one another")
	}
	for actual, relative := range paths {
		if actual != filepath.Join(directory, relative) {
			t.Fatal("retained fixture path changed its exact scope")
		}
		resolved, err = filepath.EvalSymlinks(actual)
		must(t, err)
		if resolved != actual {
			t.Fatal("retained fixture path contains an alias")
		}
	}
	for path, expected := range map[string][]byte{b.AuthorityFile: saved.Authority, b.Local.CertificateFile: saved.SourceCertificate, b.Local.PrivateKeyFile: saved.SourceKey, b.Local.CAFile: saved.CertificateCA} {
		actual, err := os.ReadFile(path)
		must(t, err)
		if !bytes.Equal(actual, expected) {
			t.Fatal("retained authority or identity file changed")
		}
	}
	grant, err := ingress.VerifyAuthority(saved.Authority, b.Local.Owner, time.Now())
	must(t, err)
	if b.Local.Node != grant.Source || !bytes.Equal(saved.WriterKey.Public().(ed25519.PublicKey), grant.Trust.Writer) || saved.DataOwner.Domain != grant.Trust.Domain ||
		b.Profile.MinimumCopies != 1 || len(b.Profile.CopyTargets) != 1 || b.Profile.CopyTargets[0] != grant.Ingress {
		t.Fatal("retained fixture grant or source scope changed")
	}
	u, err := url.Parse(b.Endpoint)
	must(t, err)
	if u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("retained fixture listener is not the original loopback endpoint")
	}
	destination, err := tls.X509KeyPair(saved.DestinationCertificate, saved.DestinationKey)
	must(t, err)
	leaf, err := x509.ParseCertificate(destination.Certificate[0])
	must(t, err)
	if peer.Identity(leaf) != grant.Ingress {
		t.Fatal("retained receiver identity changed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(saved.CertificateCA) {
		t.Fatal("invalid retained certificate authority")
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1"})
	must(t, err)
	f := &fixture{base: directory, tree: b.Tree.Path, replicaPath: filepath.Join(directory, "replica"), b: b,
		owner: saved.DataOwner, writer: saved.WriterKey, ownerSigner: saved.ControlOwnerKey, authority: saved.Authority,
		grant: grant, destination: destination, roots: roots}
	f.replica, err = generation.Open(f.replicaPath, grant.Trust, false)
	must(t, err)
	t.Cleanup(func() { f.replica.Close() })
	f.registry, err = ingress.OpenRegistry(ctx, ingress.RegistryOptions{Directory: filepath.Join(directory, "registry"), Authority: saved.Authority,
		Owner: b.Local.Owner, Replica: f.replica, Certificate: destination, Roots: roots, Limits: sourceFixtureLimits, Initialize: false})
	must(t, err)
	t.Cleanup(func() { f.registry.Close() })
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.registryMu.RLock()
		defer f.registryMu.RUnlock()
		if f.intercept != nil && f.intercept(w, r) {
			return
		}
		f.registry.ServeHTTP(w, r)
	}))
	s.Listener.Close()
	s.Listener, err = net.Listen("tcp", u.Host)
	must(t, err)
	s.TLS, err = peer.AuthenticatedServerTLS(destination, roots, grant.Ingress)
	must(t, err)
	s.StartTLS()
	f.server = s
	t.Cleanup(s.Close)
	if s.URL != b.Endpoint {
		t.Fatal("retained listener changed its original endpoint")
	}
	f.a, err = Open(ctx, b, false)
	must(t, err)
	t.Cleanup(func() {
		if f.a != nil {
			f.a.Close()
		}
	})
	return f
}

func TestRetainedFixtureReopensOriginalIdentityAuthorityAndCapture(t *testing.T) {
	admitted := t.TempDir()
	t.Setenv("OUTPOST_TEST_ROOT", admitted)
	base := filepath.Join(admitted, "retained-source")
	f := newFixtureWithOptions(t, 1800, nil, nil, fixtureOptions{Directory: base, RetainContext: true, MaxSourceBytes: 1 << 20})
	must(t, f.a.Next(t.Context()))
	pause := errors.New("retained fixture pause after sealed catalog")
	f.a.Fault = func(point string) error {
		if point == "source-catalog-durable" {
			return pause
		}
		return nil
	}
	if err := f.a.Run(t.Context()); !errors.Is(err, pause) {
		t.Fatal("retained fixture did not reach its original seal", err)
	}
	before, err := f.a.Status(t.Context())
	must(t, err)
	if before.Phase != "ACTIVE" || before.Job == nil || before.Job.Phase != "SEALED" || !storage.ID(before.Job.Generation) {
		t.Fatal("missing original sealed capture")
	}
	state, err := f.a.load()
	must(t, err)
	intent, err := f.a.stateIntent(state)
	must(t, err)
	contextBytes, err := os.ReadFile(filepath.Join(base, "fixture-context.json"))
	must(t, err)
	must(t, f.a.Close())
	f.a = nil
	f.server.Close()
	must(t, f.registry.Close())
	must(t, f.replica.Close())
	reopened := reopenRetainedFixture(t, base, storage.Hash(contextBytes))
	pending, err := reopened.a.Status(t.Context())
	must(t, err)
	if pending.Operation != before.Operation || pending.Sequence != before.Sequence || pending.Generation != before.Generation || pending.AuthorityRevision != before.AuthorityRevision ||
		pending.Job == nil || pending.Job.Generation != before.Job.Generation || pending.Job.Phase != "SEALED" {
		t.Fatal("reopen changed the original capture or grant")
	}
	must(t, reopened.a.Run(t.Context()))
	checkpoint, err := reopened.a.Checkpoint(t.Context())
	must(t, err)
	verified, err := capture.VerifyCheckpoint(checkpoint, reopened.grant.Trust)
	must(t, err)
	if verified.Generation != before.Job.Generation || verified.Sequence != intent.Sequence {
		t.Fatal("reopen replaced the original sealed generation")
	}
	after, err := os.ReadFile(filepath.Join(base, "fixture-context.json"))
	must(t, err)
	if !bytes.Equal(contextBytes, after) {
		t.Fatal("reopen rewrote private identity or authority")
	}
	must(t, reopened.replica.VerifyComplete(context.Background(), verified.Generation))
}
