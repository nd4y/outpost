package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

type testCA struct {
	cert   *x509.Certificate
	key    ed25519.PrivateKey
	roots  *x509.CertPool
	serial int64
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	must(t, e)
	cert, e := x509.ParseCertificate(der)
	must(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &testCA{cert, key, roots, 1}
}
func (a *testCA) node(t *testing.T) tls.Certificate {
	t.Helper()
	a.serial++
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	template := &x509.Certificate{SerialNumber: big.NewInt(a.serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * time.Minute), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
	must(t, e)
	private, e := x509.MarshalPKCS8PrivateKey(key)
	must(t, e)
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	must(t, e)
	return cert
}
func certID(t *testing.T, c tls.Certificate) string {
	t.Helper()
	leaf, e := x509.ParseCertificate(c.Certificate[0])
	must(t, e)
	return peer.Identity(leaf)
}

var httpLimits = peer.Limits{Concurrency: 2, Timeout: 5 * time.Second, Attempts: 1}

type httpFixture struct {
	*fixture
	ca                     *testCA
	sourceCert, serverCert tls.Certificate
	server                 *httptest.Server
	client                 *Client
}

func network(t *testing.T, wrap func(http.Handler) http.Handler) *httpFixture {
	t.Helper()
	ca := newCA(t)
	source, receiver := ca.node(t), ca.node(t)
	f := setupIDs(t, certID(t, source), certID(t, receiver))
	wire, e := NewServer(f.session, receiver, ca.roots, httpLimits)
	must(t, e)
	handler := wire.Handler
	if wrap != nil {
		handler = wrap(handler)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = wire.TLSConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	client, e := NewClient(server.URL, f.options.Authority, f.options.Intent, f.options.Owner, source, ca.roots, httpLimits)
	must(t, e)
	t.Cleanup(client.Close)
	must(t, f.source.Close())
	f.source, e = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, client)
	must(t, e)
	return &httpFixture{f, ca, source, receiver, server, client}
}
func TestAuthenticatedSourceIngressAndOfflineReplicaRecovery(t *testing.T) {
	f := network(t, nil)
	ctx := context.Background()
	stats, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{stats.Version})
	for id, b := range roots {
		_, e = f.client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
	batch, receipt, e := f.client.FinishStep(ctx, raw)
	must(t, e)
	if !batch.Complete || receipt == nil || receipt.Generation != storage.Hash(raw) {
		t.Fatal("missing complete receipt", batch, receipt)
	}
	entries, e := os.ReadDir(filepath.Join(f.base, "source-cache/objects"))
	must(t, e)
	if len(entries) != 0 {
		t.Fatal("source keeps payload")
	}
	if f.client.UploadedBytes.Load() < int64(len(f.payload)) || f.client.ReadbackBytes.Load() < int64(len(f.payload)) {
		t.Fatal("body transfer costs omitted")
	}
	f.client.Close()
	f.server.Close()
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil
	must(t, os.RemoveAll(filepath.Join(f.base, "source-cache")))
	must(t, os.RemoveAll(filepath.Join(f.base, "session")))
	must(t, os.Remove(f.input))
	f.owner.SigningKey = nil
	out := filepath.Join(f.base, "restored")
	_, e = generation.RecoverMaterialized(ctx, filepath.Join(f.base, "replica"), receipt.Generation, f.authority.Trust, f.owner, generation.RecoverySelection{}, out)
	must(t, e)
	body, e := os.ReadFile(filepath.Join(out, "private/data"))
	must(t, e)
	if !bytes.Equal(body, f.payload) {
		t.Fatal("offline content differs")
	}
}
func TestIngressRejectsWrongIdentityScopeAndCancelledRequest(t *testing.T) {
	f := network(t, nil)
	rogue := f.ca.node(t)
	if c, e := NewClient(f.server.URL, f.options.Authority, f.options.Intent, f.options.Owner, rogue, f.ca.roots, httpLimits); e == nil {
		c.Close()
		t.Fatal("wrong source identity accepted")
	}
	h, _, e := peer.AuthenticatedHTTP(f.server.URL, rogue, f.ca.roots, certID(t, rogue), f.intent.Ingress, httpLimits)
	must(t, e)
	defer h.CloseIdleConnections()
	r, e := http.NewRequest(http.MethodGet, f.server.URL+route(f.intent)+"/catalog", nil)
	must(t, e)
	r.Header.Set("Outpost-Authority", f.intent.Authority)
	response, e := h.Do(r)
	must(t, e)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("server did not enforce source identity", response.StatusCode)
	}
	r, e = http.NewRequest(http.MethodGet, f.server.URL+strings.Replace(route(f.intent), f.intent.Tenant, storage.Hash([]byte("other tenant")), 1)+"/catalog", nil)
	must(t, e)
	r.Header.Set("Outpost-Authority", f.intent.Authority)
	response, e = f.client.http.Do(r)
	must(t, e)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("cross-tenant request accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = f.client.Read(ctx, filekit.Object{ID: storage.Hash([]byte("object")), Bytes: 1}); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel ignored", e)
	}
}
func TestIngressClientRejectsFalseObjectAcknowledgementAndRedirect(t *testing.T) {
	for _, mode := range []string{"false-ack", "redirect", "corrupt-readback"} {
		t.Run(mode, func(t *testing.T) {
			var redirected atomic.Int64
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(http.StatusOK) }))
			defer other.Close()
			payload := []byte("opaque verified payload")
			ref := filekit.Object{ID: storage.Hash(payload), Bytes: len(payload)}
			f := network(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/objects/") {
						if mode == "false-ack" && r.Method == http.MethodPut {
							jsonReply(w, http.StatusOK, struct {
								Created bool `json:"created"`
							}{true})
							return
						}
						if mode == "redirect" {
							http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
							return
						}
						if mode == "corrupt-readback" && r.Method == http.MethodGet {
							bad := bytes.Clone(payload)
							bad[0] ^= 1
							_, _ = w.Write(bad)
							return
						}
					}
					next.ServeHTTP(w, r)
				})
			})
			if _, e := f.client.Write(context.Background(), ref, payload); e == nil {
				t.Fatal("unverified object accepted")
			}
			if redirected.Load() != 0 {
				t.Fatal("redirect followed")
			}
		})
	}
}
