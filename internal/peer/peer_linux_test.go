package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
)

var testContext = context.Background()
var testLimits = Limits{Concurrency: 3, Timeout: 3 * time.Second, Attempts: 2}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type authority struct {
	cert         *x509.Certificate
	key          ed25519.PrivateKey
	roots        *x509.CertPool
	serial       int64
	nodeLifetime time.Duration
}

func newAuthority(t *testing.T) *authority {
	return newAuthorityWithLifetime(t, time.Hour, 30*time.Minute)
}
func newAuthorityWithLifetime(t *testing.T, caLifetime, nodeLifetime time.Duration) *authority {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(caLifetime), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	must(t, e)
	cert, e := x509.ParseCertificate(der)
	must(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &authority{cert, key, roots, 1, nodeLifetime}
}
func (a *authority) nodeCert(t *testing.T) tls.Certificate {
	a.serial++
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	template := &x509.Certificate{SerialNumber: big.NewInt(a.serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(a.nodeLifetime), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
	must(t, e)
	private, e := x509.MarshalPKCS8PrivateKey(key)
	must(t, e)
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	must(t, e)
	return cert
}

type node struct {
	dir, id string
	cert    tls.Certificate
	replica *generation.Replica
	journal *Journal
}
type fixture struct {
	base        string
	ca          *authority
	trust       generation.Trust
	writer      ed25519.PrivateKey
	maintenance ed25519.PrivateKey
	owner       filekit.Owner
	source      *filekit.Store
	input       string
	old         []byte
	version     string
	a, b, c     *node
}

func testRoot(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if required := os.Getenv("OUTPOST_TEST_ROOT"); required != "" {
		rel, e := filepath.Rel(required, base)
		if e != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatal("fixture outside admitted HDD")
		}
	}
	return base
}
func newNode(t *testing.T, base, name string, a *authority, trust generation.Trust) *node {
	t.Helper()
	dir := filepath.Join(base, name)
	must(t, os.Mkdir(dir, 0700))
	must(t, os.Mkdir(filepath.Join(dir, "replica"), 0700))
	must(t, os.Mkdir(filepath.Join(dir, "journal"), 0700))
	cert := a.nodeCert(t)
	id, e := certificateID(cert)
	must(t, e)
	r, e := generation.Open(filepath.Join(dir, "replica"), trust, true)
	must(t, e)
	j, e := OpenJournal(filepath.Join(dir, "journal"), id, trust, true)
	must(t, e)
	n := &node{dir, id, cert, r, j}
	t.Cleanup(func() { n.replica.Close(); n.journal.Close() })
	return n
}
func newFixture(t *testing.T) *fixture {
	return newFixtureWithAuthority(t, newAuthority(t))
}
func newFixtureWithAuthority(t *testing.T, ca *authority) *fixture {
	base := testRoot(t)
	owner, e := filekit.NewOwner()
	must(t, e)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	maintenance, maintenanceKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	trust := generation.Trust{Domain: owner.Domain, Repository: generation.Hash([]byte("test repository")), Epoch: 1, Writer: pub, Maintenance: maintenance}
	f := &fixture{base: base, ca: ca, trust: trust, writer: key, owner: owner, maintenance: maintenanceKey}
	f.a = newNode(t, base, "a", ca, trust)
	f.b = newNode(t, base, "b", ca, trust)
	f.c = newNode(t, base, "c", ca, trust)
	f.source, e = filekit.OpenStore(filepath.Join(base, "source-store"), owner, true)
	must(t, e)
	t.Cleanup(func() { f.source.Close() })
	f.input = filepath.Join(base, "source-file")
	f.old = make([]byte, 2<<20)
	_, e = rand.Read(f.old)
	must(t, e)
	must(t, os.WriteFile(f.input, f.old, 0640))
	must(t, os.Chmod(f.input, 0640))
	return f
}
func (f *fixture) policy(n *node, peers ...*node) Policy {
	p := Policy{Self: n.id, Class: "trusted", Domain: f.trust.Domain, Repository: f.trust.Repository, Epoch: 1, AllowedClasses: []string{"trusted"}, Peers: map[string]Grant{}}
	for _, peer := range peers {
		p.Peers[peer.id] = Grant{Class: "trusted", Push: true, Pull: true, ExpiresUnix: time.Now().Add(10 * time.Minute).Unix()}
	}
	return p
}
func (f *fixture) seal(t *testing.T, seq uint64, parent string) (string, string) {
	return f.sealAt(t, seq, parent, time.Now().Unix(), 1)
}
func (f *fixture) sealAt(t *testing.T, seq uint64, parent string, snapshot int64, policy uint64) (string, string) {
	v, e := f.source.Backup(testContext, f.input, filekit.BackupOptions{Names: []string{"private.bin", "alias.bin"}})
	must(t, e)
	c := generation.Catalog{Format: generation.Format, Domain: f.trust.Domain, Repository: f.trust.Repository, Epoch: 1, Sequence: seq, Parent: parent, SnapshotUnix: snapshot, Policy: policy, KitFormat: generation.KitFormat}
	id, e := generation.Seal(testContext, f.source, []string{v.Version}, f.b.replica, c, f.writer)
	must(t, e)
	return id, v.Version
}
func (f *fixture) endpoint(t *testing.T, n *node, p Policy, wrap func(http.Handler) http.Handler) *httptest.Server {
	server, e := NewServer(n.replica, n.journal, p, n.cert, f.ca.roots, testLimits)
	must(t, e)
	if wrap != nil {
		server.Handler = wrap(server.Handler)
	}
	ts := httptest.NewUnstartedServer(server.Handler)
	ts.Config = server
	ts.TLS = server.TLSConfig
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}
func (f *fixture) client(t *testing.T, from, to *node, address string, p Policy) *Client {
	c, e := NewClient(address, to.id, from.cert, f.ca.roots, p, from.journal, f.trust, testLimits)
	must(t, e)
	t.Cleanup(c.Close)
	return c
}
func restore(t *testing.T, f *fixture, n *node, id, version string, want []byte) {
	t.Helper()
	kit := filepath.Join(f.base, "kit-"+version)
	must(t, n.replica.ExportKit(testContext, id, version, kit))
	owner := f.owner
	owner.SigningKey = nil
	r, e := filekit.OpenStore(kit, owner, false)
	must(t, e)
	defer r.Close()
	out := kit + "-restored"
	d, e := r.Restore(testContext, version, out)
	must(t, e)
	b, e := os.ReadFile(filepath.Join(out, d.Names[0]))
	must(t, e)
	if !bytes.Equal(b, want) {
		t.Fatal("independent bytes differ")
	}
	a, e := os.Stat(filepath.Join(out, d.Names[0]))
	must(t, e)
	bInfo, e := os.Stat(filepath.Join(out, d.Names[1]))
	must(t, e)
	if !os.SameFile(a, bInfo) || a.Mode().Perm() != 0640 {
		t.Fatal("attributes/aliases differ")
	}
}

func TestAsynchronousBridgeOnlyTransferAndRestore(t *testing.T) {
	f := newFixture(t)
	first, v1 := f.seal(t, 1, "")
	server := f.endpoint(t, f.a, f.policy(f.a, f.b, f.c), nil)
	push := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	pull := f.client(t, f.c, f.a, server.URL, f.policy(f.c, f.a))
	one, e := push.Push(testContext, generation.Hash([]byte("push one")), first, f.b.replica)
	must(t, e)
	if one.Receipt.Verification != "client-full-readback" || one.TargetReceipt.Verification != "target-window-read" {
		t.Fatal(one)
	}
	_, e = pull.Pull(testContext, generation.Hash([]byte("pull one")), first, f.c.replica)
	must(t, e)
	changed := append([]byte(nil), f.old...)
	copy(changed[1<<20:], bytes.Repeat([]byte{37}, 8192))
	must(t, os.WriteFile(f.input, changed, 0640))
	second, v2 := f.seal(t, 2, first)
	_, e = push.Push(testContext, generation.Hash([]byte("push two")), second, f.b.replica)
	must(t, e)
	// B is no longer available when C's later outbound-only window begins.
	push.Close()
	must(t, f.b.replica.Close())
	must(t, f.b.journal.Close())
	must(t, f.source.Close())
	must(t, os.RemoveAll(f.b.dir))
	must(t, os.RemoveAll(filepath.Join(f.base, "source-store")))
	must(t, os.Remove(f.input))
	result, e := pull.Pull(testContext, generation.Hash([]byte("pull two")), second, f.c.replica)
	must(t, e)
	if result.Receipt.Target != f.c.id || result.Receipt.Verification != "local-window-read" {
		t.Fatal(result)
	}
	if _, e = NewClient(server.URL, f.b.id, f.c.cert, f.ca.roots, f.policy(f.c, f.a), f.c.journal, f.trust, testLimits); !errors.Is(e, ErrDenied) {
		t.Fatal("implicit bypass route", e)
	}
	server.Close()
	_, e = pull.Pull(testContext, generation.Hash([]byte("bridge lost")), generation.Hash([]byte("unavailable next")), f.c.replica)
	if e == nil {
		t.Fatal("unavailable bridge reported delivery")
	}
	status, e := f.c.replica.Status(testContext)
	must(t, e)
	if status.LatestComplete != second {
		t.Fatal("old complete lost")
	}
	restore(t, f, f.c, first, v1, f.old)
	restore(t, f, f.c, second, v2, changed)
}

func TestFalseAcknowledgementCannotCompleteSenderJob(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	raw, e := f.b.replica.Catalog(testContext, id)
	must(t, e)
	var lie atomic.Bool
	lie.Store(true)
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if lie.Load() {
				parts := strings.Split(r.URL.Path, "/")
				if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") {
					respond(w, map[string]string{"object": parts[len(parts)-1], "state": "HASH_VERIFIED_DURABLE"})
					return
				}
				if strings.HasSuffix(r.URL.Path, "/complete") {
					respond(w, Receipt{Format, f.a.id, id, id, r.Header.Get("Outpost-Operation"), "target-full-read", time.Now().Unix()})
					return
				}
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/catalog") {
					_, _ = w.Write(raw)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	op := generation.Hash([]byte("false ack"))
	_, e = client.Push(testContext, op, id, f.b.replica)
	if e == nil {
		t.Fatal("false ACK accepted")
	}
	job, e := f.b.journal.Read(testContext, client.binding(op, id, "push"))
	must(t, e)
	if job.Phase == "COMPLETE" || job.LastReceipt != nil {
		t.Fatal(job)
	}
	status, e := f.a.replica.Status(testContext)
	must(t, e)
	if status.LatestComplete != "" {
		t.Fatal("partial remote generation published")
	}
	lie.Store(false)
	_, e = client.Push(testContext, op, id, f.b.replica)
	must(t, e)
}

func TestLostReplyRestartAndDuplicateTransfer(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	var lose atomic.Bool
	lose.Store(true)
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") && lose.CompareAndSwap(true, false) {
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				conn, _, e := w.(http.Hijacker).Hijack()
				if e == nil {
					conn.Close()
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	client.limits.Concurrency = 1
	client.limits.Attempts = 1
	op := generation.Hash([]byte("lost reply"))
	_, e := client.Push(testContext, op, id, f.b.replica)
	if e == nil {
		t.Fatal("lost ACK not surfaced")
	}
	status, e := f.a.replica.Status(testContext)
	must(t, e)
	if status.LatestComplete != "" {
		t.Fatal("partial published")
	}
	server.Close()
	client.Close()
	must(t, f.a.replica.Close())
	must(t, f.a.journal.Close())
	must(t, f.b.journal.Close())
	f.a.replica, e = generation.Open(filepath.Join(f.a.dir, "replica"), f.trust, false)
	must(t, e)
	f.a.journal, e = OpenJournal(filepath.Join(f.a.dir, "journal"), f.a.id, f.trust, false)
	must(t, e)
	f.b.journal, e = OpenJournal(filepath.Join(f.b.dir, "journal"), f.b.id, f.trust, false)
	must(t, e)
	server = f.endpoint(t, f.a, f.policy(f.a, f.b), nil)
	client = f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	_, e = client.Push(testContext, op, id, f.b.replica)
	must(t, e)
	job, e := f.b.journal.Read(testContext, client.binding(op, id, "push"))
	must(t, e)
	if job.Attempt != 2 || job.Phase != "COMPLETE" {
		t.Fatal(job)
	}
	duplicate, e := client.Push(testContext, op, id, f.b.replica)
	must(t, e)
	if duplicate.Counters.ObjectBytesSubmitted != 0 || duplicate.Counters.ReadbackBytes == 0 {
		t.Fatal("duplicate resent immutable data or skipped readback", duplicate)
	}
	if _, e = client.Push(testContext, op, generation.Hash([]byte("different generation")), f.b.replica); !errors.Is(e, ErrConflict) {
		t.Fatal("operation rebound", e)
	}
}

func TestPartialVisibilityAndCorruptionPreservePreviousComplete(t *testing.T) {
	for _, fault := range []string{"truncated", "corrupt"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			first, _ := f.seal(t, 1, "")
			normal := f.endpoint(t, f.a, f.policy(f.a, f.b, f.c), nil)
			push := f.client(t, f.b, f.a, normal.URL, f.policy(f.b, f.a))
			pull := f.client(t, f.c, f.a, normal.URL, f.policy(f.c, f.a))
			_, e := push.Push(testContext, generation.Hash([]byte("initial send")), first, f.b.replica)
			must(t, e)
			_, e = pull.Pull(testContext, generation.Hash([]byte("initial receive")), first, f.c.replica)
			must(t, e)
			must(t, os.WriteFile(f.input, bytes.Repeat([]byte{71}, 2<<20), 0640))
			second, _ := f.seal(t, 2, first)
			_, e = push.Push(testContext, generation.Hash([]byte("changed send")), second, f.b.replica)
			must(t, e)
			normal.Close()
			var broken atomic.Bool
			var injected atomic.Int64
			broken.Store(true)
			server := f.endpoint(t, f.a, f.policy(f.a, f.c), func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if broken.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/objects/") {
						rec := httptest.NewRecorder()
						next.ServeHTTP(rec, r)
						for k, values := range rec.Header() {
							for _, v := range values {
								w.Header().Add(k, v)
							}
						}
						data := rec.Body.Bytes()
						if rec.Code != 200 {
							// The first invalid object cancels its concurrent siblings.
							// Preserve that real response; corrupt only successful reads.
							if rec.Code != http.StatusServiceUnavailable || r.Context().Err() == nil {
								t.Errorf("unexpected fault fixture response: status=%d context=%v", rec.Code, r.Context().Err())
							}
							w.WriteHeader(rec.Code)
							_, _ = w.Write(data)
							return
						}
						if len(data) == 0 {
							t.Error("empty successful object response")
							w.WriteHeader(500)
							return
						}
						injected.Add(1)
						if fault == "truncated" {
							_, _ = w.Write(data[:len(data)/2])
						} else {
							data[0] ^= 1
							_, _ = w.Write(data)
						}
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			pull = f.client(t, f.c, f.a, server.URL, f.policy(f.c, f.a))
			op := generation.Hash([]byte("fault receive"))
			_, e = pull.Pull(testContext, op, second, f.c.replica)
			if e == nil {
				t.Fatal("invalid object accepted")
			}
			if injected.Load() == 0 {
				t.Fatal("transfer failed without exercising the injected data fault")
			}
			status, e := f.c.replica.Status(testContext)
			must(t, e)
			if status.LatestComplete != first {
				t.Fatal("old complete lost")
			}
			broken.Store(false)
			_, e = pull.Pull(testContext, op, second, f.c.replica)
			must(t, e)
		})
	}
}

func TestAuthorizationTLSScopesAndNoRedirect(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	var forbiddenRequests atomic.Int64
	forbidden := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forbiddenRequests.Add(1); w.WriteHeader(200) }))
	defer forbidden.Close()
	var redirect atomic.Bool
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if redirect.Load() {
				http.Redirect(w, r, forbidden.URL, 307)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	policy := f.policy(f.b, f.a)
	for _, address := range []string{strings.Replace(server.URL, "https://", "http://", 1), server.URL + "/?secret=value", server.URL + "/other"} {
		if _, e := NewClient(address, f.a.id, f.b.cert, f.ca.roots, policy, f.b.journal, f.trust, testLimits); e == nil {
			t.Fatal("unsafe route accepted")
		}
	}
	denied := f.policy(f.b, f.a)
	g := denied.Peers[f.a.id]
	g.ExpiresUnix = time.Now().Unix() - 1
	denied.Peers[f.a.id] = g
	client := f.client(t, f.b, f.a, server.URL, denied)
	if _, e := client.Push(testContext, generation.Hash([]byte("expired")), id, f.b.replica); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	wrongClass := f.policy(f.b, f.a)
	wrongClass.Class = "untrusted"
	if _, e := NewClient(server.URL, f.a.id, f.b.cert, f.ca.roots, wrongClass, f.b.journal, f.trust, testLimits); !errors.Is(e, ErrDenied) {
		t.Fatal("trusted-only domain bypass", e)
	}
	unknown := f.policy(f.c, f.a)
	client = f.client(t, f.c, f.a, server.URL, unknown)
	if _, e := client.Pull(testContext, generation.Hash([]byte("unknown peer")), id, f.c.replica); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	badPin := f.policy(f.b, f.a)
	fake := generation.Hash([]byte("wrong TLS identity"))
	badPin.Peers[fake] = badPin.Peers[f.a.id]
	client, e := NewClient(server.URL, fake, f.b.cert, f.ca.roots, badPin, f.b.journal, f.trust, testLimits)
	must(t, e)
	defer client.Close()
	if _, e = client.Push(testContext, generation.Hash([]byte("bad pin")), id, f.b.replica); e == nil {
		t.Fatal("wrong TLS identity accepted")
	}
	client = f.client(t, f.b, f.a, server.URL, policy)
	redirect.Store(true)
	if _, e = client.Push(testContext, generation.Hash([]byte("redirect")), id, f.b.replica); e == nil {
		t.Fatal("redirect accepted")
	}
	if forbiddenRequests.Load() != 0 {
		t.Fatal("followed unapproved route")
	}
	redirect.Store(false)
	// An authenticated sender still cannot choose its signing key or domain.
	raw, e := f.b.replica.Catalog(testContext, id)
	must(t, e)
	var catalog generation.Catalog
	must(t, json.Unmarshal(raw, &catalog))
	_, unauthorized, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	bad, e := generation.SignCatalog(catalog, unauthorized)
	must(t, e)
	if _, e = client.request(testContext, generation.Hash([]byte("wrong author")), generation.Hash(bad), "push", http.MethodPut, "catalog", bad, 1024, nil); e == nil {
		t.Fatal("unauthorized catalog author accepted")
	}
	client.policy.Domain = generation.Hash([]byte("other domain"))
	if _, e = client.request(testContext, generation.Hash([]byte("wrong domain")), id, "push", http.MethodPut, "catalog", raw, 1024, nil); e == nil {
		t.Fatal("cross-domain path accepted")
	}
}

func TestParallelObjectTransferIsBounded(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	var active, peak atomic.Int64
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") {
				n := active.Add(1)
				defer active.Add(-1)
				for {
					old := peak.Load()
					if n <= old || peak.CompareAndSwap(old, n) {
						break
					}
				}
				time.Sleep(30 * time.Millisecond)
			}
			next.ServeHTTP(w, r)
		})
	})
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	_, e := client.Push(testContext, generation.Hash([]byte("parallel")), id, f.b.replica)
	must(t, e)
	if peak.Load() < 2 || peak.Load() > int64(testLimits.Concurrency) {
		t.Fatal(fmt.Sprintf("unexpected object concurrency %d", peak.Load()))
	}
}
