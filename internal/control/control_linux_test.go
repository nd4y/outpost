package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	return p, k
}
func configFixture(t *testing.T) (Config, ed25519.PrivateKey) {
	_, owner := key(t)
	writer, _ := key(t)
	maintenance, _ := key(t)
	planner, _ := key(t)
	a, b, c := storage.Hash([]byte("a")), storage.Hash([]byte("b")), storage.Hash([]byte("c"))
	domain := storage.Hash([]byte("domain"))
	return Config{Format: Format, Node: a, Revision: 1, NotBefore: time.Now().Add(-time.Minute).Unix(), ExpiresUnix: time.Now().Add(time.Hour).Unix(), Limits: Limits{Parallel: 2, AttemptMillis: 1000, PollSeconds: 2, CapacityBytes: 1 << 30, ReserveBytes: 1 << 28, SpoolBytes: 1 << 26, TelemetryBytes: 1 << 20}, Nodes: []policy.Node{{ID: a, Class: "trusted", Endpoint: "https://a.invalid"}, {ID: b, Class: "trusted", Endpoint: "https://b.invalid"}, {ID: c, Class: "untrusted"}}, Domains: []Domain{{Trust: generation.Trust{Domain: domain, Repository: storage.Hash([]byte("repository")), Epoch: 1, Writer: writer, Maintenance: maintenance}, Planner: planner, Placement: policy.Placement{Domain: domain, AllowedClasses: []string{"trusted", "untrusted"}, Holders: []string{a, c}, Transit: []string{b}, Edges: []policy.Edge{{From: a, To: b, Mode: "push"}, {From: b, To: c, Mode: "pull"}}}}}}, owner
}
func TestOwnerConfigurationRejectsExpansionAndAmbiguousIdentity(t *testing.T) {
	base, k := configFixture(t)
	raw, e := Sign(base, k)
	must(t, e)
	_, e = Verify(raw, k.Public().(ed25519.PublicKey), base.Node)
	must(t, e)
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Nodes = append(c.Nodes, c.Nodes[0]) },
		func(c *Config) { c.Domains = append(c.Domains, c.Domains[0]) },
		func(c *Config) { c.Domains[0].Planner = c.Domains[0].Trust.Writer },
		func(c *Config) { c.Domains[0].Trust.Writer = k.Public().(ed25519.PublicKey) },
		func(c *Config) { c.Domains[0].Placement.AllowedClasses = []string{"trusted"} },
		func(c *Config) {
			c.Jobs = []Job{{Operation: storage.Hash([]byte("op")), Kind: "push", Domain: c.Domains[0].Trust.Domain, Generation: storage.Hash([]byte("gen")), Peer: c.Nodes[2].ID}}
		},
		func(c *Config) { c.Limits.ReserveBytes = c.Limits.CapacityBytes },
	} {
		var c Config
		must(t, json.Unmarshal(raw, &c))
		mutate(&c)
		if _, e := Sign(c, k); e == nil {
			t.Fatal("invalid owner configuration signed")
		}
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-10] ^= 1
	if _, e := Verify(bad, k.Public().(ed25519.PublicKey), base.Node); e == nil {
		t.Fatal("tampered configuration admitted")
	}
	if _, e := Verify(raw, k.Public().(ed25519.PublicKey), base.Nodes[1].ID); e == nil {
		t.Fatal("wrong recipient admitted")
	}
	if _, e := Verify(append(raw, '\n'), k.Public().(ed25519.PublicKey), base.Node); e == nil {
		t.Fatal("noncanonical signed document admitted")
	}
}
func TestCachedPolicySurvivesRestartWithoutRollbackOrExpiredFallback(t *testing.T) {
	ctx := context.Background()
	c, k := configFixture(t)
	now := time.Now()
	dir := filepath.Join(teststore.Root(t), "cache")
	cache, e := OpenCache(dir, c.Node, k.Public().(ed25519.PublicKey), true)
	must(t, e)
	raw, e := Sign(c, k)
	must(t, e)
	must(t, cache.Accept(ctx, raw, now))
	must(t, cache.Accept(ctx, raw, now))
	must(t, cache.Close())
	cache, e = OpenCache(dir, c.Node, k.Public().(ed25519.PublicKey), false)
	must(t, e)
	defer cache.Close()
	got, e := cache.Current(ctx, now)
	must(t, e)
	if got.Revision != 1 {
		t.Fatal("lost cached revision")
	}
	changed := c
	changed.Limits.Parallel = 1
	conflict, e := Sign(changed, k)
	must(t, e)
	if !errors.Is(cache.Accept(ctx, conflict, now), ErrRollback) {
		t.Fatal("same-revision conflict admitted")
	}
	c.Revision = 2
	c.NotBefore = now.Add(time.Minute).Unix()
	future, e := Sign(c, k)
	must(t, e)
	must(t, cache.Accept(ctx, future, now))
	if _, e = cache.Current(ctx, now); !errors.Is(e, ErrInactive) {
		t.Fatal("fell back to previous policy before activation")
	}
	if !errors.Is(cache.Accept(ctx, raw, now), ErrRollback) {
		t.Fatal("old policy admitted")
	}
	_, e = cache.Current(ctx, now.Add(2*time.Minute))
	must(t, e)
	if _, e = cache.Current(ctx, now); !errors.Is(e, ErrRollback) {
		t.Fatal("clock rollback resurrected policy")
	}
	if _, e = cache.Current(ctx, time.Unix(c.ExpiresUnix, 0)); !errors.Is(e, ErrInactive) {
		t.Fatal("expired policy active")
	}
	preserved, e := cache.Raw(ctx)
	must(t, e)
	if !bytes.Equal(preserved, future) {
		t.Fatal("expiry deleted signed cache")
	}
}
func TestAuthorityHistorySurvivesDomainRemoval(t *testing.T) {
	ctx := context.Background()
	c, k := configFixture(t)
	now := time.Now()
	cache, e := OpenCache(filepath.Join(teststore.Root(t), "cache"), c.Node, k.Public().(ed25519.PublicKey), true)
	must(t, e)
	defer cache.Close()
	c.Domains[0].Trust.Epoch = 3
	raw, e := Sign(c, k)
	must(t, e)
	must(t, cache.Accept(ctx, raw, now))
	remember := c.Domains[0]
	c.Domains = nil
	c.Revision = 2
	raw, e = Sign(c, k)
	must(t, e)
	must(t, cache.Accept(ctx, raw, now))
	remember.Trust.Epoch = 2
	c.Domains = []Domain{remember}
	c.Revision = 3
	raw, e = Sign(c, k)
	must(t, e)
	if !errors.Is(cache.Accept(ctx, raw, now), ErrRollback) {
		t.Fatal("removed domain lost epoch floor")
	}
	remember.Trust.Epoch = 3
	remember.Planner, _ = key(t)
	c.Domains = []Domain{remember}
	raw, e = Sign(c, k)
	must(t, e)
	if !errors.Is(cache.Accept(ctx, raw, now), ErrRollback) {
		t.Fatal("same-epoch authority replaced")
	}
}
func TestCacheRejectsCorruptionSymlinkAndWrongBootstrap(t *testing.T) {
	c, k := configFixture(t)
	dir := filepath.Join(teststore.Root(t), "cache")
	cache, e := OpenCache(dir, c.Node, k.Public().(ed25519.PublicKey), true)
	must(t, e)
	must(t, cache.Close())
	other, _ := key(t)
	if bad, e := OpenCache(dir, c.Node, other, true); e == nil {
		bad.Close()
		t.Fatal("bootstrap mismatch silently reset cache")
	}
	path := filepath.Join(dir, "cache.json")
	must(t, os.WriteFile(path, []byte("broken"), 0600))
	if bad, e := OpenCache(dir, c.Node, k.Public().(ed25519.PublicKey), true); e == nil {
		bad.Close()
		t.Fatal("corruption silently reset cache")
	}
	must(t, os.Remove(path))
	must(t, os.Symlink("/dev/zero", path))
	if bad, e := OpenCache(dir, c.Node, k.Public().(ed25519.PublicKey), true); e == nil {
		bad.Close()
		t.Fatal("symlink cache admitted")
	}
}

type testCA struct {
	cert   *x509.Certificate
	key    ed25519.PrivateKey
	pool   *x509.CertPool
	serial int64
}

func ca(t *testing.T) *testCA {
	p, k := key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, p, k)
	must(t, e)
	cert, e := x509.ParseCertificate(der)
	must(t, e)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert, k, pool, 1}
}
func (a *testCA) node(t *testing.T) (tls.Certificate, string) {
	a.serial++
	p, k := key(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(a.serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, template, a.cert, p, a.key)
	must(t, e)
	leaf, e := x509.ParseCertificate(der)
	must(t, e)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}, peer.Identity(leaf)
}
func serve(t *testing.T, h http.Handler, cert tls.Certificate, id string, roots *x509.CertPool) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	cfg, e := ServerTLS(cert, roots, id)
	must(t, e)
	s.TLS = cfg
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func TestHTTPSRelayPreservesSignatureAndOfflineRecipientCache(t *testing.T) {
	ctx := context.Background()
	authority := ca(t)
	origin, originID := authority.node(t)
	relay, relayID := authority.node(t)
	recipient, recipientID := authority.node(t)
	stranger, strangerID := authority.node(t)
	cfg, k := configFixture(t)
	cfg.Node = recipientID
	cfg.Nodes = append(cfg.Nodes, policy.Node{ID: recipientID, Class: "trusted"})
	raw, e := Sign(cfg, k)
	must(t, e)
	newCache := func(label string) *Cache {
		c, e := OpenCache(filepath.Join(teststore.Root(t), label), recipientID, k.Public().(ed25519.PublicKey), true)
		must(t, e)
		t.Cleanup(func() { c.Close() })
		return c
	}
	originCache, relayCache, localCache := newCache("origin"), newCache("relay"), newCache("local")
	must(t, originCache.Accept(ctx, raw, time.Now()))
	h, e := Handler(map[string]*Cache{recipientID: originCache}, map[string][]string{relayID: {recipientID}})
	must(t, e)
	originServer := serve(t, h, origin, originID, authority.pool)
	pull, e := NewFetcher(originServer.URL, originID, relayID, relay, authority.pool, time.Second)
	must(t, e)
	defer pull.Close()
	received, e := pull.FetchFor(ctx, recipientID)
	must(t, e)
	must(t, relayCache.Accept(ctx, received, time.Now()))
	originServer.Close()
	h, e = Handler(map[string]*Cache{recipientID: relayCache}, map[string][]string{recipientID: {recipientID}})
	must(t, e)
	relayServer := serve(t, h, relay, relayID, authority.pool)
	download, e := NewFetcher(relayServer.URL, relayID, recipientID, recipient, authority.pool, time.Second)
	must(t, e)
	defer download.Close()
	received, e = download.Fetch(ctx)
	must(t, e)
	if !bytes.Equal(received, raw) {
		t.Fatal("relay rewrote owner signature")
	}
	must(t, localCache.Accept(ctx, received, time.Now()))
	denied, e := NewFetcher(relayServer.URL, relayID, strangerID, stranger, authority.pool, time.Second)
	must(t, e)
	defer denied.Close()
	if _, e = denied.FetchFor(ctx, recipientID); e == nil {
		t.Fatal("unlisted relay client fetched config")
	}
	wrong, e := NewFetcher(relayServer.URL, originID, recipientID, recipient, authority.pool, time.Second)
	must(t, e)
	defer wrong.Close()
	if _, e = wrong.Fetch(ctx); e == nil {
		t.Fatal("wrong pinned server admitted")
	}
	relayServer.Close()
	_, e = localCache.Current(ctx, time.Now())
	must(t, e)
}
