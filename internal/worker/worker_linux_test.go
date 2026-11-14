package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
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

type fixture struct {
	base                string
	ca                  *testCA
	owner               ed25519.PrivateKey
	dataOwner           filekit.Owner
	writer              ed25519.PrivateKey
	maintenance         ed25519.PrivateKey
	domain              control.Domain
	nodes               []*Worker
	cfg                 control.Config
	generation, version string
	content             []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{base: teststore.Root(t), ca: ca(t)}
	_, f.owner = key(t)
	writer, wk := key(t)
	f.writer = wk
	maint, mk := key(t)
	f.maintenance = mk
	planner, _ := key(t)
	var e error
	f.dataOwner, e = filekit.NewOwner()
	must(t, e)
	trust := generation.Trust{Domain: f.dataOwner.Domain, Repository: storage.Hash([]byte("worker repository")), Epoch: 1, Writer: writer, Maintenance: maint}
	f.domain = control.Domain{Trust: trust, Planner: planner, Placement: policy.Placement{Domain: trust.Domain, AllowedClasses: []string{"trusted", "untrusted"}}}
	f.cfg = control.Config{Format: control.Format, Revision: 1, NotBefore: time.Now().Add(-time.Minute).Unix(), ExpiresUnix: time.Now().Add(time.Hour).Unix(), Limits: control.Limits{Parallel: 2, AttemptMillis: 5000, PollSeconds: 1, CapacityBytes: 1 << 30, ReserveBytes: 1 << 28, SpoolBytes: 1 << 26, TelemetryBytes: 1 << 20}}
	for _, name := range []string{"a", "b", "c"} {
		cert, id := f.ca.node(t)
		w, e := Open(Options{Directory: filepath.Join(f.base, name), Node: id, Owner: f.owner.Public().(ed25519.PublicKey), Certificate: cert, Roots: f.ca.pool, Initialize: true})
		must(t, e)
		f.nodes = append(f.nodes, w)
		t.Cleanup(func() {
			if t.Failed() {
				s, e := w.Status(context.Background())
				t.Logf("worker %s status %+v error %v", name, s, e)
			}
			w.Close()
		})
		class := "trusted"
		if name == "c" {
			class = "untrusted"
		}
		f.cfg.Nodes = append(f.cfg.Nodes, policy.Node{ID: id, Class: class})
		f.domain.Placement.Holders = append(f.domain.Placement.Holders, id)
	}
	f.domain.Placement.Edges = []policy.Edge{{From: f.nodes[0].node, To: f.nodes[1].node, Mode: "push"}, {From: f.nodes[1].node, To: f.nodes[2].node, Mode: "pull"}}
	store, e := filekit.OpenStore(filepath.Join(f.base, "source-kit"), f.dataOwner, true)
	must(t, e)
	defer store.Close()
	f.content = make([]byte, 256<<10)
	_, e = rand.Read(f.content)
	must(t, e)
	input := filepath.Join(f.base, "input")
	must(t, os.WriteFile(input, f.content, 0640))
	stats, e := store.Backup(context.Background(), input, filekit.BackupOptions{Names: []string{"dataset/данные.bin"}})
	must(t, e)
	f.version = stats.Version
	path := filepath.Join(DomainDirectory(f.nodes[0].dir, trust), "replica")
	must(t, os.MkdirAll(path, 0700))
	replica, e := generation.Open(path, trust, true)
	must(t, e)
	defer replica.Close()
	f.generation, e = generation.Seal(context.Background(), store, []string{f.version}, replica, generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, f.writer)
	must(t, e)
	return f
}
func (f *fixture) endpoint(t *testing.T, wrapper func(http.Handler) http.Handler) *httptest.Server {
	w := f.nodes[1]
	server, e := w.HTTPServer()
	must(t, e)
	h := server.Handler
	if wrapper != nil {
		h = wrapper(h)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = server.TLSConfig
	s.StartTLS()
	t.Cleanup(s.Close)
	f.cfg.Nodes[1].Endpoint = s.URL
	return s
}
func (f *fixture) config(t *testing.T, index int, jobs []control.Job) control.Config {
	c := f.cfg
	c.Node = f.nodes[index].node
	c.Domains = []control.Domain{f.domain}
	c.Jobs = jobs
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, f.nodes[index].Accept(context.Background(), raw))
	return c
}
func start(t *testing.T, w *Worker) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case e := <-done:
			must(t, e)
		case <-time.After(8 * time.Second):
			t.Fatal("worker failed to join")
		}
	}
	t.Cleanup(stop)
	return stop
}
func wait(t *testing.T, fn func() bool) {
	t.Helper()
	waitFor(t, 12*time.Second, fn)
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("bounded worker condition not reached")
}
func complete(w *Worker, op string) bool {
	s, e := w.Status(context.Background())
	return e == nil && s.Jobs[op].Phase == "COMPLETE"
}
func (f *fixture) jobs() (control.Job, control.Job) {
	return control.Job{PeerRevision: 1, Operation: storage.Hash([]byte("a-to-b")), Executor: f.nodes[0].node, Kind: "push", Domain: f.domain.Trust.Domain, Generation: f.generation, Peer: f.nodes[1].node}, control.Job{PeerRevision: 1, Operation: storage.Hash([]byte("b-to-c")), Executor: f.nodes[2].node, Kind: "pull", Domain: f.domain.Trust.Domain, Generation: f.generation, Peer: f.nodes[1].node}
}
func TestWorkerTransfersThroughOutboundOnlyReplicaAndOfflineCache(t *testing.T) {
	f := newFixture(t)
	// This integration test checks the route and restart, not a disk SLA.
	f.cfg.Limits.AttemptMillis = 60000
	server := f.endpoint(t, nil)
	push, pull := f.jobs()
	f.config(t, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push, pull})
	f.config(t, 2, []control.Job{pull})
	stopB := start(t, f.nodes[1])
	stopA := start(t, f.nodes[0])
	waitFor(t, 90*time.Second, func() bool { return complete(f.nodes[0], push.Operation) })
	stopA()
	// B serves from its durable copy after the sender has left. No A->C endpoint exists.
	stopC := start(t, f.nodes[2])
	waitFor(t, 90*time.Second, func() bool { return complete(f.nodes[2], pull.Operation) })
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[0].cert}}}}
	defer client.CloseIdleConnections()
	request, e := http.NewRequest(http.MethodGet, server.URL+"/v1/"+f.domain.Trust.Domain+"/generations/"+f.generation+"/catalog", nil)
	must(t, e)
	request.Header.Set("Outpost-Operation", storage.Hash([]byte("unassigned")))
	request.Header.Set("Outpost-Mode", "push")
	response, e := client.Do(request)
	must(t, e)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("edge alone authorized an unassigned operation", response.StatusCode)
	}
	request.Header.Set("Outpost-Operation", push.Operation)
	request.Header.Set("Outpost-Mode", "pull")
	response, e = client.Do(request)
	must(t, e)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("push readback granted an implicit pull operation")
	}
	stopC()
	stopB()
	server.Close()
	// Reopen the worker on its signed cache, with no control plane or other node.
	reopened, e := Open(Options{Directory: f.nodes[2].dir, Node: f.nodes[2].node, Owner: f.owner.Public().(ed25519.PublicKey), Certificate: f.nodes[2].cert, Roots: f.ca.pool})
	must(t, e)
	defer reopened.Close()
	stop := start(t, reopened)
	wait(t, func() bool { reopened.mu.Lock(); defer reopened.mu.Unlock(); return reopened.active != nil })
	if !complete(reopened, pull.Operation) {
		t.Fatal("completion receipt lost on restart")
	}
	stop()
	replica, e := generation.Open(filepath.Join(DomainDirectory(reopened.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	kit := filepath.Join(f.base, "independent-kit")
	must(t, replica.ExportKit(context.Background(), f.generation, f.version, kit))
	reader, e := filekit.OpenStore(kit, f.dataOwner, false)
	must(t, e)
	defer reader.Close()
	out := filepath.Join(f.base, "restored")
	_, e = reader.Restore(context.Background(), f.version, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "dataset/данные.bin"))
	must(t, e)
	if !bytes.Equal(got, f.content) {
		t.Fatal("standalone restored bytes differ")
	}
}
func TestNewPolicyCancelsInFlightTransferBeforeStartingNextRevision(t *testing.T) {
	f := newFixture(t)
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, generation.MaxCatalog))
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-r.Context().Done():
				case <-time.After(6 * time.Second):
					return
				}
				select {
				case canceled <- struct{}{}:
				default:
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	push, _ := f.jobs()
	cfg := f.config(t, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push})
	start(t, f.nodes[1])
	start(t, f.nodes[0])
	select {
	case <-started:
	case <-time.After(6 * time.Second):
		t.Fatal("transfer did not start")
	}
	cfg.Revision++
	cfg.Jobs = nil
	cfg.Domains[0].Placement.Edges = nil
	raw, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, f.nodes[0].Accept(context.Background(), raw))
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("withdrawn transfer not canceled within poll interval")
	}
	wait(t, func() bool {
		s, e := f.nodes[0].Status(context.Background())
		return e == nil && s.Revision == 2 && s.Jobs[push.Operation].Phase == "WITHDRAWN"
	})
	replica, e := generation.Open(filepath.Join(DomainDirectory(f.nodes[0].dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	state, e := replica.Status(context.Background())
	must(t, e)
	if len(state.Pins) == 0 || state.LatestComplete != f.generation {
		t.Fatal("revocation discarded source protection")
	}
}
