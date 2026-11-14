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
	"strings"
	"sync"
	"sync/atomic"
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

// The source and receiver share the fixture disk. Allow durable receiver
// writes within the same bounded request window as the source client.
var sourceFixtureLimits = peer.Limits{Concurrency: 1, Timeout: 30 * time.Second, Attempts: 1}

type fixture struct {
	server                          *httptest.Server
	base, tree, replicaPath         string
	b                               Bootstrap
	a                               *Agent
	owner                           filekit.Owner
	grant                           ingress.Authority
	authority                       []byte
	writer                          ed25519.PrivateKey
	ownerSigner                     ed25519.PrivateKey
	destination, replicaCertificate tls.Certificate
	roots                           *x509.CertPool
	intercept                       func(http.ResponseWriter, *http.Request) bool
	registry                        *ingress.Registry
	registryMu                      sync.RWMutex
	replica                         *generation.Replica
}

func newFixture(t *testing.T) *fixture {
	return newFixtureLifetime(t, 1800)
}

func TestSourceRunOffersRelayBeforeUploading(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	original := f.intent(t, 1, "")
	i, _, err := ingress.VerifyIntent(original, f.authority, f.b.Local.Owner, time.Now())
	must(t, err)
	grant := f.grant
	grant.Ingress = storage.Hash([]byte("downstream recipient"))
	authority, err := ingress.SignAuthority(grant, f.ownerSigner)
	must(t, err)
	var offered, uploadAfterOffer atomic.Int64
	f.registryMu.Lock()
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/relay-intent") {
			var offer struct {
				Recipient         string
				Authority, Intent json.RawMessage
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 3*ingress.MaxDocument)).Decode(&offer); err != nil {
				http.Error(w, "invalid offer", http.StatusBadRequest)
				return true
			}
			target, _, err := ingress.VerifyIntent(offer.Intent, offer.Authority, f.b.Local.Owner, time.Now())
			if err != nil || !bytes.Equal(offer.Authority, authority) || offer.Recipient != grant.Ingress || target.Operation != i.Operation {
				http.Error(w, "invalid offer", http.StatusBadRequest)
				return true
			}
			offered.Add(1)
			w.WriteHeader(http.StatusAccepted)
			return true
		}
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") {
			uploadAfterOffer.Store(offered.Load())
			http.Error(w, "interrupt the test upload", http.StatusServiceUnavailable)
			return true
		}
		return false
	}
	f.registryMu.Unlock()
	must(t, f.a.Prepare(ctx, original))
	if err = f.a.RunWithRelay(ctx, authority); err == nil || offered.Load() != 1 || uploadAfterOffer.Load() != 1 {
		t.Fatalf("source did not offer admission before uploading: %v", err)
	}
	status, err := f.a.Status(ctx)
	must(t, err)
	if status.Phase != "ACTIVE" || status.Operation != i.Operation {
		t.Fatalf("interrupted source lost the original active capture: %+v", status)
	}

	path := filepath.Join(f.base, "signed-recipient.json")
	must(t, os.WriteFile(path, authority, 0600))
	schedule := Schedule{Format: ScheduleFormat, Revision: 1, Enabled: true, IntervalSeconds: 60, RetrySeconds: 1, AttemptSeconds: 60, StartUnix: time.Now().Unix(), RelayAuthorityFile: path, RelayAuthoritySHA256: storage.Hash(authority)}
	must(t, f.a.ConfigureSchedule(ctx, schedule))
	changed := grant
	changed.Revision++
	modified, err := ingress.SignAuthority(changed, f.ownerSigner)
	must(t, err)
	must(t, os.WriteFile(path, modified, 0600))
	if err = f.a.attemptSchedule(ctx, schedule); !errors.Is(err, ingress.ErrDenied) || offered.Load() != 1 {
		t.Fatalf("scheduled capture used a replacement authority: %v", err)
	}
	must(t, os.WriteFile(path, authority, 0600))
	if err = f.a.attemptSchedule(ctx, schedule); err == nil || offered.Load() != 2 || uploadAfterOffer.Load() != 2 {
		t.Fatalf("scheduled retry did not offer the same intent before uploading: %v", err)
	}
	scheduled, err := f.a.ScheduleStatus(ctx)
	must(t, err)
	if scheduled.Config != schedule || scheduled.Operation != i.Operation || scheduled.Attempts != 1 {
		t.Fatalf("schedule did not retain its active intent and exact revision: %+v", scheduled)
	}
}
func newFixtureLifetime(t *testing.T, seconds int64) *fixture {
	t.Helper()
	return newFixtureWithPeer(t, seconds, nil)
}

func newFixtureWithPeer(t *testing.T, seconds int64, extra *tls.Certificate) *fixture {
	return newFixtureWithKeys(t, seconds, extra, nil)
}

type fixtureEpoch struct {
	owner  filekit.Owner
	trust  generation.Trust
	writer ed25519.PrivateKey
}

// fixtureOptions overrides fixture defaults. Zero values select the original
// bounded defaults, so newFixtureWithKeys keeps its existing behaviour.
type fixtureOptions struct {
	Directory           string
	MaxSourceBytes      int64
	MaxBytes            int64
	MaxObjects          int
	Limits              diskbudget.Limits
	CertificateLifetime time.Duration
	InitialSource       func(*testing.T, string)
}

func newFixtureWithKeys(t *testing.T, seconds int64, extra *tls.Certificate, epoch *fixtureEpoch) *fixture {
	t.Helper()
	return newFixtureWithOptions(t, seconds, extra, epoch, fixtureOptions{})
}

func newFixtureWithOptions(t *testing.T, seconds int64, extra *tls.Certificate, epoch *fixtureEpoch, opts fixtureOptions) *fixture {
	t.Helper()
	maxSourceBytes := opts.MaxSourceBytes
	if maxSourceBytes == 0 {
		maxSourceBytes = 32 << 20
	}
	maxBytes := opts.MaxBytes
	if maxBytes == 0 {
		maxBytes = 32 << 20
	}
	maxObjects := opts.MaxObjects
	if maxObjects == 0 {
		maxObjects = 128
	}
	limits := opts.Limits
	if limits.Capacity == 0 {
		limits.Capacity = 128 << 20
	}
	if limits.Reserve == 0 {
		limits.Reserve = 8 << 20
	}
	if limits.Spool == 0 {
		limits.Spool = 64 << 20
	}
	if limits.Telemetry == 0 {
		limits.Telemetry = 1 << 20
	}
	certificateLifetime := opts.CertificateLifetime
	if certificateLifetime == 0 {
		certificateLifetime = time.Hour
	}
	ctx := context.Background()
	base := opts.Directory
	if base == "" {
		base = teststore.Root(t)
	} else {
		// Scale fixtures survive a failed assertion. The caller owns this new
		// direct child of the admitted volume; existing directories are refused.
		admitted := os.Getenv("OUTPOST_TEST_ROOT")
		resolved, err := filepath.EvalSymlinks(admitted)
		if err != nil || !filepath.IsAbs(admitted) || resolved != admitted || filepath.Dir(base) != admitted {
			t.Fatal("retained fixture must be a new direct child of the admitted volume")
		}
		must(t, os.Mkdir(base, 0700))
	}
	f := &fixture{base: base}
	write := func(name string, raw []byte) string {
		p := filepath.Join(f.base, name)
		must(t, os.WriteFile(p, raw, 0600))
		return p
	}
	marshal := func(v any) []byte { b, e := json.Marshal(v); must(t, e); return b }
	pub, caKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(certificateLifetime), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, caKey)
	must(t, e)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	caFile := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	newCert := func(serial int64) (tls.Certificate, []byte, []byte) {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(certificateLifetime), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
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
	f.destination = dst
	f.replicaCertificate, _, _ = newCert(4)
	if extra != nil {
		*extra, _, _ = newCert(5)
	}
	f.roots = roots
	id := func(c tls.Certificate) string {
		leaf, e := x509.ParseCertificate(c.Certificate[0])
		must(t, e)
		return peer.Identity(leaf)
	}
	ownerPub, ownerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.ownerSigner = ownerKey
	if epoch == nil {
		writer, key, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		maint, _, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		owner, err := filekit.NewOwner()
		must(t, err)
		epoch = &fixtureEpoch{owner: owner, writer: key, trust: generation.Trust{
			Domain: owner.Domain, Repository: storage.Hash([]byte("repo")), Epoch: 1, Writer: writer, Maintenance: maint,
		}}
	}
	f.owner, f.writer = epoch.owner, epoch.writer
	trust, key := epoch.trust, f.writer
	f.grant = ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: id(src), Ingress: id(dst), Revision: 1, NotBefore: now.Unix() - 10, ExpiresUnix: now.Unix() + seconds, Trust: trust, MaxBytes: maxBytes, MaxObjects: maxObjects}
	f.authority, e = ingress.SignAuthority(f.grant, ownerKey)
	must(t, e)
	f.replicaPath = filepath.Join(f.base, "replica")
	must(t, os.Mkdir(f.replicaPath, 0700))
	r, e := generation.Open(f.replicaPath, trust, true)
	must(t, e)
	f.replica = r
	t.Cleanup(func() { r.Close() })
	g, e := ingress.OpenRegistry(ctx, ingress.RegistryOptions{Directory: filepath.Join(f.base, "registry"), Authority: f.authority, Owner: ownerPub, Replica: r, Certificate: dst, Roots: roots, Limits: sourceFixtureLimits, Initialize: true})
	must(t, e)
	f.registry = g
	t.Cleanup(func() { f.registry.Close() })
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.registryMu.RLock()
		defer f.registryMu.RUnlock()
		if f.intercept != nil && f.intercept(w, r) {
			return
		}
		f.registry.ServeHTTP(w, r)
	}))
	s.TLS, e = peer.AuthenticatedServerTLS(dst, roots, id(dst))
	must(t, e)
	s.StartTLS()
	f.server = s
	t.Cleanup(s.Close)
	vol := filepath.Join(f.base, "volume")
	must(t, os.Mkdir(vol, 0700))
	obs, e := volume.Probe(ctx, vol)
	must(t, e)
	binding, e := volume.Enroll(ctx, vol, obs, id(src), 1)
	must(t, e)
	f.tree = filepath.Join(f.base, "source")
	must(t, os.Mkdir(f.tree, 0700))
	if opts.InitialSource != nil {
		opts.InitialSource(t, f.tree)
	} else {
		must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), bytes.Repeat([]byte("source"), 65536), 0640))
	}
	origin := storage.Hash([]byte("origin"))
	tree, e := capture.ProbeTree(ctx, f.tree, origin)
	must(t, e)
	f.b = Bootstrap{Format: Format, Local: worker.Bootstrap{Format: worker.BootstrapFormat, Volume: binding, Directory: filepath.Join(vol, "agent"), Node: id(src), Owner: ownerPub, CertificateFile: write("source.pem", cp), PrivateKeyFile: write("source-key.pem", kp), CAFile: caFile}, Profile: capture.Profile{ID: f.grant.Profile, Origin: origin, Consistency: "best-effort", Selection: source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: f.owner.Domain}}, Domains: map[string]bool{f.owner.Domain: true}, EntryLimit: 128}, MaxSourceBytes: maxSourceBytes, MinimumCopies: 1, CopyTargets: []string{id(dst)}}, Tree: tree, DataKeyFile: write("data-key.json", marshal(f.owner)), WriterKeyFile: write("writer-key.json", marshal(map[string]any{"privateKey": key})), AuthorityFile: write("authority.json", f.authority), Endpoint: s.URL, Limits: limits}
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
	return f.intentUntil(t, seq, parent, time.Now().Add(10*time.Minute).Unix())
}

func (f *fixture) intentUntil(t *testing.T, seq uint64, parent string, expiry int64) []byte {
	t.Helper()
	a := f.grant
	now := time.Now()
	i := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte(parent + "operation")), Authority: storage.Hash(f.authority), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: a.Trust.Epoch, Sequence: seq, Parent: parent, Policy: 1, SnapshotUnix: now.Unix(), NotBefore: now.Unix() - 1, ExpiresUnix: expiry, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	raw, e := ingress.SignIntent(i, f.authority, f.b.Local.Owner, f.writer, now)
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
