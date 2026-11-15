package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

// This is a capture-library reference, not an extra CLI routing mode. Control
// methods are promoted unchanged from the real pair: no proof is synthesized.
type asymmetricSingleSink struct{ *parallelSink }

func (s *asymmetricSingleSink) ParallelWrites() int { return 1 }
func (s *asymmetricSingleSink) Read(ctx context.Context, ref filekit.Object) ([]byte, error) {
	return s.Client.Read(ctx, ref)
}
func (s *asymmetricSingleSink) Check(ctx context.Context, ref filekit.Object) error {
	return s.Client.Check(ctx, ref)
}
func (s *asymmetricSingleSink) Write(ctx context.Context, ref filekit.Object, body []byte) (bool, error) {
	if err := s.Client.Check(ctx, ref); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	created, err := s.Client.Write(ctx, ref, body)
	if err == nil && (!s.split || s.splitOwner(ref) == 1) {
		// Preserve the paired sink's actual full-copy or stable-partition
		// delivery. Only initial placement is fixed; the source sends no body
		// directly to B. Coverage itself never imports a missing assigned part.
		err = s.relayAcceptedStaged(ctx, s.companion, s.Client, ref)
	}
	return created, err
}

type asymmetricCapture struct {
	job   *capture.Job
	cache *filekit.Store
	close func()
}

// Construct the ordinary, non-routed capture components with the same signed
// inputs. Only the initial data sink differs. After completion Agent.Run can
// export the actual completed job through the normal coordinator path.
func openAsymmetricCapture(t *testing.T, ctx context.Context, a *Agent, single bool) asymmetricCapture {
	t.Helper()
	s, err := a.load()
	must(t, err)
	if s.Phase != "PREPARING" || a.b.Companion == nil || a.b.Standby || a.b.Reserve != nil || a.routed() {
		t.Fatal("reference requires a new ordinary paired capture")
	}
	i, err := a.stateIntent(s)
	must(t, err)
	prefix := path.Join("operations", i.Operation)
	limits := peer.Limits{Concurrency: 1, Timeout: 30 * time.Second, Attempts: 1}
	client, err := ingress.NewClient(a.b.Endpoint, a.intentAuthority(s), s.Intent, a.b.Local.Owner, a.cert, a.roots, limits)
	must(t, err)
	provider, err := a.openProvider(ctx, prefix, i, true)
	must(t, err)
	group, err := a.openParallelSink(i, prefix, a.companion.Ingress, a.b.Companion.Endpoint, a.companionAuthority, client, limits, true, false, nil)
	must(t, err)
	var sink capture.Sink = group
	if single {
		sink = &asymmetricSingleSink{group}
	}
	cache, err := filekit.OpenStreamingStoreAt(a.root, "cache", a.owner, true, sink)
	must(t, err)
	cache.Admit = a.admission("cache")
	inputs, err := statefile.OpenAt(a.root, prefix+"/input", maxState, true)
	must(t, err)
	inputs.Admit = a.admission(prefix + "/input")
	expected, err := json.Marshal(s.Previous)
	must(t, err)
	must(t, inputs.WithLock(ctx, func() error {
		raw, err := inputs.Read("previous.json")
		if errors.Is(err, os.ErrNotExist) {
			return inputs.Write("previous.json", expected)
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, expected) {
			return ErrInvalid
		}
		return nil
	}))
	must(t, inputs.Close())
	profile := a.b.Profile
	profile.View = i.Operation
	job, err := capture.Open(ctx, capture.Options{
		Parent: a.root, Directory: prefix + "/job", Initialize: true,
		Profile: profile, Authority: a.intentAuthority(s), Intent: s.Intent,
		Owner: a.b.Local.Owner, Data: a.owner, Writer: a.writer, Provider: provider,
		Sink: sink, Cache: cache, Previous: s.Previous, Copies: a.copies,
		Guard: a.guard, Admission: func(name string) statefile.Admission { return a.admission(prefix + "/job/" + name) },
	})
	must(t, err)
	job.Fault = a.Fault
	must(t, a.fenceCapture(ctx, &s))
	closed := false
	close := func() {
		if closed {
			return
		}
		closed = true
		job.Close()
		must(t, cache.Close())
		must(t, provider.Close())
		group.Close()
	}
	t.Cleanup(close)
	return asymmetricCapture{job: job, cache: cache, close: close}
}

// Application-body shaping is declared separately from TCP/TLS wire rates.
// A path waits for the latest reservation across its gates, not their sum.
type asymmetricRate struct {
	mu    sync.Mutex
	bytes int64
	next  time.Time
}

func (g *asymmetricRate) reserve(now time.Time, n int) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.next.Before(now) {
		g.next = now
	}
	g.next = g.next.Add(time.Duration(int64(n) * int64(time.Second) / g.bytes))
	return g.next
}

func asymmetricWait(ctx context.Context, n int, gates ...*asymmetricRate) error {
	now, until := time.Now(), time.Now()
	for _, gate := range gates {
		if gate != nil {
			deadline := gate.reserve(now, n)
			if deadline.After(until) {
				until = deadline
			}
		}
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type asymmetricBody struct {
	io.ReadCloser
	ctx     context.Context
	gates   []*asymmetricRate
	observe func(int)
}

func (r *asymmetricBody) Read(b []byte) (int, error) {
	n, err := r.ReadCloser.Read(b)
	if n > 0 {
		r.observe(n)
		if wait := asymmetricWait(r.ctx, n, r.gates...); wait != nil {
			return n, wait
		}
	}
	return n, err
}

type asymmetricResponse struct {
	http.ResponseWriter
	ctx     context.Context
	gates   []*asymmetricRate
	observe func(int)
	status  int
}

func (w *asymmetricResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *asymmetricResponse) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *asymmetricResponse) Write(b []byte) (int, error) {
	if err := asymmetricWait(w.ctx, len(b), w.gates...); err != nil {
		return 0, err
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.observe(n)
	return n, err
}

type asymmetricEvent struct {
	Node, Object string
	Bytes        int64
	Start, End   time.Time
	Status       int
}

type asymmetricTraffic struct {
	mu                  sync.Mutex
	source              string
	input, output       map[string]*asymmetricRate
	sourceOut, sourceIn *asymmetricRate
	requests, responses map[string]int64
	puts                []asymmetricEvent
	peerBytes           int64
	forwardedBeforeSeal int64
	sealed              bool
}

func newAsymmetricTraffic(source, a, b, c string) *asymmetricTraffic {
	return &asymmetricTraffic{source: source,
		input:     map[string]*asymmetricRate{a: {bytes: 500_000_000 / 8}, b: {bytes: 500_000_000 / 8}, c: {bytes: 100_000_000 / 8}},
		output:    map[string]*asymmetricRate{a: {bytes: 500_000_000 / 8}, b: {bytes: 500_000_000 / 8}, c: {bytes: 100_000_000 / 8}},
		sourceOut: &asymmetricRate{bytes: 1_000_000_000 / 8}, sourceIn: &asymmetricRate{bytes: 1_000_000_000 / 8},
		requests: map[string]int64{}, responses: map[string]int64{}}
}

func (m *asymmetricTraffic) watch(node string, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
			actor = peer.Identity(r.TLS.PeerCertificates[0])
		}
		started := time.Now()
		var received int64
		incoming := []*asymmetricRate{m.input[node]}
		if actor == m.source {
			incoming = append(incoming, m.sourceOut)
		}
		if r.Body != nil {
			r.Body = &asymmetricBody{ReadCloser: r.Body, ctx: r.Context(), gates: incoming, observe: func(n int) {
				received += int64(n)
				m.mu.Lock()
				m.requests[actor+">"+node] += int64(n)
				m.mu.Unlock()
			}}
		}
		outgoing := []*asymmetricRate{m.output[node]}
		if actor == m.source {
			outgoing = append(outgoing, m.sourceIn)
		} else {
			outgoing = append(outgoing, m.input[actor])
		}
		out := &asymmetricResponse{ResponseWriter: w, ctx: r.Context(), gates: outgoing, observe: func(n int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.responses[node+">"+actor] += int64(n)
			if actor != m.source && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/staged/") {
				m.peerBytes += int64(n)
				if !m.sealed {
					m.forwardedBeforeSeal += int64(n)
				}
			}
		}}
		next.ServeHTTP(out, r)
		if actor == m.source && r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") {
			m.mu.Lock()
			m.puts = append(m.puts, asymmetricEvent{Node: node, Object: filepath.Base(r.URL.Path), Bytes: received, Start: started, End: time.Now(), Status: out.status})
			m.mu.Unlock()
		}
	}
}

type asymmetricSnapshot struct {
	Requests, Responses map[string]int64
	Puts                []asymmetricEvent
	PeerBytes, PreSeal  int64
}

func (m *asymmetricTraffic) snapshot() asymmetricSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := asymmetricSnapshot{Requests: map[string]int64{}, Responses: map[string]int64{}, Puts: append([]asymmetricEvent(nil), m.puts...), PeerBytes: m.peerBytes, PreSeal: m.forwardedBeforeSeal}
	for k, v := range m.requests {
		r.Requests[k] = v
	}
	for k, v := range m.responses {
		r.Responses[k] = v
	}
	return r
}

func (m *asymmetricTraffic) begin() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests, m.responses = map[string]int64{}, map[string]int64{}
	m.puts, m.peerBytes, m.forwardedBeforeSeal, m.sealed = nil, 0, 0, false
}

type asymmetricFixture struct {
	f                      *fixture
	traffic                *asymmetricTraffic
	workers                [3]*worker.Worker
	dirs, ids              [3]string
	stopA, stopB           func()
	proof, publication     atomic.Bool
	withheld               atomic.Int64
	split                  bool
	retained               map[string]asymmetricExpected
	removeVerifiedRestores bool
	beforeSourcePut        func(string, http.ResponseWriter, *http.Request) bool
}

func newAsymmetricFixture(t *testing.T, epoch *fixtureEpoch, payload []byte, split bool) *asymmetricFixture {
	t.Helper()
	return newAsymmetricFixtureOptions(t, epoch, split, 7200, fixtureOptions{
		MaxSourceBytes: int64(len(payload)), MaxBytes: 64 << 20, MaxObjects: 4096,
		InitialSource: func(t *testing.T, tree string) {
			must(t, os.WriteFile(filepath.Join(tree, "private.bin"), payload, 0640))
		},
	}, control.Limits{Parallel: 2, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20})
}

func newAsymmetricFixtureOptions(t *testing.T, epoch *fixtureEpoch, split bool, lifetime int64, options fixtureOptions, limits control.Limits) *asymmetricFixture {
	t.Helper()
	var follower tls.Certificate
	f := newFixtureWithOptions(t, lifetime, &follower, epoch, options)
	x := &asymmetricFixture{f: f, split: split, retained: map[string]asymmetricExpected{}}
	id := func(cert tls.Certificate) string {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		must(t, err)
		return peer.Identity(leaf)
	}
	x.ids = [3]string{f.grant.Ingress, id(f.replicaCertificate), id(follower)}
	x.traffic = newAsymmetricTraffic(f.grant.Source, x.ids[0], x.ids[1], x.ids[2])
	certs := [3]tls.Certificate{f.destination, f.replicaCertificate, follower}
	for n := range 3 {
		x.dirs[n] = filepath.Join(f.base, "asymmetric-holder-"+string(rune('a'+n)))
		w, err := worker.Open(worker.Options{Directory: x.dirs[n], Node: x.ids[n], Owner: f.b.Local.Owner, Certificate: certs[n], Roots: f.roots, Initialize: true})
		must(t, err)
		x.workers[n] = w
		t.Cleanup(func() { must(t, w.Close()) })
		if n < 2 {
			w.Fault = func(point string) error {
				if point == "capture-coverage-before-publication" && !x.publication.Load() {
					return errors.New("test publication gate")
				}
				return nil
			}
		}
	}
	filter := func(node int, w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") && x.beforeSourcePut != nil &&
			r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && peer.Identity(r.TLS.PeerCertificates[0]) == f.grant.Source && x.beforeSourcePut(x.ids[node], w, r) {
			return
		}
		// Withhold only the required proof, not source object acceptance. A
		// named hit plus exact capture state are required by the negative test.
		if !x.proof.Load() && ((split && node == 1 && (strings.HasSuffix(r.URL.Path, "/coverage") || strings.HasSuffix(r.URL.Path, "/partition"))) ||
			(!split && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/observations/"))) {
			x.withheld.Add(1)
			http.Error(w, "test required proof unavailable", http.StatusPreconditionFailed)
			return
		}
		x.workers[node].ServeHTTP(w, r)
	}
	aHandler := x.traffic.watch(x.ids[0], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { filter(0, w, r) }))
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool { aHandler(w, r); return true }
	bServer := httptest.NewUnstartedServer(x.traffic.watch(x.ids[1], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { filter(1, w, r) })))
	bTLS, err := peer.AuthenticatedServerTLS(f.replicaCertificate, f.roots, x.ids[1])
	must(t, err)
	bServer.TLS = bTLS
	bServer.StartTLS()
	t.Cleanup(bServer.Close)
	companionGrant := f.grant
	companionGrant.Ingress = x.ids[1]
	companion, err := ingress.SignAuthority(companionGrant, f.ownerSigner)
	must(t, err)
	proof, err := observation.SignGrant(observation.Grant{Format: observation.GrantFormat, Trust: f.grant.Trust, Reader: f.grant.Source, Collector: x.ids[0], Targets: []string{x.ids[1]}, Epoch: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix, MaxAgeSeconds: 3600}, f.ownerSigner)
	must(t, err)
	planner, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	domain := control.Domain{CaptureStagingPeers: []string{x.ids[1]}, Trust: f.grant.Trust, Planner: planner, Placement: policy.Placement{
		Domain: f.grant.Trust.Domain, AllowedClasses: []string{"trusted"}, Holders: x.ids[:], Transit: []string{f.grant.Source},
		Edges: []policy.Edge{{From: f.grant.Source, To: x.ids[0], Mode: "push"}, {From: f.grant.Source, To: x.ids[1], Mode: "push"},
			{From: x.ids[0], To: x.ids[1], Mode: "pull"}, {From: x.ids[1], To: x.ids[0], Mode: "pull"}, {From: x.ids[0], To: x.ids[2], Mode: "pull"}},
	}}
	follow := control.Replication{Domain: f.grant.Trust.Domain, From: x.ids[0], To: x.ids[2], Mode: "pull", Epoch: 1, PeerRevision: 1}
	cfg := control.Config{Format: control.SettlementConfigFormat, Node: x.ids[0], Revision: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix,
		Limits:  limits,
		Nodes:   []policy.Node{{ID: f.grant.Source, Class: "trusted"}, {ID: x.ids[0], Class: "trusted", Endpoint: f.server.URL}, {ID: x.ids[1], Class: "trusted", Endpoint: bServer.URL}, {ID: x.ids[2], Class: "trusted"}},
		Domains: []control.Domain{domain}, Observations: []json.RawMessage{proof}, Ingress: []json.RawMessage{f.authority}, Replication: []control.Replication{follow},
	}
	for n := range 3 {
		if n == 1 {
			cfg.Node, cfg.Ingress, cfg.Replication = x.ids[1], []json.RawMessage{companion}, nil
			cfg.Domains[0].CaptureStagingPeers = []string{x.ids[0]}
		} else if n == 2 {
			cfg.Node, cfg.Ingress, cfg.Observations = x.ids[2], nil, nil
			cfg.Domains[0].CaptureStagingPeers = nil
			cfg.Replication = []control.Replication{follow}
		}
		raw, err := control.Sign(cfg, f.ownerSigner)
		must(t, err)
		must(t, x.workers[n].Accept(t.Context(), raw))
	}
	x.publication.Store(!split)
	x.stopA = runCaptureWorker(t, t.Context(), x.workers[0])
	x.stopB = runCaptureWorker(t, t.Context(), x.workers[1])
	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "asymmetric-agent")
	f.b.Profile.MinimumCopies, f.b.Profile.CopyTargets = 2, []string{x.ids[0], x.ids[1]}
	if split {
		f.b.Profile.ReleasePolicy = capture.PairedSplitCoverage
	}
	f.b.ObservationFile = filepath.Join(f.base, "asymmetric-observation.json")
	f.b.Companion = &CompanionIngress{Endpoint: bServer.URL, AuthorityFile: filepath.Join(f.base, "asymmetric-companion.json")}
	must(t, os.WriteFile(f.b.ObservationFile, proof, 0600))
	must(t, os.WriteFile(f.b.Companion.AuthorityFile, companion, 0600))
	f.a, err = Open(t.Context(), f.b, true)
	must(t, err)
	return x
}

type asymmetricResult struct {
	Strategy, ReleasePolicy, Generation                              string
	InputSHA256                                                      string
	SourceBytes, InitialBytes, RetryBytes                            int64
	CiphertextReadbackBytes                                          int64
	RequiredProofRefused                                             bool
	LargeWriteOverlap                                                bool
	SourceReadBytesPerSecond, InitialBodyBytesPerSecond              float64
	SealedSeconds, ReleasedSeconds, CompleteSeconds, FollowerSeconds float64
	Milestones                                                       *Milestones
	Traffic                                                          asymmetricSnapshot
}

type asymmetricExpected struct {
	Bytes   int64
	SHA256  string
	Mode    os.FileMode
	MtimeNS int64
	Verify  func(*testing.T, string) string
}

func asymmetricBytes(b []byte) asymmetricExpected {
	return asymmetricExpected{Bytes: int64(len(b)), SHA256: storage.Hash(b)}
}

func (e asymmetricExpected) verify(t *testing.T, name string) string {
	t.Helper()
	info, err := os.Stat(name)
	must(t, err)
	if info.Size() != e.Bytes || info.Mode().Perm() != e.Mode || info.ModTime().UnixNano() != e.MtimeNS {
		t.Fatal("retained attributes differ", info.Size(), info.Mode().Perm(), info.ModTime().UnixNano())
	}
	var hash string
	if e.Verify != nil {
		hash = e.Verify(t, name)
	} else {
		file, err := os.Open(name)
		must(t, err)
		digest := sha256.New()
		n, err := io.Copy(digest, file)
		must(t, err)
		must(t, file.Close())
		if n != e.Bytes {
			t.Fatal("recovery read length differs", n)
		}
		hash = hex.EncodeToString(digest.Sum(nil))
	}
	if !storage.ID(hash) || (e.SHA256 != "" && hash != e.SHA256) {
		t.Fatal("retained bytes differ", hash, e.SHA256)
	}
	return hash
}

func (x *asymmetricFixture) capture(t *testing.T, ctx context.Context, single bool, expected asymmetricExpected) asymmetricResult {
	t.Helper()
	f := x.f
	info, err := os.Stat(filepath.Join(f.tree, "private.bin"))
	must(t, err)
	expected.Mode, expected.MtimeNS = info.Mode().Perm(), info.ModTime().UnixNano()
	x.traffic.begin()
	x.proof.Store(false)
	x.publication.Store(!x.split)
	before := x.withheld.Load()
	started := time.Now()
	must(t, f.a.Next(ctx))
	pause := errors.New("test durable boundary")
	f.a.Fault = func(point string) error {
		if point == "source-catalog-durable" {
			return pause
		}
		return nil
	}
	var c asymmetricCapture
	must(t, f.a.lease.WithLock(ctx, func() error { c = openAsymmetricCapture(t, ctx, f.a, single); return nil }))
	run := func() error { return f.a.lease.WithLock(ctx, func() error { return c.job.Run(ctx) }) }
	if err := run(); !errors.Is(err, pause) {
		t.Fatal("capture did not reach durable seal", err)
	}
	r := asymmetricResult{Strategy: "paired-adaptive", ReleasePolicy: f.b.Profile.ReleasePolicy, SealedSeconds: time.Since(started).Seconds(), SourceBytes: c.cache.Stats.SourceBytes}
	r.InputSHA256 = expected.SHA256
	r.CiphertextReadbackBytes = c.cache.Stats.VerifiedReadBytes
	if single {
		r.Strategy = "single-initial-recipient-reference"
	}
	if r.SourceBytes != expected.Bytes {
		t.Fatal("source read counter differs", r.SourceBytes, expected.Bytes)
	}
	x.traffic.mu.Lock()
	x.traffic.sealed = true
	x.traffic.mu.Unlock()
	c.job.Fault = nil
	err = run()
	if x.split {
		if !errors.Is(err, ingress.ErrIncomplete) {
			t.Fatal("missing partition proof was not refused", err)
		}
	} else if !errors.Is(err, observation.ErrPending) {
		t.Fatal("missing full-copy observation was not refused", err)
	}
	s, err := f.a.Status(ctx)
	must(t, err)
	if x.withheld.Load() == before || s.Job == nil || s.Job.StagedRelease != "" || s.Milestones == nil || s.Milestones.ProviderReleaseUnix != 0 {
		t.Fatal("required proof did not block provider release", s)
	}
	r.RequiredProofRefused = true
	x.proof.Store(true)
	if x.split {
		c.job.Fault = func(point string) error {
			if point == "source-coverage-release-durable" {
				return pause
			}
			return nil
		}
		if err = run(); !errors.Is(err, pause) {
			t.Fatal("coverage did not release before publication", err)
		}
		s, err = f.a.Status(ctx)
		must(t, err)
		if s.Job.Phase != "SEALED" || s.Job.StagedRelease != "RELEASED" || s.Job.Receipt != nil || s.Milestones.ProviderReleaseUnix == 0 || s.Milestones.FirstReplicaVerifiedUnix != 0 {
			t.Fatal("partition release was confused with a full copy", s)
		}
		r.ReleasedSeconds = time.Since(started).Seconds()
		// Removing the path after the durable release keeps the same inode for
		// the next incremental generation, while all publication runs without it.
		must(t, os.Rename(filepath.Join(f.tree, "private.bin"), filepath.Join(f.base, "offline.bin")))
		x.publication.Store(true)
	}
	c.job.Fault = func(point string) error {
		if point == "source-provider-released" {
			r.ReleasedSeconds = time.Since(started).Seconds()
		}
		return nil
	}
	for {
		err = run()
		if err == nil {
			break
		}
		if !errors.Is(err, capture.ErrCopies) && !errors.Is(err, observation.ErrPending) {
			t.Fatal("capture completion", err)
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if r.ReleasedSeconds == 0 {
		t.Fatal("actual provider release boundary was not observed")
	}
	checkpoint, _, err := c.job.Export(ctx)
	must(t, err)
	verified, err := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, err)
	if len(verified.Copies) != 2 {
		t.Fatal("complete-copy threshold changed")
	}
	r.Generation = verified.Generation
	x.retained[r.Generation] = expected
	c.close()
	// Use the normal coordinator to advance lineage from the actual completed
	// job, without synthesizing or directly editing any state/checkpoint.
	must(t, f.a.Run(ctx))
	s, err = f.a.Status(ctx)
	must(t, err)
	checkReplicaMilestones(t, s.Milestones, verified.Copies)
	r.Milestones = s.Milestones
	r.CompleteSeconds = time.Since(started).Seconds()
	must(t, f.a.Close())
	f.a = nil
	if !x.split {
		must(t, os.Rename(filepath.Join(f.tree, "private.bin"), filepath.Join(f.base, "offline.bin")))
	}
	// C has no server and no route to B or source. It was not running at
	// provider release and now catches up by an authenticated pull from A.
	stopC := runCaptureWorker(t, ctx, x.workers[2])
	for {
		state, err := x.workers[2].Status(ctx)
		must(t, err)
		job := control.Replication{Domain: f.grant.Trust.Domain, From: x.ids[0], To: x.ids[2], Mode: "pull", Epoch: 1, PeerRevision: 1}.Job(f.grant.Trust, r.Generation)
		if state.Jobs[job.Operation].Phase == "COMPLETE" {
			break
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("outbound follower", ctx.Err(), state.Jobs[job.Operation])
		}
	}
	stopC()
	r.FollowerSeconds = time.Since(started).Seconds()
	r.Traffic = x.traffic.snapshot()
	seen := map[string]bool{}
	latest := map[string]time.Time{}
	for _, event := range r.Traffic.Puts {
		if event.Status < 200 || event.Status >= 300 {
			t.Fatal("source PUT did not receive durable acceptance", event)
		}
		if single && event.Node != x.ids[0] {
			t.Fatal("reference initially uploaded to companion")
		}
		if seen[event.Object] {
			r.RetryBytes += event.Bytes
		} else {
			r.InitialBytes += event.Bytes
			seen[event.Object] = true
		}
		for node, end := range latest {
			if node != event.Node && event.Bytes > 1<<20 && event.Start.Before(end) {
				r.LargeWriteOverlap = true
			}
		}
		if event.Bytes > 1<<20 && event.End.After(latest[event.Node]) {
			latest[event.Node] = event.End
		}
	}
	// A capture can be source/readback limited, or contain too few new packs
	// for actual PUT intervals to overlap. Record that result as measured.
	// TestSplitIngressColdSameOwnerUsesTwoInitialRecipients independently
	// requires actual two-node overlap when both payloads are already ready.
	if r.RetryBytes != 0 || r.InitialBytes == 0 {
		t.Fatal("initial data distribution or duplicate body accounting", r)
	}
	r.SourceReadBytesPerSecond = float64(r.SourceBytes) / r.SealedSeconds
	r.InitialBodyBytesPerSecond = float64(r.InitialBytes) / r.SealedSeconds
	if !x.split && r.Traffic.PreSeal == 0 {
		t.Fatal("complete-copy forwarding did not overlap capture")
	}
	if _, err := os.Stat(filepath.Join(f.tree, "private.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source input unexpectedly available during recovery")
	}
	for generationID, original := range x.retained {
		for n, dir := range x.dirs {
			replica := filepath.Join(worker.DomainDirectory(dir, f.grant.Trust), "replica")
			out := filepath.Join(f.base, "restore-"+r.Generation+"-"+generationID+"-"+string(rune('a'+n)))
			_, err := generation.RecoverMaterialized(ctx, replica, generationID, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
			must(t, err)
			hash := original.verify(t, filepath.Join(out, "private.bin"))
			if original.SHA256 == "" {
				original.SHA256 = hash
				x.retained[generationID] = original
			}
			if generationID == r.Generation {
				r.InputSHA256 = hash
			}
			t.Logf("ASYMMETRIC_RESTORE capture=%s generation=%s holder=%d bytes=%d sha256=%s", r.Generation, generationID, n, original.Bytes, hash)
			if x.removeVerifiedRestores {
				if filepath.Dir(out) != f.base || !strings.HasPrefix(filepath.Base(out), "restore-") {
					t.Fatal("restore cleanup outside owned fixture")
				}
				must(t, os.RemoveAll(out))
			}
		}
	}
	must(t, os.Rename(filepath.Join(f.base, "offline.bin"), filepath.Join(f.tree, "private.bin")))
	f.a, err = Open(ctx, f.b, false)
	must(t, err)
	raw, err := json.Marshal(r)
	must(t, err)
	t.Logf("ASYMMETRIC_CAPTURE %s", raw)
	return r
}

func TestAsymmetricSourceComparison(t *testing.T) {
	if os.Getenv("OUTPOST_ASYMMETRIC_SOURCE") != "1" {
		t.Skip("opt-in application-body rate model; not a wire-throughput benchmark")
	}
	payload, patch := make([]byte, 24<<20), make([]byte, 8<<20)
	_, err := rand.Read(payload)
	must(t, err)
	_, err = rand.Read(patch)
	must(t, err)
	var epoch fixtureEpoch
	epoch.owner, err = filekit.NewOwner()
	must(t, err)
	writer, private, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	maint, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	epoch.writer, epoch.trust = private, generation.Trust{Domain: epoch.owner.Domain, Repository: storage.Hash([]byte("asymmetric-repo")), Epoch: 1, Writer: writer, Maintenance: maint}
	for _, split := range []bool{false, true} {
		for _, single := range []bool{true, false} {
			name := "complete/paired"
			if split {
				name = "split/paired"
			}
			if single {
				name = strings.TrimSuffix(name, "paired") + "single"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
				defer cancel()
				x := newAsymmetricFixture(t, &epoch, payload, split)
				x.capture(t, ctx, single, asymmetricBytes(payload))
				input := filepath.Join(x.f.tree, "private.bin")
				info, err := os.Stat(input)
				must(t, err)
				file, err := os.OpenFile(input, os.O_WRONLY, 0)
				must(t, err)
				_, err = file.WriteAt(patch, 4<<20)
				must(t, err)
				must(t, file.Sync())
				must(t, file.Close())
				must(t, os.Chtimes(input, info.ModTime(), info.ModTime()))
				changed := bytes.Clone(payload)
				copy(changed[4<<20:], patch)
				r := x.capture(t, ctx, single, asymmetricBytes(changed))
				if r.InitialBytes >= int64(len(payload)) {
					t.Fatal("incremental capture retransmitted the full source", r.InitialBytes)
				}
			})
		}
	}
}

func TestAsymmetricBodyRateReservations(t *testing.T) {
	now := time.Now()
	fast, slow := &asymmetricRate{bytes: 100}, &asymmetricRate{bytes: 50}
	if got := fast.reserve(now, 100).Sub(now); got != time.Second {
		t.Fatal(got)
	}
	if got := fast.reserve(now, 100).Sub(now); got != 2*time.Second {
		t.Fatal("concurrent reservations did not share the cap", got)
	}
	if got := slow.reserve(now, 100).Sub(now); got != 2*time.Second {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := asymmetricWait(ctx, 10, &asymmetricRate{bytes: 1}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSplitIngressColdSameOwnerUsesTwoInitialRecipients(t *testing.T) {
	x := newAsymmetricFixture(t, nil, make([]byte, 32<<10), true)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	var mu sync.Mutex
	nodes := map[string]bool{}
	both := make(chan struct{})
	x.beforeSourcePut = func(node string, w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		nodes[node] = true
		if len(nodes) == 2 {
			select {
			case <-both:
			default:
				close(both)
			}
		}
		mu.Unlock()
		timer := time.NewTimer(8 * time.Second)
		defer timer.Stop()
		select {
		case <-both:
			return false
		case <-timer.C:
			http.Error(w, "same-owner initial writes did not use idle peer", http.StatusServiceUnavailable)
			return true
		case <-r.Context().Done():
			return true
		}
	}
	a := x.f.a
	must(t, a.Next(ctx))
	s, err := a.load()
	must(t, err)
	i, err := a.stateIntent(s)
	must(t, err)
	primary, err := ingress.NewClient(a.b.Endpoint, a.intentAuthority(s), s.Intent, a.b.Local.Owner, a.cert, a.roots, sourceFixtureLimits)
	must(t, err)
	group, err := a.openParallelSink(i, path.Join("operations", i.Operation), a.companion.Ingress, a.b.Companion.Endpoint, a.companionAuthority, primary, sourceFixtureLimits, true, false, nil)
	must(t, err)
	defer group.Close()
	must(t, group.Begin(ctx))
	type item struct {
		body []byte
		ref  filekit.Object
	}
	objects := make([]item, 2)
	for n := range objects {
		body := make([]byte, 2<<20)
		_, err = rand.Read(body)
		must(t, err)
		for attempt := 0; ; attempt++ {
			if attempt == 256 {
				t.Fatal("could not choose two distinct same-owner ciphertext objects")
			}
			body[0] = byte(attempt)
			ref := filekit.Object{ID: storage.Hash(body), Bytes: len(body)}
			if group.splitOwner(ref) == 0 {
				objects[n] = item{body, ref}
				break
			}
		}
	}
	done := make(chan error, 2)
	for _, object := range objects {
		go func() {
			created, err := group.Write(ctx, object.ref, object.body)
			if err == nil && !created {
				err = errors.New("new object was not created")
			}
			done <- err
		}()
	}
	var failures []error
	for range objects {
		if err := <-done; err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		t.Fatal("cold same-owner writes failed actual two-node rendezvous", failures)
	}
	mu.Lock()
	count := len(nodes)
	mu.Unlock()
	if count != 2 {
		t.Fatal("initial source requests used only one node", count)
	}
	traffic := x.traffic.snapshot()
	counts := map[string]int{}
	for _, event := range traffic.Puts {
		if event.Status < 200 || event.Status >= 300 {
			t.Fatal("PUT not durably accepted", event)
		}
		counts[event.Object]++
	}
	for _, object := range objects {
		if counts[object.ref.ID] != 1 {
			t.Fatal("source sent the same object more than once", counts)
		}
		body, err := group.Client.Read(ctx, object.ref)
		must(t, err)
		if !bytes.Equal(body, object.body) {
			t.Fatal("assigned owner did not receive exact peer ciphertext")
		}
	}
	t.Log("two cold same-owner objects used distinct actual source PUT recipients, one body per object, and exact assigned-owner peer delivery")
}
