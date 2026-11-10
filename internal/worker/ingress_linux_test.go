package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWorkerAdmitsSourceUnderCachedPolicyAndCancelsRevokedGrant(t *testing.T) {
	f := newFixture(t)
	// Leave room for durable publication on a rotational test disk. The
	// revocation path below must still close a request with its body open.
	f.cfg.Limits.AttemptMillis = 60000
	received := make(chan struct{}, 1)
	served := make(chan struct{}, 1)
	server := f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Outpost-Test-Stall") == "1" {
				received <- struct{}{}
				defer func() { served <- struct{}{} }()
			}
			next.ServeHTTP(w, r)
		})
	})
	ctx := context.Background()
	w := f.nodes[1]
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	araw, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Ingress = []json.RawMessage{araw}
	f.config(t, 1, nil)
	stop := start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	i := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte("source-op")), Authority: storage.Hash(araw), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: time.Now().Unix(), NotBefore: a.NotBefore, ExpiresUnix: a.ExpiresUnix, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	iraw, e := ingress.SignIntent(i, araw, f.owner.Public().(ed25519.PublicKey), f.writer, time.Now())
	must(t, e)
	client, e := ingress.NewClient(server.URL, araw, iraw, f.owner.Public().(ed25519.PublicKey), f.nodes[0].cert, f.ca.pool, peer.Limits{Concurrency: 1, Timeout: 60 * time.Second, Attempts: 1})
	must(t, e)
	defer client.Close()
	must(t, client.Begin(ctx))
	s, e := filekit.OpenStreamingStore(filepath.Join(f.base, "stream-cache"), f.dataOwner, true, client)
	must(t, e)
	defer s.Close()
	v, e := s.Backup(ctx, filepath.Join(f.base, "input"), filekit.BackupOptions{Names: []string{"dataset/data"}})
	must(t, e)
	raw, roots, e := generation.BuildCatalog(ctx, s, []string{v.Version}, generation.Catalog{Format: generation.Format, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Sequence: i.Sequence, SnapshotUnix: i.SnapshotUnix, Policy: i.Policy}, f.writer)
	must(t, e)
	for id, b := range roots {
		_, e = client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
	_, receipt, e := client.FinishStep(ctx, raw)
	must(t, e)
	if receipt == nil {
		t.Fatal("no complete receipt")
	}
	before, e := w.budget.Status(ctx)
	must(t, e)
	ack, e := client.AcknowledgeStep(ctx, *receipt)
	must(t, e)
	if !ack.Clean {
		t.Fatal("not clean")
	}
	after, e := w.budget.Status(ctx)
	must(t, e)
	if before.Used["data"] <= after.Used["data"] {
		t.Fatal("staging removal did not return quota")
	}
	stop()
	// Cached policy alone resumes the same registry and its durable fence.
	stop = start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	i.Sequence = 2
	i.Parent = receipt.Generation
	i.Operation = storage.Hash([]byte("source-op-2"))
	i.SnapshotUnix = time.Now().Unix()
	iraw, e = ingress.SignIntent(i, araw, f.owner.Public().(ed25519.PublicKey), f.writer, time.Now())
	must(t, e)
	next, e := ingress.NewClient(server.URL, araw, iraw, f.owner.Public().(ed25519.PublicKey), f.nodes[0].cert, f.ca.pool, peer.Limits{Concurrency: 1, Timeout: 60 * time.Second, Attempts: 1})
	must(t, e)
	defer next.Close()
	must(t, next.Begin(ctx))
	// A slow authenticated body must not hold the old policy alive. Context
	// cancellation alone does not interrupt net/http's body reader.
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[0].cert}}}
	defer transport.CloseIdleConnections()
	stall := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	request, e := http.NewRequest(http.MethodPut, server.URL+"/v1/tenants/"+i.Tenant+"/domains/"+i.Domain+"/captures/"+i.Operation+"/objects/"+storage.Hash([]byte("stalled-object")), reader)
	must(t, e)
	request.ContentLength = 100
	request.Header.Set("Outpost-Bytes", "100")
	request.Header.Set("Outpost-Authority", i.Authority)
	request.Header.Set("Outpost-Test-Stall", "1")
	finished := make(chan bool, 1)
	go func() {
		response, e := stall.Do(request)
		accepted := e == nil && response.StatusCode == 200
		if response != nil {
			response.Body.Close()
		}
		finished <- accepted
	}()
	_, e = writer.Write([]byte("x"))
	must(t, e)
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled request absent")
	}
	select {
	case <-served:
		t.Fatal("stalled request ended before the policy change")
	default:
	}
	revoked := time.Now()
	f.cfg.Ingress = nil
	f.cfg.Revision = 2
	f.config(t, 1, nil)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 2 })
	if time.Since(revoked) >= 30*time.Second {
		t.Fatal("revocation waited for body timeout")
	}
	// The server must return while the sender still holds the body open. The
	// HTTP/1 client can wait for its own body writer before returning.
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled request handler leaked after revocation")
	}
	writer.Close()
	select {
	case accepted := <-finished:
		if accepted {
			t.Fatal("partial body accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled request leaked after revocation")
	}
	b := []byte("denied after policy replacement")
	_, e = next.Write(ctx, filekit.Object{ID: storage.Hash(b), Bytes: len(b)}, b)
	if !errors.Is(e, ingress.ErrDenied) {
		t.Fatal("stale capability accepted", e)
	}
	stop()
	out := filepath.Join(f.base, "restored-ingress")
	_, e = generation.RecoverMaterialized(ctx, filepath.Join(DomainDirectory(w.dir, a.Trust), "replica"), receipt.Generation, a.Trust, f.dataOwner, generation.RecoverySelection{}, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "dataset/data"))
	must(t, e)
	if string(got) != string(f.content) {
		t.Fatal("policy revocation damaged previous generation")
	}
	// The ordinary signed configuration remains valid without the removed grant.
	_, e = control.Sign(f.config(t, 1, nil), f.owner)
	must(t, e)
}

func TestWorkerAdvancesStagedImportBetweenQueuedTransfers(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	source, bridge, target := f.nodes[0], f.nodes[1], f.nodes[2]
	durable := make(chan struct{}, 3)
	target.Fault = func(point string) error {
		if point == "capture-object-durable" {
			select {
			case durable <- struct{}{}:
			default:
			}
		}
		return nil
	}
	_, first := f.jobs()
	second := first
	second.Operation = storage.Hash([]byte("second ordinary transfer"))
	jobs := []control.Job{first, second}
	started := make(chan string, len(jobs))
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	releases := map[string]chan struct{}{first.Operation: releaseFirst, second.Operation: releaseSecond}
	bridgeServer := f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			op := r.Header.Get("Outpost-Operation")
			release := releases[op]
			if release == nil {
				next.ServeHTTP(w, r)
				return
			}
			select {
			case started <- op:
			case <-r.Context().Done():
				return
			}
			select {
			case <-release:
				http.Error(w, "synthetic rejection", http.StatusForbidden)
			case <-r.Context().Done():
			}
		})
	})
	httpServer, err := target.HTTPServer()
	must(t, err)
	targetServer := httptest.NewUnstartedServer(httpServer.Handler)
	targetServer.TLS = httpServer.TLSConfig
	targetServer.StartTLS()
	t.Cleanup(targetServer.Close)
	f.cfg.Nodes[2].Endpoint = targetServer.URL
	f.cfg.Format = control.SettlementConfigFormat
	f.cfg.Limits.Parallel, f.cfg.Limits.AttemptMillis = 1, 60000
	f.domain.Placement.Edges = append(f.domain.Placement.Edges, policy.Edge{From: source.node, To: target.node, Mode: "push"})
	owner := f.owner.Public().(ed25519.PublicKey)
	intent := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte("queued capture")), Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: source.node, Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: time.Now().Unix(), NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, MaxBytes: 32 << 20, MaxObjects: 64}
	capture := func(index int, endpoint, stagingPeer string) *ingress.Client {
		t.Helper()
		i := intent
		i.Ingress = f.nodes[index].node
		a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: i.Tenant, Profile: i.Profile, Source: i.Source, Ingress: i.Ingress, Revision: 1, NotBefore: i.NotBefore, ExpiresUnix: i.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: i.MaxBytes, MaxObjects: i.MaxObjects}
		grant, err := ingress.SignAuthority(a, f.owner)
		must(t, err)
		i.Authority = storage.Hash(grant)
		signed, err := ingress.SignIntent(i, grant, owner, f.writer, time.Now())
		must(t, err)
		f.cfg.Ingress = []json.RawMessage{grant}
		f.domain.CaptureStagingPeers = []string{stagingPeer}
		f.domain.CaptureAutomaticPeers = []string{stagingPeer}
		f.config(t, index, jobs)
		client, err := ingress.NewClient(endpoint, grant, signed, owner, source.cert, f.ca.pool, peer.Limits{Concurrency: 1, Timeout: 60 * time.Second, Attempts: 1})
		must(t, err)
		t.Cleanup(client.Close)
		return client
	}
	origin := capture(1, bridgeServer.URL, target.node)
	destination := capture(2, targetServer.URL, bridge.node)
	stopBridge := start(t, bridge)
	wait(t, func() bool { bridge.mu.Lock(); defer bridge.mu.Unlock(); return bridge.active != nil })
	must(t, origin.Begin(ctx))
	data := []byte("durably staged ciphertext")
	object := filekit.Object{ID: storage.Hash(data), Bytes: len(data)}
	_, err = origin.Write(ctx, object, data)
	must(t, err)
	stopTarget := start(t, target)
	waitForStart := func(expected string) {
		t.Helper()
		select {
		case op := <-started:
			if op != expected {
				t.Fatalf("started %s, want %s", op, expected)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("transfer did not get a worker slot")
		}
	}
	waitForStart(first.Operation)
	must(t, destination.Begin(ctx))
	must(t, destination.QueueStaged(ctx, origin, object))
	if err = destination.Check(ctx, object); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the import ran while the only slot was occupied: %v", err)
	}
	close(releaseFirst)
	waitForStart(second.Operation)
	if err = destination.Check(ctx, object); err != nil {
		t.Fatalf("next ordinary transfer took the slot before the pending import: %v", err)
	}
	select {
	case <-durable:
	default:
		t.Fatal("explicit import did not reach durable storage")
	}
	awaitImport := func(ref filekit.Object) {
		t.Helper()
		select {
		case <-durable:
			must(t, destination.Check(ctx, ref))
		case <-time.After(60 * time.Second):
			t.Fatal("automatic import did not reach durable storage")
		}
	}
	// After initial capture admission, the source writes only to the bridge.
	// The receiver finds later objects without a per-object source request.
	automatic := []byte("ciphertext available only on the bridge")
	autoRef := filekit.Object{ID: storage.Hash(automatic), Bytes: len(automatic)}
	_, err = origin.Write(ctx, autoRef, automatic)
	must(t, err)
	if err = destination.Check(ctx, autoRef); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("automatic import ran while the second pull occupied the slot: %v", err)
	}
	close(releaseSecond)
	awaitImport(autoRef)
	stopBridge()
	stopBridge = start(t, bridge)
	wait(t, func() bool { bridge.mu.Lock(); defer bridge.mu.Unlock(); return bridge.active != nil })
	newData := []byte("ciphertext accepted after bridge reopen")
	newRef := filekit.Object{ID: storage.Hash(newData), Bytes: len(newData)}
	_, err = origin.Write(ctx, newRef, newData)
	must(t, err)
	awaitImport(newRef)
	stopTarget()
	stopBridge()
}

func TestWorkerAdmitsInitialCaptureThroughOfflineBridge(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	source, bridge, target := f.nodes[0], f.nodes[1], f.nodes[2]
	bridgeServer := f.endpoint(t, nil)
	f.cfg.Format = control.SettlementConfigFormat
	f.cfg.Limits.Parallel, f.cfg.Limits.AttemptMillis = 1, 60000
	owner := f.owner.Public().(ed25519.PublicKey)
	intent := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte("relayed capture")), Tenant: storage.Hash([]byte("relay tenant")), Profile: storage.Hash([]byte("relay profile")), Source: source.node, Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: time.Now().Unix(), NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, MaxBytes: 32 << 20, MaxObjects: 64}
	proof := func(receiver string) ([]byte, []byte) {
		t.Helper()
		i := intent
		i.Ingress = receiver
		a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: i.Tenant, Profile: i.Profile, Source: i.Source, Ingress: i.Ingress, Revision: 1, NotBefore: i.NotBefore, ExpiresUnix: i.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: i.MaxBytes, MaxObjects: i.MaxObjects}
		grant, err := ingress.SignAuthority(a, f.owner)
		must(t, err)
		i.Authority = storage.Hash(grant)
		raw, err := ingress.SignIntent(i, grant, owner, f.writer, time.Now())
		must(t, err)
		return grant, raw
	}
	bridgeGrant, bridgeIntent := proof(bridge.node)
	targetGrant, targetIntent := proof(target.node)
	f.cfg.Ingress = []json.RawMessage{bridgeGrant}
	f.domain.CaptureStagingPeers = []string{target.node}
	f.domain.CaptureAutomaticPeers = []string{target.node}
	f.domain.CaptureRelayPeers = []string{target.node}
	f.config(t, 1, nil)
	f.cfg.Ingress = []json.RawMessage{targetGrant}
	f.domain.CaptureStagingPeers = []string{bridge.node}
	f.domain.CaptureAutomaticPeers = []string{bridge.node}
	f.domain.CaptureRelayPeers = nil
	withoutRelay := f.cfg
	withoutRelay.Node, withoutRelay.Domains = target.node, []control.Domain{f.domain}
	if _, err := control.Sign(withoutRelay, f.owner); err == nil {
		t.Fatal("configuration accepted a capture with neither a direct nor a relay route")
	}
	f.domain.CaptureRelayPeers = []string{bridge.node}
	f.config(t, 2, nil)
	limits := peer.Limits{Concurrency: 1, Timeout: 60 * time.Second, Attempts: 1}
	upstream, err := ingress.NewClient(bridgeServer.URL, bridgeGrant, bridgeIntent, owner, source.cert, f.ca.pool, limits)
	must(t, err)
	t.Cleanup(upstream.Close)
	stopBridge := start(t, bridge)
	wait(t, func() bool { bridge.mu.Lock(); defer bridge.mu.Unlock(); return bridge.active != nil })
	must(t, upstream.Begin(ctx))
	unknownGrant, unknownIntent := proof(storage.Hash([]byte("unadmitted relay recipient")))
	if err = upstream.OfferRelayIntent(ctx, unknownGrant, unknownIntent); !errors.Is(err, ingress.ErrDenied) {
		t.Fatalf("unadmitted recipient entered the relay: %v", err)
	}
	must(t, upstream.OfferRelayIntent(ctx, targetGrant, targetIntent))
	must(t, upstream.OfferRelayIntent(ctx, targetGrant, targetIntent))
	data := []byte("ciphertext sent in the first connectivity window")
	object := filekit.Object{ID: storage.Hash(data), Bytes: len(data)}
	_, err = upstream.Write(ctx, object, data)
	must(t, err)
	upstream.Close()
	stopBridge()

	// The recipient's signed topology has no inbound endpoint or source edge.
	// An isolated listener makes the direct rejection observable in this test.
	targetHTTP, err := target.HTTPServer()
	must(t, err)
	listener := httptest.NewUnstartedServer(targetHTTP.Handler)
	listener.TLS = targetHTTP.TLSConfig
	listener.StartTLS()
	t.Cleanup(listener.Close)
	direct, err := ingress.NewClient(listener.URL, targetGrant, targetIntent, owner, source.cert, f.ca.pool, limits)
	must(t, err)
	t.Cleanup(direct.Close)
	durable := make(chan struct{}, 1)
	target.Fault = func(point string) error {
		if point == "capture-object-durable" {
			durable <- struct{}{}
		}
		return nil
	}
	stopTarget := start(t, target)
	wait(t, func() bool { target.mu.Lock(); defer target.mu.Unlock(); return target.active != nil })
	if err = direct.Begin(ctx); !errors.Is(err, ingress.ErrDenied) {
		t.Fatalf("direct source admission bypassed the signed topology: %v", err)
	}
	stopBridge = start(t, bridge)
	select {
	case <-durable:
	case <-time.After(90 * time.Second):
		t.Fatal("recipient did not admit and import the stored offer")
	}
	path := filepath.Join(DomainDirectory(target.dir, f.domain.Trust), "ingress", "current", "objects", object.ID)
	stored, err := os.ReadFile(path)
	must(t, err)
	if string(stored) != string(data) {
		t.Fatal("ciphertext changed across the bridge")
	}
	stopTarget()
	stopBridge()
}
