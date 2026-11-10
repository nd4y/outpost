package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

type captureTraffic struct {
	mu       sync.Mutex
	initial  map[string]int
	payload  map[string]bool
	object   string
	length   string
	relayed  int
	together chan struct{}
}

type droppedCaptureReply struct {
	*httptest.ResponseRecorder
	wire http.ResponseWriter
}

func (r droppedCaptureReply) Unwrap() http.ResponseWriter { return r.wire }

func (c *captureTraffic) watch(node string, next http.Handler) http.HandlerFunc {
	return func(out http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) == 10 && parts[9] != "" {
			switch {
			case r.Method == http.MethodPut && parts[8] == "objects":
				c.mu.Lock()
				c.initial[parts[9]]++
				if c.object == "" {
					c.object = parts[9]
					c.length = r.Header.Get("Outpost-Bytes")
				}
				first := r.ContentLength > 1<<20 && !c.payload[node]
				if first {
					c.payload[node] = true
					if len(c.payload) == 2 {
						close(c.together)
					}
				}
				c.mu.Unlock()
				if first {
					select {
					case <-c.together:
					case <-r.Context().Done():
						return
					}
				}
			case r.Method == http.MethodGet && parts[8] == "staged":
				c.mu.Lock()
				c.relayed++
				c.mu.Unlock()
			}
		}
		next.ServeHTTP(out, r)
	}
}

func runCaptureWorker(t *testing.T, ctx context.Context, w *worker.Worker) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
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
		case <-time.After(15 * time.Second):
			t.Fatal("capture worker did not stop")
		}
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		status, e := w.Status(ctx)
		if e == nil && status.Phase == "ACTIVE" {
			return stop
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("capture worker did not reach ACTIVE")
	return stop
}

func TestSourceParallelIngressForwardsBeforeSealAndRecoversBoth(t *testing.T) {
	testPairedCapture(t, "", false, false)
}

func TestSourceCoverageReleasesBeforePublicationAndWorkersResume(t *testing.T) {
	testPairedCapture(t, capture.TwoHolderCoverage, false, false)
}

func TestSourcePartitionCoverageAssemblesFromPeersAfterRelease(t *testing.T) {
	testPairedCapture(t, capture.PairedSplitCoverage, false, false)
}

func TestSourceSplitReusesInitialCiphertextAfterInterruptedDelivery(t *testing.T) {
	testPairedCapture(t, capture.PairedSplitCoverage, false, true)
}

func TestExpiredPairedCoveragePublishesAndSettlesOfflineSource(t *testing.T) {
	if os.Getenv("OUTPOST_EXPIRY_INTEGRATION") != "1" {
		t.Skip("real expiry integration is exercised on the dedicated HDD")
	}
	testPairedCapture(t, capture.PairedSplitCoverage, true, false)
}

func testPairedCapture(t *testing.T, releasePolicy string, expire, interruptedDelivery bool) {
	t.Helper()
	coverage := releasePolicy != ""
	split := releasePolicy == capture.PairedSplitCoverage
	var followerCert tls.Certificate
	lifetime, timeout := int64(1800), 240*time.Second
	if expire {
		lifetime, timeout = 155, 425*time.Second
	}
	f := newFixtureWithPeer(t, lifetime, &followerCert)
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	leaf, e := x509.ParseCertificate(f.replicaCertificate.Certificate[0])
	must(t, e)
	bID := peer.Identity(leaf)
	aID := f.grant.Ingress
	leaf, e = x509.ParseCertificate(followerCert.Certificate[0])
	must(t, e)
	cID := peer.Identity(leaf)
	companionGrant := f.grant
	companionGrant.Ingress = bID
	companion, e := ingress.SignAuthority(companionGrant, f.ownerSigner)
	must(t, e)
	aDir, bDir := filepath.Join(f.base, "holder-a"), filepath.Join(f.base, "holder-b")
	aWorker, e := worker.Open(worker.Options{Directory: aDir, Node: aID, Owner: f.b.Local.Owner, Certificate: f.destination, Roots: f.roots, Initialize: true})
	must(t, e)
	t.Cleanup(func() { aWorker.Close() })
	bWorker, e := worker.Open(worker.Options{Directory: bDir, Node: bID, Owner: f.b.Local.Owner, Certificate: f.replicaCertificate, Roots: f.roots, Initialize: true})
	must(t, e)
	t.Cleanup(func() { bWorker.Close() })
	cDir := filepath.Join(f.base, "outbound-follower")
	cWorker, e := worker.Open(worker.Options{Directory: cDir, Node: cID, Owner: f.b.Local.Owner, Certificate: followerCert, Roots: f.roots, Initialize: true})
	must(t, e)
	t.Cleanup(func() { cWorker.Close() })
	traffic := &captureTraffic{initial: map[string]int{}, payload: map[string]bool{}, together: make(chan struct{})}
	aHandler := traffic.watch(aID, aWorker)
	var attemptedDrop, dropped atomic.Bool
	var allowCoverage, allowPublication, refuseInitial atomic.Bool
	var peerImports atomic.Int64
	allowCoverage.Store(!coverage)
	allowPublication.Store(!coverage)
	for _, node := range []*worker.Worker{aWorker, bWorker} {
		node.Fault = func(point string) error {
			if point == "capture-coverage-before-publication" && !allowPublication.Load() {
				return errors.New("publication paused until source exits")
			}
			return nil
		}
	}
	peerRead := func(out http.ResponseWriter, r *http.Request) bool {
		if !split || r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/staged/") ||
			r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || peer.Identity(r.TLS.PeerCertificates[0]) == cID {
			return false
		}
		if !allowPublication.Load() {
			http.Error(out, "peer import paused", http.StatusServiceUnavailable)
			return true
		}
		peerImports.Add(1)
		return false
	}
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool {
		if peerRead(out, r) {
			return true
		}
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") && refuseInitial.CompareAndSwap(true, false) {
			http.Error(out, "staging quota", http.StatusInsufficientStorage)
			return true
		}
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/catalog") && attemptedDrop.CompareAndSwap(false, true) {
			rec := httptest.NewRecorder()
			aHandler(droppedCaptureReply{ResponseRecorder: rec, wire: out}, r)
			if rec.Code == http.StatusAccepted || rec.Code == http.StatusOK {
				dropped.Store(true)
				http.Error(out, "lost catalog reply after durable processing", http.StatusServiceUnavailable)
				return true
			}
			attemptedDrop.Store(false)
			for name, values := range rec.Header() {
				out.Header()[name] = values
			}
			out.WriteHeader(rec.Code)
			_, _ = out.Write(rec.Body.Bytes())
			return true
		}
		aHandler(out, r)
		return true
	}
	bHandler := traffic.watch(bID, bWorker)
	bServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peerRead(w, r) {
			return
		}
		if !allowCoverage.Load() && (strings.HasSuffix(r.URL.Path, "/coverage") || strings.HasSuffix(r.URL.Path, "/partition")) {
			http.Error(w, "required coverage unavailable", http.StatusPreconditionFailed)
			return
		}
		bHandler.ServeHTTP(w, r)
	}))
	bServer.TLS, e = peer.AuthenticatedServerTLS(f.replicaCertificate, f.roots, bID)
	must(t, e)
	bServer.StartTLS()
	t.Cleanup(bServer.Close)

	proofGrant, e := observation.SignGrant(observation.Grant{Format: observation.GrantFormat, Trust: f.grant.Trust, Reader: f.grant.Source, Collector: aID, Targets: []string{bID}, Epoch: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix, MaxAgeSeconds: 3600}, f.ownerSigner)
	must(t, e)
	planner, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	domain := control.Domain{CaptureStagingPeers: []string{bID}, Trust: f.grant.Trust, Planner: planner, Placement: policy.Placement{
		Domain: f.grant.Trust.Domain, AllowedClasses: []string{"trusted"}, Holders: []string{aID, bID, cID}, Transit: []string{f.grant.Source},
		Edges: []policy.Edge{
			{From: f.grant.Source, To: aID, Mode: "push"}, {From: f.grant.Source, To: bID, Mode: "push"},
			{From: aID, To: bID, Mode: "pull"}, {From: bID, To: aID, Mode: "pull"},
			{From: aID, To: cID, Mode: "pull"},
		},
	}}
	follow := control.Replication{Domain: f.grant.Trust.Domain, From: aID, To: cID, Mode: "pull", Epoch: 1, PeerRevision: 1}
	cfg := control.Config{
		Format: control.SettlementConfigFormat, Node: aID, Revision: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix,
		Limits: control.Limits{Parallel: 2, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20},
		Nodes: []policy.Node{{ID: f.grant.Source, Class: "trusted"}, {ID: aID, Class: "trusted", Endpoint: f.server.URL},
			{ID: bID, Class: "trusted", Endpoint: bServer.URL}, {ID: cID, Class: "trusted"}},
		Domains: []control.Domain{domain}, Observations: []json.RawMessage{proofGrant}, Ingress: []json.RawMessage{f.authority},
		Replication: []control.Replication{follow},
	}
	legacy := cfg
	legacy.Format = control.Format
	if _, e = control.Sign(legacy, f.ownerSigner); !errors.Is(e, control.ErrDenied) {
		t.Fatal("legacy policy unexpectedly permits staged transport", e)
	}
	raw, e := control.Sign(cfg, f.ownerSigner)
	must(t, e)
	must(t, aWorker.Accept(ctx, raw))
	aConfig := cfg
	aConfig.Domains = append([]control.Domain(nil), cfg.Domains...)
	cfg.Node, cfg.Ingress = bID, []json.RawMessage{companion}
	cfg.Replication = nil
	cfg.Domains[0].CaptureStagingPeers = []string{aID}
	raw, e = control.Sign(cfg, f.ownerSigner)
	must(t, e)
	must(t, bWorker.Accept(ctx, raw))
	bConfig := cfg
	bConfig.Domains = append([]control.Domain(nil), cfg.Domains...)
	cfg.Node, cfg.Ingress, cfg.Observations = cID, nil, nil
	cfg.Limits.AttemptMillis = 60000
	cfg.Domains[0].CaptureStagingPeers = nil
	cfg.Replication = []control.Replication{follow}
	raw, e = control.Sign(cfg, f.ownerSigner)
	must(t, e)
	must(t, cWorker.Accept(ctx, raw))
	stopA := runCaptureWorker(t, t.Context(), aWorker)
	stopB := runCaptureWorker(t, t.Context(), bWorker)

	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "parallel-agent")
	f.b.Profile.MinimumCopies = 2
	f.b.Profile.CopyTargets = []string{aID, bID}
	f.b.ObservationFile = filepath.Join(f.base, "parallel-observation.json")
	f.b.Companion = &CompanionIngress{Endpoint: bServer.URL, AuthorityFile: filepath.Join(f.base, "companion-authority.json")}
	must(t, os.WriteFile(f.b.ObservationFile, proofGrant, 0600))
	must(t, os.WriteFile(f.b.Companion.AuthorityFile, companion, 0600))
	// Two payload packs are enough to force concurrent durable writes.
	size := 9 << 20
	if coverage {
		f.b.Profile.ReleasePolicy = releasePolicy
		size = 32 << 10
	}
	payload := make([]byte, size)
	_, e = rand.Read(payload)
	must(t, e)
	input := filepath.Join(f.tree, "private.bin")
	must(t, os.WriteFile(input, payload, 0640))
	f.a, e = Open(ctx, f.b, true)
	must(t, e)
	must(t, f.a.Next(ctx))
	if interruptedDelivery {
		testSplitDelivery(t, ctx, f.a, traffic, &allowPublication, &refuseInitial)
		return
	}
	started := time.Now()
	pause := errors.New("pause before receiver publication")
	f.a.Fault = func(point string) error {
		if point == "source-catalog-durable" {
			return pause
		}
		return nil
	}
	if e = f.a.Run(ctx); !errors.Is(e, pause) {
		t.Fatal("capture did not reach durable seal", e)
	}
	s, e := f.a.Status(ctx)
	must(t, e)
	if s.Job == nil || s.Job.Phase != "SEALED" || s.Job.Receipt != nil {
		t.Fatal("unexpected publication before seal checkpoint", s)
	}
	paths := []string{
		filepath.Join(worker.DomainDirectory(aDir, f.grant.Trust), "replica"),
		filepath.Join(worker.DomainDirectory(bDir, f.grant.Trust), "replica"),
	}
	for _, dir := range paths {
		r, e := generation.Open(dir, f.grant.Trust, false)
		must(t, e)
		inventory, e := r.Inventory(ctx)
		must(t, e)
		must(t, r.Close())
		if len(inventory) != 0 {
			t.Fatal("staged capture entered complete inventory")
		}
	}
	traffic.mu.Lock()
	initial := len(traffic.initial)
	both := len(traffic.payload) == 2
	relayed := traffic.relayed
	object, length := traffic.object, traffic.length
	for _, count := range traffic.initial {
		if count != 1 {
			traffic.mu.Unlock()
			t.Fatal("the source sent a ciphertext object more than once")
		}
	}
	traffic.mu.Unlock()
	wantRelay := initial
	if split {
		wantRelay = 0
	}
	if (!coverage && (!both || initial < 3)) || initial == 0 || relayed != wantRelay {
		t.Fatal("distinct initial uploads or pre-publication pulls missing", both, initial, relayed)
	}
	client, _, e := peer.AuthenticatedHTTP(f.server.URL, followerCert, f.roots, cID, aID, sourceFixtureLimits)
	must(t, e)
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, f.server.URL+"/v1/tenants/"+f.grant.Tenant+
		"/domains/"+f.grant.Trust.Domain+"/captures/"+s.Operation+"/staged/"+object, nil)
	must(t, e)
	req.Header.Set("Outpost-Authority", storage.Hash(f.authority))
	req.Header.Set("Outpost-Bytes", length)
	response, e := client.Do(req)
	must(t, e)
	must(t, response.Body.Close())
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("ordinary follower route admitted a staged read", response.StatusCode)
	}
	t.Logf("sealed after %s with %d initial sends and %d peer reads", time.Since(started), initial, relayed)
	if coverage {
		f.a.Fault = nil
		if e = f.a.Run(ctx); !errors.Is(e, ingress.ErrIncomplete) {
			t.Fatal("capture did not wait for the second holder", e)
		}
		current, e := f.a.Status(ctx)
		must(t, e)
		if current.Job.StagedRelease != "" || current.Milestones == nil || current.Milestones.ProviderReleaseUnix != 0 {
			t.Fatal("snapshot release advanced without the second coverage receipt", current.Job)
		}
		allowCoverage.Store(true)
		f.a.Fault = func(point string) error {
			if point == "source-coverage-checkpoint-durable" {
				return pause
			}
			return nil
		}
		if e = f.a.Run(ctx); !errors.Is(e, pause) {
			t.Fatal("capture did not persist its signed coverage before release", e)
		}
		f.reopen(t)
		f.a.Fault = func(point string) error {
			if point == "source-coverage-release-durable" {
				return pause
			}
			return nil
		}
		if e = f.a.Run(ctx); !errors.Is(e, pause) {
			t.Fatal("capture did not release independently of publication", e)
		}
		current, e = f.a.Status(ctx)
		must(t, e)
		if current.Job.Phase != "SEALED" || current.Job.StagedRelease != "RELEASED" || current.Job.Receipt != nil {
			t.Fatal("coverage was confused with full publication", current.Job)
		}
		if current.Milestones == nil || current.Milestones.ProviderReleaseUnix < current.Milestones.SnapshotUnix ||
			current.Milestones.FirstReplicaVerifiedUnix != 0 || len(current.Milestones.Replicas) != 0 {
			t.Fatal("coverage release was not observed independently of full replica readiness", current.Milestones)
		}
		released := current.Milestones.ProviderReleaseUnix
		if _, e = f.a.Checkpoint(ctx); !errors.Is(e, capture.ErrCopies) {
			t.Fatal("coverage was exposed as a full-copy checkpoint", e)
		}
		must(t, os.Remove(input))
		must(t, f.a.Close())
		f.a = nil
		stopA()
		stopB()
		for _, dir := range paths {
			replica, e := generation.Open(dir, f.grant.Trust, false)
			must(t, e)
			inventory, e := replica.Inventory(ctx)
			must(t, e)
			must(t, replica.Close())
			if len(inventory) != 0 {
				t.Fatal("coverage published a full replica before verification")
			}
		}
		var primary, companion control.SettlementAdmission
		if expire {
			deadline := time.NewTimer(time.Until(time.Unix(f.grant.ExpiresUnix, 0)) + 20*time.Millisecond)
			defer deadline.Stop()
			select {
			case <-deadline.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			f.a, e = Open(ctx, f.b, false)
			must(t, e)
			if e = f.a.Run(ctx); !errors.Is(e, ingress.ErrDenied) {
				t.Fatal("expired original capture unexpectedly resumed", e)
			}
			provision := func(receiver string, cfg control.Config, node *worker.Worker) control.SettlementAdmission {
				req, err := f.a.SettlementPreviewFor(ctx, ingress.SettlementPublish, receiver)
				must(t, err)
				grant, err := SignSettlementAdmission(req, f.ownerSigner)
				must(t, err)
				cfg.Ingress, cfg.Observations, cfg.Settlements = nil, nil, []control.SettlementAdmission{grant}
				cfg.Revision++
				cfg.NotBefore = time.Now().Unix()
				cfg.ExpiresUnix = cfg.NotBefore + 300
				raw, err := control.Sign(cfg, f.ownerSigner)
				must(t, err)
				must(t, node.Accept(ctx, raw))
				return grant
			}
			primary = provision(aID, aConfig, aWorker)
			companion = provision(bID, bConfig, bWorker)
			must(t, f.a.Close())
			f.a = nil
		}
		allowPublication.Store(true)
		runCaptureWorker(t, ctx, aWorker)
		runCaptureWorker(t, ctx, bWorker)
		for idx, dir := range paths {
			replica, e := generation.Open(dir, f.grant.Trust, false)
			must(t, e)
			for {
				inventory, e := replica.Inventory(ctx)
				must(t, e)
				if len(inventory) == 1 {
					break
				}
				select {
				case <-time.After(100 * time.Millisecond):
				case <-ctx.Done():
					t.Fatal("worker did not publish without the source", ctx.Err())
				}
			}
			must(t, replica.Close())
			out := filepath.Join(f.base, "coverage-restore-"+string(rune('a'+idx)))
			_, e = generation.RecoverMaterialized(ctx, dir, s.Job.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
			must(t, e)
			got, e := os.ReadFile(filepath.Join(out, "private.bin"))
			must(t, e)
			if !bytes.Equal(got, payload) {
				t.Fatal("coverage restore differs", idx)
			}
		}
		if split && peerImports.Load() < int64(initial) {
			t.Fatal("split coverage did not retrieve all initially disjoint objects from the peer", peerImports.Load(), initial)
		}
		lateReads := peerImports.Load()
		if expire {
			endpoint, node, reader, authority, wrong := f.server.URL, aID, f.replicaCertificate, f.authority, primary
			if ingress.CoverageHolder(object, aID, bID) == bID {
				endpoint, node, reader, authority, wrong = bServer.URL, bID, f.destination, companion.Authority, companion
			}
			readerLeaf, e := x509.ParseCertificate(reader.Certificate[0])
			must(t, e)
			wire, _, e := peer.AuthenticatedHTTP(endpoint, reader, f.roots, peer.Identity(readerLeaf), node, sourceFixtureLimits)
			must(t, e)
			defer wire.CloseIdleConnections()
			for _, grant := range [][]byte{nil, wrong.Grant} {
				req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/tenants/"+f.grant.Tenant+
					"/domains/"+f.grant.Trust.Domain+"/captures/"+s.Operation+"/staged/"+object, nil)
				must(t, e)
				req.Header.Set("Outpost-Authority", storage.Hash(authority))
				req.Header.Set("Outpost-Bytes", length)
				if len(grant) != 0 {
					req.Header.Set("Outpost-Publication-Grant", base64.RawStdEncoding.EncodeToString(grant))
				}
				reply, e := wire.Do(req)
				must(t, e)
				must(t, reply.Body.Close())
				if reply.StatusCode != http.StatusForbidden {
					t.Fatal("late peer read accepted an absent or mismatched requester grant", reply.StatusCode)
				}
			}
			f.a, e = Open(ctx, f.b, false)
			must(t, e)
			must(t, f.a.SettleWithCompanion(ctx, primary, &companion))
			raw, e := f.a.Checkpoint(ctx)
			must(t, e)
			checkpoint, e := capture.VerifyCheckpoint(raw, f.grant.Trust)
			must(t, e)
			if checkpoint.Receipt.PublishedWith == "" || len(checkpoint.Copies) != 2 || checkpoint.Receipt.VerifiedAt < f.grant.ExpiresUnix {
				t.Fatal("late receipt lost its provenance or bypassed the full-copy threshold", checkpoint)
			}
			t.Log("both receivers independently restored after original expiry; source accepted the late receipts with their original verification times")
		} else {
			f.a, e = Open(ctx, f.b, false)
			must(t, e)
			for {
				e = f.a.Run(ctx)
				if !errors.Is(e, capture.ErrCopies) && !errors.Is(e, observation.ErrPending) {
					break
				}
				select {
				case <-time.After(100 * time.Millisecond):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			must(t, e)
			completed, e := f.a.Status(ctx)
			must(t, e)
			if completed.Milestones == nil || completed.Milestones.ProviderReleaseUnix != released {
				t.Fatal("release observation changed after complete publication", completed.Milestones)
			}
			checkpoint, e := f.a.Checkpoint(ctx)
			must(t, e)
			verified, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
			must(t, e)
			checkReplicaMilestones(t, completed.Milestones, verified.Copies)
		}
		t.Logf("withheld coverage blocked release; signed checkpoint survived source restart; both restarted workers restored independently with the source offline (%d background peer reads)", lateReads)
		return
	}
	must(t, os.Remove(input))
	f.reopen(t)
	finishCtx, stopFinish := context.WithTimeout(t.Context(), 180*time.Second)
	defer stopFinish()
	for {
		e = f.a.Run(finishCtx)
		if !errors.Is(e, capture.ErrCopies) && !errors.Is(e, observation.ErrPending) {
			break
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-finishCtx.Done():
			t.Fatal(finishCtx.Err())
		}
	}
	must(t, e)
	if !dropped.Load() {
		t.Fatal("no durable catalog response was withheld")
	}
	t.Log("source resumed publication after a lost durable catalog reply")
	checkpoint, e := f.a.Checkpoint(finishCtx)
	must(t, e)
	c, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	if len(c.Copies) != 2 || c.Generation != s.Job.Generation {
		t.Fatal("expected two verified full copies", c)
	}
	completed, e := f.a.Status(finishCtx)
	must(t, e)
	checkReplicaMilestones(t, completed.Milestones, c.Copies)
	t.Logf("two-copy checkpoint and acknowledgement after %s", time.Since(started))
	must(t, f.a.Close())
	f.a = nil
	stopB()
	// The third node has no listener and never ran during source capture.
	// It obtains the complete generation from A after the source is gone.
	followCtx, stopFollow := context.WithTimeout(t.Context(), 140*time.Second)
	defer stopFollow()
	stopC := runCaptureWorker(t, followCtx, cWorker)
	operation := follow.Job(f.grant.Trust, c.Generation).Operation
	for {
		state, e := cWorker.Status(followCtx)
		must(t, e)
		if state.Jobs[operation].Phase == "COMPLETE" {
			break
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-followCtx.Done():
			t.Fatal("outbound follower did not complete after source release", followCtx.Err(), state.Jobs[operation].Phase, state.Jobs[operation].ErrorCode)
		}
	}
	stopC()
	stopA()
	paths = append(paths, filepath.Join(worker.DomainDirectory(cDir, f.grant.Trust), "replica"))
	for idx, dir := range paths {
		out := filepath.Join(f.base, "restore-"+string(rune('a'+idx)))
		_, e = generation.RecoverMaterialized(followCtx, dir, c.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		data, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		if !bytes.Equal(data, payload) {
			t.Fatal("independent restore differs", idx)
		}
	}
	t.Logf("concurrent source uploads, %d single initial sends, %d pre-seal peer reads, three independent restores with the outbound follower admitted after source release", initial, relayed)
}

func checkReplicaMilestones(t *testing.T, milestones *Milestones, receipts []capture.CopyReceipt) {
	t.Helper()
	if milestones == nil || len(receipts) != 2 || len(milestones.Replicas) != 2 ||
		milestones.FirstReplicaVerifiedUnix != min(receipts[0].ObservedUnix, receipts[1].ObservedUnix) {
		t.Fatal("first and per-replica times did not survive completion", milestones)
	}
	for i, receipt := range receipts {
		if milestones.Replicas[i].Target != receipt.Target || milestones.Replicas[i].VerifiedUnix != receipt.ObservedUnix {
			t.Fatal("replica timing differs from the authenticated checkpoint", milestones.Replicas[i])
		}
	}
}

func testSplitDelivery(t *testing.T, ctx context.Context, a *Agent, traffic *captureTraffic, allow, refuse *atomic.Bool) {
	t.Helper()
	state, err := a.load()
	must(t, err)
	i, err := a.stateIntent(state)
	must(t, err)
	companion, raw, err := a.companionIntent(i, a.companionAuthority)
	must(t, err)
	open := func(replaying bool) *parallelSink {
		primary, err := ingress.NewClient(a.b.Endpoint, a.authority, state.Intent, a.b.Local.Owner, a.cert, a.roots, sourceFixtureLimits)
		must(t, err)
		t.Cleanup(primary.Close)
		other, err := ingress.NewClient(a.b.Companion.Endpoint, a.companionAuthority, raw, a.b.Local.Owner, a.cert, a.roots, sourceFixtureLimits)
		must(t, err)
		t.Cleanup(other.Close)
		sink := &parallelSink{Client: primary, companion: other, primary: i.Ingress, intention: companion, split: true, replaying: replaying}
		must(t, sink.Begin(ctx))
		return sink
	}
	sink := open(false)
	object := func(seed byte) ([]byte, filekit.Object) {
		t.Helper()
		payload := make([]byte, minIngressSample)
		payload[1] = seed
		for n := range 256 {
			payload[0] = byte(n)
			ref := filekit.Object{ID: storage.Hash(payload), Bytes: len(payload)}
			if sink.splitOwner(ref) == 1 {
				return payload, ref
			}
		}
		t.Fatal("test object has no companion ownership")
		return nil, filekit.Object{}
	}
	preferPrimary := func(s *parallelSink) {
		s.distribution.observe(0, minIngressSample, time.Second)
		s.distribution.observe(1, minIngressSample, 4*time.Second)
	}
	payload, ref := object(1)
	preferPrimary(sink)
	if _, err = sink.Write(ctx, ref, payload); !errors.Is(err, ingress.ErrUnavailable) {
		t.Fatal("did not interrupt delivery after durable source PUT", err)
	}
	must(t, sink.Client.Check(ctx, ref))
	if err = sink.companion.Check(ctx, ref); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stable owner unexpectedly accepted the object", err)
	}
	sink.Client.Close()
	sink.companion.Close()
	allow.Store(true)
	resumed := open(true)
	created, err := resumed.Write(ctx, ref, payload)
	must(t, err)
	if created {
		t.Fatal("resume sent source bytes again")
	}
	got, err := resumed.Read(ctx, ref)
	must(t, err)
	traffic.mu.Lock()
	initial := traffic.initial[ref.ID]
	traffic.mu.Unlock()
	if initial != 1 || !bytes.Equal(got, payload) {
		t.Fatal("handoff did not recover exact ciphertext with one source PUT", initial)
	}
	capped := open(false)
	preferPrimary(capped)
	payload, ref = object(2)
	refuse.Store(true)
	created, err = capped.Write(ctx, ref, payload)
	must(t, err)
	if !created || refuse.Load() {
		t.Fatal("adaptive staging refusal did not fall back to the owner")
	}
	must(t, capped.companion.Check(ctx, ref))
	if err = capped.Client.Check(ctx, ref); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused origin unexpectedly accepted a duplicate", err)
	}
}

func TestParallelIngressRenewsBothAuthoritiesAtomically(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	leaf, e := x509.ParseCertificate(f.replicaCertificate.Certificate[0])
	must(t, e)
	bID := peer.Identity(leaf)
	pair := f.grant
	pair.Ingress = bID
	originalCompanion, e := ingress.SignAuthority(pair, f.ownerSigner)
	must(t, e)
	g := observation.Grant{Format: observation.GrantFormat, Trust: f.grant.Trust, Reader: f.grant.Source,
		Collector: f.grant.Ingress, Targets: []string{bID}, Epoch: 1, NotBefore: f.grant.NotBefore,
		ExpiresUnix: f.grant.ExpiresUnix, MaxAgeSeconds: 3600}
	observed, e := observation.SignGrant(g, f.ownerSigner)
	must(t, e)
	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "renewable-pair")
	f.b.Profile.MinimumCopies = 2
	f.b.Profile.CopyTargets = []string{f.grant.Ingress, bID}
	f.b.ObservationFile = filepath.Join(f.base, "pair-observation.json")
	f.b.Companion = &CompanionIngress{Endpoint: "https://127.0.0.1:1", AuthorityFile: filepath.Join(f.base, "pair-authority.json")}
	must(t, os.WriteFile(f.b.ObservationFile, observed, 0600))
	must(t, os.WriteFile(f.b.Companion.AuthorityFile, originalCompanion, 0600))
	f.a, e = Open(ctx, f.b, true)
	must(t, e)

	primary := f.grant
	primary.Revision++
	pair.Revision = primary.Revision
	a, e := ingress.SignAuthority(primary, f.ownerSigner)
	must(t, e)
	b, e := ingress.SignAuthority(pair, f.ownerSigner)
	must(t, e)
	if _, e = f.a.Renew(ctx, a, nil); !errors.Is(e, ErrUnsupported) {
		t.Fatal("one half of pair was admitted", e)
	}
	if _, e = f.a.RenewPair(ctx, a, originalCompanion, nil); !errors.Is(e, ingress.ErrDenied) {
		t.Fatal("mismatched grant revisions admitted", e)
	}
	interrupted := errors.New("lost paired renewal reply")
	before, e := f.a.store.Read("agent.json")
	must(t, e)
	f.a.Fault = func(point string) error {
		if point == "source-renewal-checkpoint-durable" {
			return interrupted
		}
		return nil
	}
	if _, e = f.a.RenewPair(ctx, a, b, nil); !errors.Is(e, interrupted) {
		t.Fatal("legacy checkpoint interruption missing", e)
	}
	after, e := f.a.store.Read("agent.json")
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("the signed source journal changed before the atomic update")
	}
	f.a.Fault = func(point string) error {
		if point == "source-renewal-committed" {
			return interrupted
		}
		return nil
	}
	if _, e = f.a.RenewPair(ctx, a, b, nil); !errors.Is(e, interrupted) {
		t.Fatal("paired renewal reply interruption missing", e)
	}
	if _, e = f.a.Status(ctx); !errors.Is(e, ErrAuthorityChanged) {
		t.Fatal("stale agent used old authority", e)
	}
	f.reopen(t)
	r, e := f.a.RenewPair(ctx, a, b, nil)
	must(t, e)
	if r.Revision != 2 || !r.Reopen {
		t.Fatal("wrong resumed renewal", r)
	}
	must(t, f.a.Next(ctx))
	pending, e := f.a.load()
	must(t, e)
	if pending.Phase != "PREPARING" || !bytes.Equal(pending.IntentAuthority, a) ||
		!bytes.Equal(pending.IntentCompanionAuthority, b) || len(pending.Checkpoint) != 0 {
		t.Fatal("new capture did not bind both current grants")
	}
	t.Log("paired authorities survive interrupted migration and bind the next signed operation")
}
