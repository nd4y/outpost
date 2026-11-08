package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/worker"
)

type captureTraffic struct {
	mu       sync.Mutex
	initial  map[string]int
	payload  map[string]bool
	relayed  int
	together chan struct{}
}

func (c *captureTraffic) watch(node string, next http.Handler) http.HandlerFunc {
	return func(out http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) == 10 && parts[9] != "" {
			switch {
			case r.Method == http.MethodPut && parts[8] == "objects":
				c.mu.Lock()
				c.initial[parts[9]]++
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
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 220*time.Second)
	defer cancel()
	leaf, e := x509.ParseCertificate(f.replicaCertificate.Certificate[0])
	must(t, e)
	bID := peer.Identity(leaf)
	aID := f.grant.Ingress
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
	traffic := &captureTraffic{initial: map[string]int{}, payload: map[string]bool{}, together: make(chan struct{})}
	aHandler := traffic.watch(aID, aWorker)
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool { aHandler(out, r); return true }
	bServer := httptest.NewUnstartedServer(traffic.watch(bID, bWorker))
	bServer.TLS, e = peer.AuthenticatedServerTLS(f.replicaCertificate, f.roots, bID)
	must(t, e)
	bServer.StartTLS()
	t.Cleanup(bServer.Close)

	proofGrant, e := observation.SignGrant(observation.Grant{Format: observation.GrantFormat, Trust: f.grant.Trust, Reader: f.grant.Source, Collector: aID, Targets: []string{bID}, Epoch: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix, MaxAgeSeconds: 3600}, f.ownerSigner)
	must(t, e)
	planner, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	domain := control.Domain{CaptureStaging: true, Trust: f.grant.Trust, Planner: planner, Placement: policy.Placement{
		Domain: f.grant.Trust.Domain, AllowedClasses: []string{"trusted"}, Holders: []string{aID, bID}, Transit: []string{f.grant.Source},
		Edges: []policy.Edge{
			{From: f.grant.Source, To: aID, Mode: "push"}, {From: f.grant.Source, To: bID, Mode: "push"},
			{From: aID, To: bID, Mode: "pull"}, {From: bID, To: aID, Mode: "pull"},
		},
	}}
	cfg := control.Config{
		Format: control.SettlementConfigFormat, Node: aID, Revision: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix,
		Limits:  control.Limits{Parallel: 2, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20},
		Nodes:   []policy.Node{{ID: f.grant.Source, Class: "trusted"}, {ID: aID, Class: "trusted", Endpoint: f.server.URL}, {ID: bID, Class: "trusted", Endpoint: bServer.URL}},
		Domains: []control.Domain{domain}, Observations: []json.RawMessage{proofGrant}, Ingress: []json.RawMessage{f.authority},
	}
	legacy := cfg
	legacy.Format = control.Format
	if _, e = control.Sign(legacy, f.ownerSigner); !errors.Is(e, control.ErrDenied) {
		t.Fatal("legacy policy unexpectedly permits staged transport", e)
	}
	raw, e := control.Sign(cfg, f.ownerSigner)
	must(t, e)
	must(t, aWorker.Accept(ctx, raw))
	cfg.Node, cfg.Ingress = bID, []json.RawMessage{companion}
	raw, e = control.Sign(cfg, f.ownerSigner)
	must(t, e)
	must(t, bWorker.Accept(ctx, raw))
	stopA := runCaptureWorker(t, ctx, aWorker)
	stopB := runCaptureWorker(t, ctx, bWorker)

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
	payload := make([]byte, 9<<20)
	_, e = rand.Read(payload)
	must(t, e)
	input := filepath.Join(f.tree, "private.bin")
	must(t, os.WriteFile(input, payload, 0640))
	f.a, e = Open(ctx, f.b, true)
	must(t, e)
	must(t, f.a.Next(ctx))
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
	for _, count := range traffic.initial {
		if count != 1 {
			traffic.mu.Unlock()
			t.Fatal("the source sent a ciphertext object more than once")
		}
	}
	traffic.mu.Unlock()
	if !both || initial < 3 || relayed != initial {
		t.Fatal("distinct initial uploads or pre-publication pulls missing", both, initial, relayed)
	}
	t.Logf("sealed after %s with %d initial sends and %d peer reads", time.Since(started), initial, relayed)
	must(t, os.Remove(input))
	f.reopen(t)
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
	checkpoint, e := f.a.Checkpoint(ctx)
	must(t, e)
	c, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	if len(c.Copies) != 2 || c.Generation != s.Job.Generation {
		t.Fatal("expected two verified full copies", c)
	}
	t.Logf("two-copy checkpoint and acknowledgement after %s", time.Since(started))
	stopB()
	stopA()
	for idx, dir := range paths {
		out := filepath.Join(f.base, "restore-"+string(rune('a'+idx)))
		_, e = generation.RecoverMaterialized(ctx, dir, c.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		data, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		if !bytes.Equal(data, payload) {
			t.Fatal("independent restore differs", idx)
		}
	}
	t.Logf("concurrent source uploads, %d single initial sends, %d pre-seal peer reads, two independent restores after restart", initial, relayed)
}
