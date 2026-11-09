package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/worker"
)

func TestSourceActiveReceiverReplacement(t *testing.T) {
	t.Run("single", func(t *testing.T) { testActiveReceiverReplacement(t, 1) })
	t.Run("two-copies", func(t *testing.T) { testActiveReceiverReplacement(t, 2) })
}

func testActiveReceiverReplacement(t *testing.T, copies int) {
	t.Helper()
	var third tls.Certificate
	f := newFixtureWithPeer(t, 1800, &third)
	ctx, cancel := context.WithTimeout(t.Context(), 350*time.Second)
	defer cancel()

	type holder struct {
		id, endpoint, directory string
		authority               []byte
		worker                  *worker.Worker
		down                    atomic.Bool
	}
	holders := make([]*holder, 0, copies+1)
	var accepted sync.Map
	var switched atomic.Bool
	var reused, resent atomic.Int64
	for k, certificate := range []tls.Certificate{f.destination, f.replicaCertificate, third}[:copies+1] {
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		must(t, err)
		h := &holder{id: peer.Identity(leaf), directory: filepath.Join(f.base, "route-holder-"+string(rune('a'+k)))}
		grant := f.grant
		grant.Ingress = h.id
		h.authority, err = ingress.SignAuthority(grant, f.ownerSigner)
		must(t, err)
		h.worker, err = worker.Open(worker.Options{Directory: h.directory, Node: h.id, Owner: f.b.Local.Owner, Certificate: certificate, Roots: f.roots, Initialize: true})
		must(t, err)
		t.Cleanup(func() { h.worker.Close() })
		handler := func(out http.ResponseWriter, req *http.Request) {
			if h.down.Load() {
				http.Error(out, "holder unavailable", http.StatusServiceUnavailable)
				return
			}
			if copies == 2 && req.Method == http.MethodPut {
				path := req.URL.Path
				if strings.Contains(path, "/imports/") || strings.Contains(path, "/objects/") {
					id := path[strings.LastIndex(path, "/")+1:]
					if !switched.Load() && k == 0 {
						accepted.Store(id, true)
					} else if switched.Load() {
						if _, old := accepted.Load(id); old && k == copies && strings.Contains(path, "/imports/") {
							reused.Add(1)
						}
						if _, old := accepted.Load(id); old && strings.Contains(path, "/objects/") {
							resent.Add(1)
						}
					}
				}
			}
			h.worker.ServeHTTP(out, req)
		}
		if k == 0 {
			h.endpoint = f.server.URL
			f.intercept = func(out http.ResponseWriter, req *http.Request) bool { handler(out, req); return true }
		} else {
			server := httptest.NewUnstartedServer(http.HandlerFunc(handler))
			server.TLS, err = peer.AuthenticatedServerTLS(certificate, f.roots, h.id)
			must(t, err)
			server.StartTLS()
			t.Cleanup(server.Close)
			h.endpoint = server.URL
		}
		holders = append(holders, h)
	}
	planner, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	sourceID := f.grant.Source
	nodes := []policy.Node{{ID: sourceID, Class: "trusted"}}
	var targets []string
	var edges []policy.Edge
	for _, h := range holders {
		targets = append(targets, h.id)
		nodes = append(nodes, policy.Node{ID: h.id, Class: "trusted", Endpoint: h.endpoint})
		edges = append(edges, policy.Edge{From: sourceID, To: h.id, Mode: "push"})
		if copies == 2 {
			for _, other := range holders {
				if h != other {
					edges = append(edges, policy.Edge{From: h.id, To: other.id, Mode: "pull"})
				}
			}
		}
	}
	for _, h := range holders {
		domain := control.Domain{Trust: f.grant.Trust, Planner: planner, Placement: policy.Placement{
			Domain: f.grant.Trust.Domain, AllowedClasses: []string{"trusted"}, Holders: targets, Transit: []string{sourceID}, Edges: edges,
		}}
		if copies == 2 {
			for _, other := range holders {
				if h != other {
					domain.CaptureStagingPeers = append(domain.CaptureStagingPeers, other.id)
				}
			}
		}
		cfg := control.Config{
			Format: control.SettlementConfigFormat, Node: h.id, Revision: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix,
			Limits: control.Limits{Parallel: 2, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20},
			Nodes:  nodes, Domains: []control.Domain{domain}, Ingress: []json.RawMessage{h.authority},
		}
		raw, err := control.Sign(cfg, f.ownerSigner)
		must(t, err)
		must(t, h.worker.Accept(ctx, raw))
		runCaptureWorker(t, ctx, h.worker)
	}

	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "receiver-route-agent")
	f.b.Profile.MinimumCopies, f.b.Profile.CopyTargets = copies, targets
	f.b.ActiveFailover, f.b.Standby = true, copies == 1
	selection := func(h *holder) *CompanionIngress {
		file := filepath.Join(h.directory, "source-authority.json")
		must(t, os.WriteFile(file, h.authority, 0600))
		return &CompanionIngress{Endpoint: h.endpoint, AuthorityFile: file}
	}
	f.b.Companion = selection(holders[1])
	if copies == 2 {
		f.b.Reserve = selection(holders[2])
	}
	payload := bytes.Repeat([]byte("preserve the bytes already accepted by the surviving receiver"), 512)
	must(t, os.WriteFile(filepath.Join(f.tree, "route-input.bin"), payload, 0640))
	f.a, err = Open(ctx, f.b, true)
	must(t, err)
	must(t, f.a.Next(ctx))
	before, err := f.a.Status(ctx)
	must(t, err)
	if before.Phase != "PREPARING" || !slices.Equal(before.Receivers, targets[:copies]) {
		t.Fatal("initial route differs", before)
	}

	crash := errors.New("stop after persisting replacement")
	failed := holders[copies-1]
	f.a.Fault = func(point string) error {
		switch point {
		case "source-file-durable":
			failed.down.Store(true)
			return ingress.ErrUnavailable
		case "source-agent-receiver-route-durable":
			switched.Store(true)
			return crash
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, crash) {
		t.Fatal("did not switch after durable capture", err)
	}
	want := slices.Clone(targets[:copies])
	want[copies-1] = holders[copies].id
	f.reopen(t)
	after, err := f.a.Status(ctx)
	must(t, err)
	if after.Operation != before.Operation || after.Phase != "ACTIVE" || after.Job != nil ||
		after.Pending == nil || after.Pending.Action != "PREPARE_RECEIVER_ROUTE" ||
		!slices.Equal(after.Receivers, want) || !slices.Equal(after.Superseded, before.Receivers) {
		t.Fatal("signed replacement did not survive restart", after)
	}
	sealed := errors.New("stop before publication")
	f.a.Fault = func(point string) error {
		if point == "source-catalog-durable" {
			return sealed
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, sealed) {
		t.Fatal("replacement did not seal a catalog", err)
	}
	finalRoute, err := f.a.Status(ctx)
	must(t, err)
	if finalRoute.Job == nil || finalRoute.Job.Phase != "SEALED" || !slices.Equal(finalRoute.Receivers, want) {
		t.Fatal("unexpected route at seal", finalRoute)
	}
	f.a.Fault = nil
	for attempt := 0; attempt < 4; attempt++ {
		err = f.a.Run(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil || !receiverUnavailable(err) {
			t.Fatal("replacement publication failed", err)
		}
		t.Logf("retry publication after bounded transport error: %v", err)
	}
	must(t, err)
	raw, err := f.a.Checkpoint(ctx)
	must(t, err)
	c, err := capture.VerifyCheckpoint(raw, f.grant.Trust)
	must(t, err)
	if c.Receipt.Ingress != want[0] || len(c.Copies) != copies || c.Sequence != 1 || c.Generation != finalRoute.Job.Generation {
		t.Fatal("incorrect published copies", c)
	}
	if copies == 2 && (reused.Load() == 0 || resent.Load() != 0) {
		t.Fatal("replacement did not reuse the survivor's accepted objects", reused.Load(), resent.Load())
	}
	for _, h := range holders {
		replica := filepath.Join(worker.DomainDirectory(h.directory, f.grant.Trust), "replica")
		if h == failed {
			r, err := generation.Open(replica, f.grant.Trust, false)
			must(t, err)
			inventory, err := r.Inventory(ctx)
			must(t, err)
			must(t, r.Close())
			if len(inventory) != 0 {
				t.Fatal("superseded receiver published a catalog", inventory)
			}
			continue
		}
		if !slices.ContainsFunc(c.Copies, func(copy capture.CopyReceipt) bool { return copy.Target == h.id }) {
			t.Fatal("missing independently verified copy", h.id)
		}
		out := filepath.Join(h.directory, "route-restored")
		_, err = generation.RecoverMaterialized(ctx, replica, c.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, err)
		got, err := os.ReadFile(filepath.Join(out, "route-input.bin"))
		must(t, err)
		if !bytes.Equal(got, payload) {
			t.Fatal("restore differs", h.id)
		}
	}
}
