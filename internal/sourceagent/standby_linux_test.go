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

func TestSourceStandbySelectionIsDurableBeforeAdmission(t *testing.T) {
	t.Run("unavailable-while-planning", func(t *testing.T) { testStandby(t, false, http.StatusServiceUnavailable) })
	t.Run("unavailable-before-first-write", func(t *testing.T) { testStandby(t, true, http.StatusServiceUnavailable) })
	t.Run("metadata-capacity-while-planning", func(t *testing.T) { testStandby(t, false, http.StatusInsufficientStorage) })
}

func testStandby(t *testing.T, initiallyReady bool, refusal int) {
	t.Helper()
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	leaf, err := x509.ParseCertificate(f.replicaCertificate.Certificate[0])
	must(t, err)
	alternate := f.grant
	alternate.Ingress = peer.Identity(leaf)
	authority, err := ingress.SignAuthority(alternate, f.ownerSigner)
	must(t, err)
	dir := filepath.Join(f.base, "standby-worker")
	w, err := worker.Open(worker.Options{Directory: dir, Node: alternate.Ingress, Owner: f.b.Local.Owner, Certificate: f.replicaCertificate, Roots: f.roots, Initialize: true})
	must(t, err)
	t.Cleanup(func() { w.Close() })
	var ready, admitted, unexpected atomic.Int32
	var primaryReady, loseAdmissionReply atomic.Bool
	primaryReady.Store(initiallyReady)
	loseAdmissionReply.Store(true)
	w.Fault = func(point string) error {
		if point == "capture-intent-durable" && loseAdmissionReply.CompareAndSwap(true, false) {
			return errors.New("lost admission acknowledgement")
		}
		return nil
	}
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/readiness") {
			ready.Add(1)
			if primaryReady.Load() {
				var i ingress.Intent
				if json.NewDecoder(r.Body).Decode(&i) != nil {
					http.Error(out, "bad intent", http.StatusBadRequest)
					return true
				}
				_ = json.NewEncoder(out).Encode(map[string]any{"operation": i.Operation, "sequence": i.Sequence})
			} else {
				http.Error(out, "primary not ready", refusal)
			}
			return true
		}
		unexpected.Add(1)
		http.Error(out, "primary not selected", http.StatusForbidden)
		return true
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/intent") {
			admitted.Add(1)
		}
		w.ServeHTTP(out, r)
	}))
	server.TLS, err = peer.AuthenticatedServerTLS(f.replicaCertificate, f.roots, alternate.Ingress)
	must(t, err)
	server.StartTLS()
	t.Cleanup(server.Close)
	planner, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	cfg := control.Config{
		Format: control.SettlementConfigFormat, Node: alternate.Ingress, Revision: 1,
		NotBefore: alternate.NotBefore, ExpiresUnix: alternate.ExpiresUnix,
		Limits: control.Limits{Parallel: 2, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20},
		Nodes:  []policy.Node{{ID: alternate.Source, Class: "trusted"}, {ID: alternate.Ingress, Class: "trusted", Endpoint: server.URL}},
		Domains: []control.Domain{{Trust: alternate.Trust, Planner: planner, Placement: policy.Placement{
			Domain: alternate.Trust.Domain, AllowedClasses: []string{"trusted"}, Holders: []string{alternate.Ingress},
			Transit: []string{alternate.Source}, Edges: []policy.Edge{{From: alternate.Source, To: alternate.Ingress, Mode: "push"}},
		}}},
		Ingress: []json.RawMessage{authority},
	}
	raw, err := control.Sign(cfg, f.ownerSigner)
	must(t, err)
	must(t, w.Accept(ctx, raw))
	runCaptureWorker(t, ctx, w)
	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "standby-agent")
	f.b.Standby = true
	f.b.Companion = &CompanionIngress{Endpoint: server.URL, AuthorityFile: filepath.Join(f.base, "standby-authority.json")}
	f.b.Profile.CopyTargets = []string{f.grant.Ingress, alternate.Ingress}
	must(t, os.WriteFile(f.b.Companion.AuthorityFile, authority, 0600))
	payload := []byte("source with only the authorized standby available")
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), payload, 0600))
	f.a, err = Open(ctx, f.b, true)
	must(t, err)
	must(t, f.a.Next(ctx))
	state, err := f.a.Status(ctx)
	must(t, err)
	expected := alternate.Ingress
	if initiallyReady {
		expected = f.grant.Ingress
	}
	if state.Phase != "PREPARING" || state.Receiver != expected || ready.Load() != 1 || admitted.Load() != 0 {
		t.Fatal("receiver was not durably selected before admission", state, ready.Load(), admitted.Load())
	}
	primaryReady.Store(false)
	f.reopen(t)
	if err = f.a.Run(ctx); !errors.Is(err, ingress.ErrUnavailable) {
		t.Fatal("did not exercise a lost durable admission reply", err)
	}
	state, err = f.a.Status(ctx)
	must(t, err)
	if state.Phase != "ACTIVE" || state.Receiver != alternate.Ingress {
		t.Fatal("source did not preserve the receiver after a lost admission reply", state)
	}
	f.reopen(t)
	must(t, f.a.Run(ctx))
	checkpoint, err := f.a.Checkpoint(ctx)
	must(t, err)
	c, err := capture.VerifyCheckpoint(checkpoint, alternate.Trust)
	must(t, err)
	if c.Receipt.Ingress != alternate.Ingress || len(c.Copies) != 1 || admitted.Load() == 0 || unexpected.Load() != 0 {
		t.Fatal("restart changed the selected receiver or the configured threshold", c, unexpected.Load())
	}
	out := filepath.Join(f.base, "standby-restored")
	replica := filepath.Join(worker.DomainDirectory(dir, alternate.Trust), "replica")
	_, err = generation.RecoverMaterialized(ctx, replica, c.Generation, alternate.Trust, f.owner, generation.RecoverySelection{}, out)
	must(t, err)
	got, err := os.ReadFile(filepath.Join(out, "private.bin"))
	must(t, err)
	if !bytes.Equal(got, payload) {
		t.Fatal("standby restore differs")
	}
}
