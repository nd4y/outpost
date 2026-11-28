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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/worker"
)

func TestSourceWaitsForSignedSecondCopyAcrossOutboundOnlyRelay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	leaf, e := x509.ParseCertificate(f.replicaCertificate.Certificate[0])
	must(t, e)
	replicaID := peer.Identity(leaf)
	collector, e := worker.Open(worker.Options{Directory: filepath.Join(f.base, "collector"), Node: f.grant.Ingress, Owner: f.b.Local.Owner, Certificate: f.destination, Roots: f.roots, Initialize: true})
	must(t, e)
	t.Cleanup(func() { collector.Close() })
	copyNode, e := worker.Open(worker.Options{Directory: filepath.Join(f.base, "copy-node"), Node: replicaID, Owner: f.b.Local.Owner, Certificate: f.replicaCertificate, Roots: f.roots, Initialize: true})
	must(t, e)
	t.Cleanup(func() { copyNode.Close() })
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool { collector.ServeHTTP(out, r); return true }
	g := observation.Grant{Format: observation.GrantFormat, Trust: f.grant.Trust, Reader: f.grant.Source, Collector: f.grant.Ingress, Targets: []string{replicaID}, Epoch: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix, MaxAgeSeconds: 3600}
	grant, e := observation.SignGrant(g, f.ownerSigner)
	must(t, e)
	planner, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	rule := control.Replication{Domain: f.grant.Trust.Domain, From: f.grant.Ingress, To: replicaID, Mode: "pull", Epoch: 1, PeerRevision: 1}
	d := control.Domain{Trust: f.grant.Trust, Planner: planner, Placement: policy.Placement{Domain: f.grant.Trust.Domain, AllowedClasses: []string{"trusted", "untrusted"}, Holders: []string{f.grant.Ingress, replicaID}, Edges: []policy.Edge{{From: f.grant.Ingress, To: replicaID, Mode: "pull"}}}}
	d.Placement.Transit = []string{f.grant.Source}
	d.Placement.Edges = append(d.Placement.Edges, policy.Edge{From: f.grant.Source, To: f.grant.Ingress, Mode: "push"})
	cfg := control.Config{Format: control.Format, Node: f.grant.Ingress, Revision: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix, Limits: control.Limits{Parallel: 2, AttemptMillis: 5000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20}, Nodes: []policy.Node{{ID: f.grant.Source, Class: "trusted"}, {ID: f.grant.Ingress, Class: "trusted", Endpoint: f.b.Endpoint}, {ID: replicaID, Class: "untrusted"}}, Domains: []control.Domain{d}, Replication: []control.Replication{rule}, Observations: []json.RawMessage{grant}, Ingress: []json.RawMessage{f.authority}}
	raw, e := control.Sign(cfg, f.ownerSigner)
	must(t, e)
	must(t, collector.Accept(ctx, raw))
	cfg.Node = replicaID
	cfg.Ingress = nil
	raw, e = control.Sign(cfg, f.ownerSigner)
	must(t, e)
	must(t, copyNode.Accept(ctx, raw))
	startWorker := func(w *worker.Worker) func() {
		run, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- w.Run(run) }()
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
				t.Fatal("worker did not stop")
			}
		}
		t.Cleanup(stop)
		return stop
	}
	stopCollector := startWorker(collector)
	waitReady := func(w *worker.Worker) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			s, e := w.Status(ctx)
			if e == nil && s.Phase == "ACTIVE" {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("worker not ready")
	}
	waitReady(collector)
	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "agent-two-copies")
	f.b.Profile.MinimumCopies = 2
	f.b.Profile.CopyTargets = append(f.b.Profile.CopyTargets, replicaID)
	f.b.ObservationFile = filepath.Join(f.base, "observation-grant.json")
	must(t, os.WriteFile(f.b.ObservationFile, grant, 0600))
	f.a, e = Open(ctx, f.b, true)
	must(t, e)
	must(t, f.a.Next(ctx))
	if e = f.a.Run(ctx); !errors.Is(e, capture.ErrCopies) {
		t.Fatal("source did not wait for second copy", e)
	}
	s, e := f.a.Status(ctx)
	must(t, e)
	if s.Job == nil || s.Job.Phase != "WAITING_COPIES" {
		t.Fatal("source view released early", s)
	}
	if _, e = f.a.Checkpoint(ctx); e == nil {
		t.Fatal("checkpoint published before copy threshold")
	}
	f.reopen(t)
	stopCopy := startWorker(copyNode)
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		e = f.a.Run(ctx)
		if e == nil {
			break
		}
		if !errors.Is(e, capture.ErrCopies) && !errors.Is(e, observation.ErrPending) {
			t.Fatal(e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	must(t, e)
	checkpoint, e := f.a.Checkpoint(ctx)
	must(t, e)
	c, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	if len(c.Copies) != 2 {
		t.Fatal("wrong independent copy count", len(c.Copies))
	}
	var retained []byte
	for _, copy := range c.Copies {
		if copy.Target == replicaID {
			retained = []byte(copy.SignedObservation)
		}
	}
	p, e := observation.VerifyProof(retained, grant, f.b.Local.Owner, c.Generation, time.Now())
	must(t, e)
	if p.Target != replicaID {
		t.Fatal("missing replica evidence")
	}
	stopCopy()
	stopCollector()
	expected, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	must(t, os.Remove(filepath.Join(f.tree, "private.bin")))
	out := filepath.Join(f.base, "second-copy-restore")
	_, e = generation.RecoverMaterialized(ctx, filepath.Join(worker.DomainDirectory(filepath.Join(f.base, "copy-node"), f.grant.Trust), "replica"), c.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "private.bin"))
	must(t, e)
	if !bytes.Equal(got, expected) {
		t.Fatal("independent second copy recovery mismatch")
	}
}
