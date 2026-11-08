package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestWorkerOwnerAdmitsMissingRepairAndSeparateCorruptCopyReplacement(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	w := f.nodes[0]
	bindFixture(t, f, w)
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	targets := map[string]*teststore.Server{}
	var holdAudit atomic.Bool
	auditRead := make(chan struct{})
	profile := func(kind string) storage.Profile {
		server := teststore.New(t, teststore.Options{Kind: kind, Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
			Logins: map[string]teststore.Login{w.node: {Secret: "isolated-cloud-secret"}}, Before: func(_ http.ResponseWriter, r *http.Request, _, _ string, _ []byte) bool {
				if r.Method == http.MethodGet && holdAudit.CompareAndSwap(true, false) {
					close(auditRead)
					<-r.Context().Done()
					return true
				}
				return false
			}})
		p := storage.Profile{Kind: kind, Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
		if kind == "s3" {
			p.Region = server.Options.Region
		}
		targets[p.ID()] = server
		return p
	}
	old, replacement := profile("s3"), profile("webdav")
	admitTarget := func(p storage.Profile) {
		f.cfg.Targets = append(f.cfg.Targets, control.Target{ID: p.ID(), Profile: p})
		f.domain.Placement.Targets = append(f.domain.Placement.Targets, p.ID())
		f.domain.Placement.CloudEdges = append(f.domain.Placement.CloudEdges, policy.CloudEdge{Node: w.node, Target: p.ID()})
	}
	admitTarget(old)
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, ok := targets[p.ID()]
		if !ok {
			return nil, ErrDenied
		}
		return storage.New(p, storage.Credentials{Access: w.node, Secret: s.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, s.Roots)
	}
	replicaPath := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	replica, err := generation.Open(replicaPath, f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	executor := upload.Worker{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
	job := func(name string, p storage.Profile) control.Job {
		t.Helper()
		op := storage.Hash([]byte(name))
		now := time.Now()
		plan, err := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: op, Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{executor}, StartMillis: now.UnixMilli(), ExpiresUnix: now.Add(time.Minute).Unix(), SlotMillis: 1000}, planner)
		must(t, err)
		return control.Job{Operation: op, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: plan}
	}
	first := job("external-initial", old)
	f.config(t, 0, []control.Job{first})
	stop := start(t, w)
	wait(t, func() bool { return complete(w, first.Operation) })
	window := ExternalAuditProfile{Format: ExternalAuditProfileFormat, Window: storage.Hash([]byte("retained-external-window")), MaxAgeSeconds: 3600}
	requests := targets[old.ID()].Snapshot().Requests
	if _, err := w.AuditExternal(ctx, first.Operation, window, true); !errors.Is(err, storage.ErrConflict) || targets[old.ID()].Snapshot().Requests != requests {
		t.Fatal("maintenance bypassed active execution lease", err)
	}
	status, err := w.Status(ctx)
	must(t, err)
	originalReceipt := bytes.Clone(status.Jobs[first.Operation].Receipt)
	plan, err := upload.Verify(first.Plan, upload.Authority{Generation: f.domain.Trust, Planner: pub})
	must(t, err)
	path := targets[old.ID()].Path("part-" + plan.Blobs[0].Parts[0].ID)
	healthy, err := os.ReadFile(path)
	must(t, err)
	must(t, os.Remove(path))
	reader, err := w.resolve(ctx, old)
	must(t, err)
	defer reader.Close()
	audit, err := reader.AuditGeneration(ctx, f.generation, f.domain.Trust)
	if !storage.Missing(err) || audit.State != "MISSING" {
		t.Fatal("missing dependency remained apparently healthy", audit, err)
	}
	repair := job("external-missing-repair", old)
	f.cfg.Revision++
	f.config(t, 0, []control.Job{repair})
	wait(t, func() bool { return complete(w, repair.Operation) })
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, healthy) {
		t.Fatal("owner-authorized repair did not restore exact part", err)
	}
	audit, err = reader.AuditGeneration(ctx, f.generation, f.domain.Trust)
	must(t, err)
	if audit.State != "VERIFIED_CIPHERTEXT" {
		t.Fatal("repaired target failed full fresh audit", audit)
	}
	corrupt := bytes.Clone(healthy)
	corrupt[0] ^= 1
	must(t, os.WriteFile(path, corrupt, 0600))
	conflict := job("external-corrupt-refusal", old)
	f.cfg.Revision++
	f.config(t, 0, []control.Job{conflict})
	wait(t, func() bool {
		s, err := w.Status(ctx)
		return err == nil && s.Jobs[conflict.Operation].Phase == "BLOCKED"
	})
	next := job("external-independent-replacement", replacement)
	proposed := f.cfg
	proposed.Revision++
	proposed.Node = w.node
	proposed.Domains = []control.Domain{f.domain}
	proposed.Jobs = []control.Job{next}
	if _, err := control.Sign(proposed, f.owner); !errors.Is(err, control.ErrDenied) {
		t.Fatal("new target used without an owner placement edge", err)
	}
	admitTarget(replacement)
	f.cfg.Revision++
	f.config(t, 0, []control.Job{next})
	wait(t, func() bool { return complete(w, next.Operation) })
	stop()
	status, err = w.Status(ctx)
	must(t, err)
	if !bytes.Equal(status.Jobs[first.Operation].Receipt, originalReceipt) || len(status.Jobs[conflict.Operation].Receipt) != 0 {
		t.Fatal("repair changed original evidence or certified corrupted data")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, corrupt) {
		t.Fatal("replacement touched corrupted canonical object", err)
	}
	must(t, replica.Close())
	must(t, os.Rename(replicaPath, replicaPath+"-unavailable"))
	backend, err := w.resolve(ctx, replacement)
	must(t, err)
	defer backend.Close()
	raw, err := backend.Catalog(ctx, f.generation, f.domain.Trust)
	must(t, err)
	owner := f.dataOwner
	owner.SigningKey = nil
	dest := filepath.Join(f.base, "replacement-restore")
	receipt, err := generation.RecoverCatalog(ctx, f.generation, raw, f.domain.Trust, owner, generation.RecoverySelection{}, backend.ReadBlob, dest)
	must(t, err)
	got, err := os.ReadFile(filepath.Join(dest, "dataset/данные.bin"))
	must(t, err)
	if !receipt.CheckpointMatch || !bytes.Equal(got, f.content) {
		t.Fatal("replacement cannot independently restore expected content")
	}
	reopened, err := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots, Resolve: w.resolve, Guard: w.guard})
	must(t, err)
	defer reopened.Close()
	requests = targets[replacement.ID()].Snapshot().Requests
	if _, err := reopened.AuditExternal(ctx, next.Operation, window, false); !errors.Is(err, os.ErrNotExist) || targets[replacement.ID()].Snapshot().Requests != requests {
		t.Fatal("missing audit window initialized without consent", err)
	}
	checked, err := reopened.AuditExternal(ctx, next.Operation, window, true)
	must(t, err)
	if checked.Generation != f.generation || checked.Target != replacement.ID() || checked.Window != window.Window {
		t.Fatal("audit lost exact retained binding", checked)
	}
	replayed, err := reopened.AuditExternal(ctx, next.Operation, window, false)
	must(t, err)
	if replayed.ObservedUnix != checked.ObservedUnix {
		t.Fatal("replayed window refreshed verification age", checked, replayed)
	}
	changed := window
	changed.MaxAgeSeconds--
	requests = targets[replacement.ID()].Snapshot().Requests
	if _, err := reopened.AuditExternal(ctx, next.Operation, changed, false); !errors.Is(err, storage.ErrConflict) || targets[replacement.ID()].Snapshot().Requests != requests {
		t.Fatal("changed audit binding reached target", err)
	}
	interrupted := window
	interrupted.Window = storage.Hash([]byte("revoked-audit-window"))
	holdAudit.Store(true)
	ended := make(chan error, 1)
	go func() {
		bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		proof, err := reopened.AuditExternal(bounded, next.Operation, interrupted, true)
		if proof.Format != "" {
			err = errors.New("withdrawn audit published a proof")
		}
		ended <- err
	}()
	select {
	case <-auditRead:
	case <-time.After(6 * time.Second):
		t.Fatal("replacement audit did not reach network")
	}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: old.ID()}}
	f.cfg.Revision++
	f.config(t, 0, nil)
	select {
	case err := <-ended:
		if !errors.Is(err, control.ErrInactive) {
			t.Fatal("policy replacement did not cancel audit", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("withdrawn audit did not join")
	}
	requests = targets[replacement.ID()].Snapshot().Requests
	if _, err := reopened.AuditExternal(ctx, next.Operation, window, false); !errors.Is(err, ErrDenied) || targets[replacement.ID()].Snapshot().Requests != requests {
		t.Fatal("withdrawn target allowed new audit", err)
	}
}
