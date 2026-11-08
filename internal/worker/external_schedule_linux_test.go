package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestWorkerScheduledExternalAuditDetectsLossAndResumesAfterRestart(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	bindFixture(t, f, w)
	ctx := context.Background()
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.ExternalAuditIntervalSeconds = 4
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	target := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
		Logins: map[string]teststore.Login{w.node: {Secret: "isolated-cloud-secret"}}})
	p := storage.Profile{Kind: "webdav", Endpoint: target.Endpoint(), Namespace: target.Options.Namespace, MaxObjectBytes: 64 << 10,
		Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
	f.domain.Placement.Targets = []string{p.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return storage.New(p, storage.Credentials{Access: w.node, Secret: target.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, target.Roots)
	}
	replica, err := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	worker := upload.Worker{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
	operation := storage.Hash([]byte("scheduled-external"))
	raw, err := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: operation, Profile: p, AllowExternal: true,
		AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{worker}, StartMillis: time.Now().UnixMilli(), ExpiresUnix: time.Now().Add(time.Minute).Unix(), SlotMillis: 1000}, planner)
	must(t, err)
	plan, err := upload.Verify(raw, upload.Authority{Generation: f.domain.Trust, Planner: pub})
	must(t, err)
	job := control.Job{Operation: operation, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: raw}
	f.config(t, 0, []control.Job{job})
	stop := start(t, w)
	wait(t, func() bool { return complete(w, operation) })
	var first ExternalAuditStatus
	wait(t, func() bool {
		first, err = w.ScheduledExternalAuditStatus(ctx, operation)
		return err == nil && first.State == "VERIFIED_CIPHERTEXT"
	})
	if first.Receipt == nil || first.Receipt.Generation != f.generation || first.Receipt.Target != p.ID() {
		t.Fatal("wrong scheduled proof", first)
	}
	status, err := w.Status(ctx)
	must(t, err)
	original := bytes.Clone(status.Jobs[operation].Receipt)
	writes := target.Snapshot().Writes
	key := "part-" + plan.Blobs[0].Parts[0].ID
	path := target.Path(key)
	part, err := os.ReadFile(path)
	must(t, err)
	must(t, os.Remove(path))
	wait(t, func() bool {
		report, err := w.ScheduledExternalAuditStatus(ctx, operation)
		return err == nil && report.State == "MISSING" && report.Receipt == nil
	})
	stop()
	reopened, err := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots, Resolve: w.resolve, Guard: w.guard})
	must(t, err)
	defer reopened.Close()
	historical, err := reopened.ScheduledExternalAuditStatus(ctx, operation)
	must(t, err)
	if historical.State != "MISSING" {
		t.Fatal("restart erased the last failed audit", historical)
	}
	// Independent fixture repair. The scheduled auditor never writes to storage.
	must(t, os.WriteFile(path, part, 0600))
	stop = start(t, reopened)
	var next ExternalAuditStatus
	wait(t, func() bool {
		next, err = reopened.ScheduledExternalAuditStatus(ctx, operation)
		return err == nil && next.State == "VERIFIED_CIPHERTEXT" && next.Receipt != nil && next.Receipt.ObservedUnix > first.Receipt.ObservedUnix
	})
	stop()
	status, err = reopened.Status(ctx)
	must(t, err)
	if !reflect.DeepEqual(writes, target.Snapshot().Writes) || !bytes.Equal(original, status.Jobs[operation].Receipt) || next.Window != first.Window {
		t.Fatal("scheduled check touched target/history or accumulated another window")
	}
	f.domain.ExternalAuditIntervalSeconds = 0
	f.cfg.Revision++
	f.config(t, 0, []control.Job{job})
	before := target.Snapshot().Requests
	if _, err = reopened.ScheduledExternalAuditStatus(ctx, operation); !errors.Is(err, ErrDenied) || target.Snapshot().Requests != before {
		t.Fatal("disabled schedule still reports current proof", err)
	}
}
