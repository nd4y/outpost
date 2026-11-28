package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func workerEnrollment(t *testing.T, f *fixture, index int) []byte {
	t.Helper()
	w := f.nodes[index]
	class := "trusted"
	if index == 2 {
		class = "untrusted"
	}
	raw, e := management.SignEnrollment(management.Enrollment{Format: management.EnrollmentFormat, Tenant: storage.Hash([]byte("report-tenant")), Node: w.node, PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), Class: class, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Domains: []management.DomainAdmission{{Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: f.domain.Trust.Epoch}}}, f.owner)
	must(t, e)
	return raw
}
func TestWorkerReportsActualInventoryJobsAndVolumeOverHTTPS(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w := f.nodes[0]
	cfg := f.config(t, 0, nil)
	must(t, w.admit(context.Background(), cfg))
	ctx := context.Background()
	raw := workerEnrollment(t, f, 0)
	grant, e := management.VerifyEnrollment(raw, f.owner.Public().(ed25519.PublicKey))
	must(t, e)
	cert, target := f.ca.node(t)
	registry, e := management.Open(management.Options{Directory: filepath.Join(f.base, "management"), Owner: f.owner.Public().(ed25519.PublicKey), Signer: cert.PrivateKey.(ed25519.PrivateKey), Initialize: true})
	must(t, e)
	defer registry.Close()
	p := management.Principal{Actor: storage.Hash([]byte("operator")), Roles: []string{"owner"}, Scopes: []management.Scope{{Tenant: grant.Tenant, Domain: f.domain.Trust.Domain}}}
	_, e = registry.ApplyEnrollment(ctx, p, storage.Hash([]byte("enroll-worker")), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	handler, e := management.Handler(registry, management.HTTPOptions{Principals: []management.Principal{p}, Origin: "https://management.invalid", Concurrency: 2, Timeout: time.Second, ReportMaxAge: time.Minute})
	must(t, e)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.ca.pool}
	server.StartTLS()
	defer server.Close()
	client, e := management.NewReportClient(server.URL, target, w.node, w.cert, f.ca.pool, time.Second)
	must(t, e)
	defer client.Close()
	reporter, e := w.OpenReporter(ctx, target, f.domain.Trust.Domain, raw, true)
	must(t, e)
	defer reporter.Close()
	snapshot, e := w.ManagementSnapshot(ctx, raw, f.domain.Trust.Domain)
	must(t, e)
	if snapshot.InventoryState != "OBSERVED" || len(snapshot.Generations) != 1 || snapshot.Generations[0].Generation != f.generation || snapshot.Generations[0].Status != "COMPLETE" || snapshot.Generations[0].Verification != "NONE" || snapshot.Generations[0].VerifiedUnix != 0 || snapshot.Generations[0].LogicalBytes != nil || snapshot.Space.Scope != "VOLUME" || snapshot.Space.AccountedBytes == nil || snapshot.Space.PhysicalBytes == nil || snapshot.Space.FreeBytes == nil || snapshot.Space.LogicalBytes != nil {
		t.Fatal("snapshot invented verification/size", snapshot)
	}
	_, e = reporter.Enqueue(ctx, snapshot)
	must(t, e)
	_, e = reporter.Deliver(ctx, client)
	must(t, e)
	view, e := registry.Report(ctx, p, grant.Tenant, w.node, f.domain.Trust.Domain, time.Minute)
	must(t, e)
	if view.InventoryState != "OBSERVED" || view.Sequence != 1 || view.ConfigurationRevision != cfg.Revision || len(view.Generations) != 1 || view.Generations[0].VerifiedUnix != 0 {
		t.Fatal("consumer differs from observation", view)
	}
	// Keep all actual worker job slots; a large bounded report must paginate in
	// the API instead of silently dropping everything after the first 256 jobs.
	must(t, w.update(ctx, func(s *Status) error {
		for i := 0; i < MaxJobs; i++ {
			op := storage.Hash([]byte(fmt.Sprint("report-job-", i)))
			j := control.Job{Operation: op, Executor: w.node, Kind: "pull", Domain: f.domain.Trust.Domain, Generation: f.generation, Peer: f.nodes[1].node}
			s.Jobs[op] = JobState{Job: j, Binding: binding(j), Phase: "QUEUED", UpdatedUnix: time.Now().Unix()}
		}
		return nil
	}))
	snapshot, e = w.ManagementSnapshot(ctx, raw, f.domain.Trust.Domain)
	must(t, e)
	if len(snapshot.Jobs) != MaxJobs || snapshot.Jobs[0].CompletedBytes != nil || snapshot.Jobs[0].TotalBytes != nil {
		t.Fatal("job truncation or fabricated progress")
	}
	before, e := w.Status(ctx)
	must(t, e)
	// Full telemetry cannot spend backup spool capacity or modify accepted jobs.
	if _, e = reporter.Enqueue(ctx, snapshot); e == nil {
		t.Fatal("fixture telemetry quota ignored")
	}
	after, e := w.Status(ctx)
	must(t, e)
	if len(after.Jobs) != len(before.Jobs) || after.Revision != before.Revision {
		t.Fatal("telemetry failure changed backup state")
	}
}

func TestWorkerReportingMissingReplicaIsUnavailableAndPolicyBound(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w := f.nodes[1]
	cfg := f.config(t, 1, nil)
	must(t, w.admit(context.Background(), cfg))
	ctx := context.Background()
	raw := workerEnrollment(t, f, 1)
	snapshot, e := w.ManagementSnapshot(ctx, raw, f.domain.Trust.Domain)
	must(t, e)
	if snapshot.InventoryState != "UNAVAILABLE" || len(snapshot.Generations) != 0 {
		t.Fatal("absent replica reported healthy-empty")
	}
	if _, e = os.Stat(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("report initialized replica", e)
	}
	grant, e := management.VerifyEnrollment(raw, w.owner)
	must(t, e)
	grant.Domains[0].Epoch++
	wrong, e := management.SignEnrollment(grant, f.owner)
	must(t, e)
	if _, e = w.ManagementSnapshot(ctx, wrong, f.domain.Trust.Domain); !errors.Is(e, management.ErrDenied) {
		t.Fatal("epoch boundary ignored", e)
	}
	cfg.Revision++
	signed, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, w.Accept(ctx, signed))
	if _, e = w.ManagementSnapshot(ctx, raw, f.domain.Trust.Domain); !errors.Is(e, management.ErrConflict) {
		t.Fatal("accepted config claimed already applied", e)
	}
}

func TestWorkerReportingSeparateHandleDoesNotReconcileActiveBackupReservation(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w := f.nodes[0]
	cfg := f.config(t, 0, nil)
	ctx := context.Background()
	must(t, w.admit(ctx, cfg))
	finish, e := w.budget.Reserve(ctx, "state/active-backup.json", 4096)
	must(t, e)
	defer func() { must(t, finish(false)) }()
	second, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer second.Close()
	raw := workerEnrollment(t, f, 0)
	reporter, e := second.OpenReporter(ctx, storage.Hash([]byte("report-target")), f.domain.Trust.Domain, raw, true)
	must(t, e)
	defer reporter.Close()
	if second.budget != nil || reporter.ownedBudget == nil {
		t.Fatal("reporting took ownership of execution budget")
	}
	bounded, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	snapshot, e := second.ManagementSnapshot(bounded, raw, f.domain.Trust.Domain)
	must(t, e)
	if snapshot.Space.ReservedBytes == nil || *snapshot.Space.ReservedBytes < 4096 {
		t.Fatal("active reservation absent", snapshot.Space)
	}
	state, e := w.budget.Status(ctx)
	must(t, e)
	if len(state.Pending) != 1 {
		t.Fatal("reporter reconciled another process reservation")
	}
}
