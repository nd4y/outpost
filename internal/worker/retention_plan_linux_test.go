package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerExecutesStagedRetentionPlan(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.AttemptMillis = 60000
	f.domain.RetirementMinimumCopies = 1
	f.cfg.Nodes = f.cfg.Nodes[:2]
	f.domain.Placement.Holders = f.domain.Placement.Holders[:2]
	f.domain.Placement.Edges = nil
	ctx := context.Background()
	retiring, survivor := f.nodes[0], f.nodes[1]
	r, head := maintenanceReplica(t, f)
	trust := f.domain.Trust

	survivorDir := filepath.Join(DomainDirectory(survivor.dir, trust), "replica")
	must(t, os.MkdirAll(survivorDir, 0700))
	copy, e := generation.Open(survivorDir, trust, true)
	must(t, e)
	defer copy.Close()
	catalog, e := r.Catalog(ctx, f.generation)
	must(t, e)
	_, e = copy.Receive(ctx, catalog, func(ref generation.Object) ([]byte, error) {
		return r.ReadObject(ctx, f.generation, ref)
	})
	must(t, e)

	id := func(s string) string { return storage.Hash([]byte(s)) }
	cert, serviceID := f.ca.node(t)
	signer := cert.PrivateKey.(ed25519.PrivateKey)
	registry, e := management.Open(management.Options{Directory: filepath.Join(f.base, "retention-management"), Owner: retiring.owner, Signer: signer, Initialize: true})
	must(t, e)
	defer registry.Close()
	enrolled := workerEnrollment(t, f, 0)
	enrollment, e := management.VerifyEnrollment(enrolled, retiring.owner)
	must(t, e)
	tenant := enrollment.Tenant
	scope := []management.Scope{{Tenant: tenant, Domain: trust.Domain}}
	owner := management.Principal{Actor: id("owner"), Roles: []string{"owner"}, Scopes: scope}
	handler, e := management.Handler(registry, management.HTTPOptions{Principals: []management.Principal{owner},
		Origin: "https://management.invalid", Concurrency: 2, Timeout: time.Second, ReportMaxAge: time.Minute})
	must(t, e)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.ca.pool}
	server.StartTLS()
	defer server.Close()
	enrollments := make([][]byte, 2)
	for i, w := range f.nodes[:2] {
		enrollments[i] = workerEnrollment(t, f, i)
		_, e = registry.ApplyEnrollment(ctx, owner, id("enroll-"+w.node), "INITIAL_ENROLLMENT", enrollments[i], 0)
		must(t, e)
	}
	type participant struct {
		worker    *Worker
		principal management.Principal
		authority []byte
		reporter  *Reporter
		client    *management.ReportClient
		enrolled  []byte
	}
	configure := func(index int, kinds []string) participant {
		t.Helper()
		w := f.nodes[index]
		enrolled := enrollments[index]
		cfg := f.cfg
		cfg.Node, cfg.Domains = w.node, []control.Domain{f.domain}
		authority, e := command.SignAuthority(command.Authority{
			Format: command.AuthorityFormat, Service: signer.Public().(ed25519.PublicKey), Node: w.node, Tenant: tenant, Domain: trust.Domain,
			Repository: trust.Repository, WriterEpoch: trust.Epoch, AuthorityEpoch: 1, Kinds: kinds,
			NotBefore: cfg.NotBefore, ExpiresUnix: cfg.ExpiresUnix,
		}, f.owner)
		must(t, e)
		cfg.Commands = []json.RawMessage{authority}
		signed, e := control.Sign(cfg, f.owner)
		must(t, e)
		input := management.SignedMutation{Operation: id("config-" + w.node), Reason: "POLICY_CHANGE", Document: signed}
		preview, e := registry.PreviewConfiguration(ctx, owner, tenant, w.node, input)
		if e != nil {
			t.Fatalf("preview participant %d: %v", index, e)
		}
		input.PreviewDigest = preview.CandidateDigest
		_, e = registry.ApplyConfiguration(ctx, owner, tenant, w.node, input)
		must(t, e)
		must(t, w.Accept(ctx, signed))
		reporter, e := w.OpenReporter(ctx, serviceID, trust.Domain, enrolled, true)
		must(t, e)
		t.Cleanup(func() { reporter.Close() })
		client, e := management.NewReportClient(server.URL, serviceID, w.node, w.cert, f.ca.pool, 5*time.Second)
		must(t, e)
		t.Cleanup(client.Close)
		return participant{worker: w, principal: management.Principal{Actor: w.node, Roles: []string{"node"}, Scopes: scope},
			authority: authority, reporter: reporter, client: client, enrolled: enrolled}
	}
	target := configure(0, []string{"maintenance", "retention"})
	holder := configure(1, []string{"retention"})

	now := time.Now().Unix()
	op, holdOp := id("retirement"), id("hold")
	status, e := r.Status(ctx)
	must(t, e)
	_, e = registry.RegisterRetentionPlan(ctx, owner, tenant, trust.Domain, management.RetentionDraftRequest{
		Format: management.RetentionPlanRequestFormat, HoldCommands: []string{holdOp},
		Preview: generation.Permit{Format: generation.PermitWindowFormat, Domain: trust.Domain, Repository: trust.Repository,
			Epoch: trust.Epoch, Revision: status.Revision, Operation: op, Retire: []string{f.generation},
			Window: &generation.PermitWindow{Node: retiring.node, StartUnix: now, ExpiresUnix: now + 300}},
	})
	must(t, e)
	plan := func(expected string) management.RetentionPlanStatus {
		t.Helper()
		p, e := registry.RetentionPlanStatus(ctx, owner, tenant, trust.Domain, op, time.Minute)
		must(t, e)
		if p.State != expected {
			t.Fatalf("plan state = %s, want %s", p.State, expected)
		}
		return p
	}
	request := func(p participant, operation, kind string) command.Request {
		return command.Request{Operation: operation, Reason: "OWNER_MAINTENANCE", Tenant: tenant, Domain: trust.Domain,
			Kind: kind, ExpectedRevision: f.cfg.Revision, Authority: p.authority, ExpiresUnix: now + 300}
	}
	protection := func(p participant, operation string, grant generation.RetentionProtection) command.Request {
		t.Helper()
		grant.Format, grant.Node, grant.Domain = generation.RetentionProtectionFormat, p.worker.node, trust.Domain
		grant.Repository, grant.Epoch = trust.Repository, trust.Epoch
		grant.NotBefore, grant.ExpiresUnix = now-1, now+180
		req := request(p, operation, "retention")
		var e error
		req.RetentionGrant, e = generation.SignRetentionProtection(grant, f.maintenance)
		must(t, e)
		return req
	}
	stage := func(p participant, req command.Request) {
		t.Helper()
		_, e := registry.StageRetentionStep(ctx, owner, tenant, trust.Domain, op,
			management.RetentionStepRequest{Format: management.RetentionStepRequestFormat, Node: p.worker.node, Command: req})
		must(t, e)
	}
	reconcile := func(operation, expected string) {
		t.Helper()
		result, e := registry.Reconcile(ctx, []management.Principal{owner}, 0, 16)
		must(t, e)
		for _, item := range result.Items {
			if item.Operation == operation && item.State == expected {
				return
			}
		}
		t.Fatalf("operation %s did not reach %s: %+v", operation, expected, result.Items)
	}
	run := func(p participant, operation string) CommandRecord {
		t.Helper()
		items, _, e := registry.Commands(ctx, p.principal, tenant, p.worker.node, 0, 2)
		must(t, e)
		if len(items) != 1 {
			t.Fatalf("expected one queued operation, got %d", len(items))
		}
		raw := items[0].Document
		env, _, e := command.VerifyEnvelope(raw, p.worker.owner)
		must(t, e)
		if env.Request.Operation != operation {
			t.Fatal("unexpected operation", env.Request.Operation)
		}
		ack, e := p.worker.ExecuteCommand(ctx, raw)
		must(t, e)
		if len(ack) != 0 {
			t.Fatal("worker admission claimed an outcome")
		}
		stop := start(t, p.worker)
		var result CommandRecord
		waitFor(t, 60*time.Second, func() bool {
			result = actionRecord(t, p.worker, raw)
			return len(result.Ack) != 0
		})
		stop()
		if got := verifyWorkerAck(t, p.worker, raw, result.Ack); got.State != "COMPLETE" {
			t.Fatal("worker did not complete command", got)
		}
		_, e = registry.AcknowledgeCommand(ctx, p.principal, tenant, p.worker.node, operation, result.Ack)
		must(t, e)
		snapshot, e := p.worker.ManagementSnapshot(ctx, p.enrolled, trust.Domain)
		must(t, e)
		_, e = p.reporter.Enqueue(ctx, snapshot)
		must(t, e)
		_, e = p.reporter.Deliver(ctx, p.client)
		must(t, e)
		return result
	}

	closeOp := id("close")
	stage(target, protection(target, closeOp, generation.RetentionProtection{Operation: op, Action: "CLOSE"}))
	reconcile(closeOp, "WAITING_PREREQUISITE")
	hold := generation.RetentionProtection{Operation: id("hold-grant"), Action: "HOLD", Generation: f.generation,
		Retirement: &generation.RetirementBinding{Node: retiring.node, Operation: op}}
	stage(holder, protection(holder, holdOp, hold))
	reconcile(holdOp, "PUBLISHED")
	held := run(holder, holdOp)
	witness, e := generation.VerifyRetentionProtectionReceipt(held.Result, survivor.node)
	must(t, e)
	ready := plan("READY_TO_SIGN")
	if ready.Draft == nil || ready.Draft.Permit == nil {
		t.Fatal("real worker hold did not produce a signing draft")
	}
	retire := request(target, op, "maintenance")
	retire.MaintenancePermit, e = generation.SignPermit(*ready.Draft.Permit, f.maintenance)
	must(t, e)
	stage(target, retire)
	reconcile(op, "PUBLISHED")
	plan("RETIREMENT_QUEUED")
	must(t, r.VerifyComplete(ctx, f.generation))
	run(target, op)
	outcome, e := r.MaintenanceResult(ctx, op)
	must(t, e)
	if outcome.AbsentCatalogs != 1 || outcome.AbsentObjects < 1 {
		t.Fatal("worker did not remove the retired catalog and its unshared objects", outcome)
	}
	if e = r.VerifyComplete(ctx, f.generation); !errors.Is(e, generation.ErrIncomplete) {
		t.Fatal("retired generation remained complete", e)
	}
	must(t, r.VerifyComplete(ctx, head))
	must(t, copy.VerifyComplete(ctx, f.generation))
	plan("RETIREMENT_REPORTED_COMPLETE")

	reconcile(closeOp, "PUBLISHED")
	closed := run(target, closeOp)
	closure, e := generation.VerifyRetentionProtectionReceipt(closed.Result, retiring.node)
	must(t, e)
	plan("CLOSED_AWAITING_RELEASES")
	releaseOp := id("release")
	hold.Action, hold.HoldDigest, hold.Closure = "RELEASE", witness.HoldDigest, &closure
	stage(holder, protection(holder, releaseOp, hold))
	reconcile(releaseOp, "PUBLISHED")
	run(holder, releaseOp)
	settled := plan("SETTLED")
	if len(settled.Holds) != 1 || settled.Holds[0].State != "RELEASED" {
		t.Fatal("survivor hold did not settle", settled.Holds)
	}
	must(t, copy.VerifyComplete(ctx, f.generation))
}
