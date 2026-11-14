package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerRetentionCommandReplaysOriginalProofAfterRestart(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.AttemptMillis = 60000
	f.endpoint(t, nil)
	w := f.nodes[0]
	ctx := context.Background()
	service, signer := key(t)
	enrolled := commandEnrollment(t, f)
	enrollment, e := management.VerifyEnrollment(enrolled, w.owner)
	must(t, e)
	trust := f.domain.Trust
	tenant := enrollment.Tenant
	scope := []management.Scope{{Tenant: tenant, Domain: trust.Domain}}
	owner := management.Principal{Actor: storage.Hash([]byte("owner")), Roles: []string{"owner"}, Scopes: scope}
	operator := management.Principal{Actor: storage.Hash([]byte("operator")), Roles: []string{"operator"}, Scopes: scope}
	node := management.Principal{Actor: w.node, Roles: []string{"node"}, Scopes: scope}
	registry, e := management.Open(management.Options{Directory: filepath.Join(f.base, "retention-management"), Owner: w.owner, Signer: signer, Initialize: true})
	must(t, e)
	defer registry.Close()
	_, e = registry.ApplyEnrollment(ctx, owner, storage.Hash([]byte("enroll")), "INITIAL_ENROLLMENT", enrolled, 0)
	must(t, e)
	cfg := f.cfg
	cfg.Node, cfg.Domains = w.node, []control.Domain{f.domain}
	cfg.Nodes = cfg.Nodes[:1]
	cfg.Domains[0].Placement.Holders = []string{w.node}
	cfg.Domains[0].Placement.Edges = nil
	authority, e := command.SignAuthority(command.Authority{
		Format: command.AuthorityFormat, Service: service, Node: w.node, Tenant: tenant, Domain: trust.Domain,
		Repository: trust.Repository, WriterEpoch: trust.Epoch, AuthorityEpoch: 1, Kinds: []string{"retention"},
		NotBefore: cfg.NotBefore, ExpiresUnix: cfg.ExpiresUnix,
	}, f.owner)
	must(t, e)
	cfg.Commands = []json.RawMessage{authority}
	config, e := control.Sign(cfg, f.owner)
	must(t, e)
	mutation := management.SignedMutation{Operation: storage.Hash([]byte("config")), Reason: "POLICY_CHANGE", Document: config}
	preview, e := registry.PreviewConfiguration(ctx, owner, tenant, w.node, mutation)
	must(t, e)
	mutation.PreviewDigest = preview.CandidateDigest
	_, e = registry.ApplyConfiguration(ctx, owner, tenant, w.node, mutation)
	must(t, e)
	must(t, w.Accept(ctx, config))

	now := time.Now().Unix()
	grant, e := generation.SignRetentionProtection(generation.RetentionProtection{
		Format: generation.RetentionProtectionFormat, Node: w.node, Domain: trust.Domain, Repository: trust.Repository,
		Epoch: trust.Epoch, Operation: storage.Hash([]byte("hold")), Generation: f.generation, Action: "HOLD",
		NotBefore: now - 60, ExpiresUnix: now + 180,
	}, f.maintenance)
	must(t, e)
	req := command.Request{Operation: storage.Hash([]byte("queue hold")), Reason: "OWNER_MAINTENANCE", Tenant: tenant,
		Domain: trust.Domain, Kind: "retention", ExpectedRevision: cfg.Revision, Authority: authority, ExpiresUnix: now + 180, RetentionGrant: grant}
	if _, e = registry.AdmitCommand(ctx, operator, tenant, w.node, req); !errors.Is(e, management.ErrDenied) {
		t.Fatal("operator gained retention authority", e)
	}
	_, e = registry.AdmitCommand(ctx, owner, tenant, w.node, req)
	must(t, e)
	items, _, e := registry.Commands(ctx, node, tenant, w.node, 0, 1)
	must(t, e)
	if len(items) != 1 {
		t.Fatal(items)
	}
	raw := items[0].Document
	_, e = w.ExecuteCommand(ctx, raw)
	must(t, e)
	lost := make(chan struct{})
	var once sync.Once
	w.Fault = func(point string) error {
		if point != "worker-command-retention-result-durable" {
			return nil
		}
		once.Do(func() { close(lost) })
		return errors.New("lost result after durable retention write")
	}
	stop := start(t, w)
	select {
	case <-lost:
	case <-time.After(45 * time.Second):
		stop()
		t.Fatal("retention action did not reach the durable boundary")
	}
	stop()
	if op := actionRecord(t, w, raw); len(op.Ack) > 0 {
		t.Fatal("lost result received an acknowledgement", op)
	}
	original, e := w.ApplyRetentionProtection(ctx, trust.Domain, grant)
	must(t, e)
	proof, e := json.Marshal(original)
	must(t, e)
	if original.State != "HELD" || original.GrantDigest != storage.Hash(grant) {
		t.Fatal(original)
	}

	reopened, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer reopened.Close()
	stop = start(t, reopened)
	var record CommandRecord
	waitFor(t, 60*time.Second, func() bool {
		record = actionRecord(t, reopened, raw)
		return len(record.Ack) > 0
	})
	stop()
	ack := verifyWorkerAck(t, reopened, raw, record.Ack)
	if ack.State != "COMPLETE" || !bytes.Equal(record.Result, proof) {
		t.Fatal("restart changed original proof", ack)
	}
	_, e = registry.AcknowledgeCommand(ctx, node, tenant, w.node, req.Operation, record.Ack)
	must(t, e)
	snapshot, e := reopened.ManagementSnapshot(ctx, enrolled, trust.Domain)
	must(t, e)
	reporter, e := reopened.OpenReporter(ctx, command.Identity(service), trust.Domain, enrolled, true)
	must(t, e)
	defer reporter.Close()
	report, e := reporter.Enqueue(ctx, snapshot)
	must(t, e)
	historical, e := management.VerifyReport(report, enrollment, time.Now())
	must(t, e)
	renewed := enrollment
	renewed.Domains = append([]management.DomainAdmission(nil), enrollment.Domains...)
	renewed.Domains[0].Epoch++
	renewed.Revision++
	historical.EnrollmentRevision = renewed.Revision
	_, e = management.SignReport(historical, renewed, w.cert.PrivateKey.(ed25519.PrivateKey), time.Now())
	must(t, e)
	invalid := historical
	original.ObservedUnix--
	bad, e := json.Marshal(original)
	must(t, e)
	invalid.Commands[0].RetentionProof = bad
	invalid.Commands[0].ResultDigest = storage.Hash(bad)
	if _, e = management.SignReport(invalid, renewed, w.cert.PrivateKey.(ed25519.PrivateKey), time.Now()); !errors.Is(e, management.ErrInvalid) {
		t.Fatal("altered retention proof accepted in a node report", e)
	}
	_, e = registry.PublishReport(ctx, w.node, tenant, w.node, report)
	must(t, e)
	view, e := registry.Report(ctx, owner, tenant, w.node, trust.Domain, time.Minute)
	must(t, e)
	if len(view.Commands) != 1 || view.Commands[0].Operation != req.Operation ||
		!bytes.Equal(view.Commands[0].RetentionProof, proof) || view.Commands[0].ResultDigest != ack.ResultDigest {
		t.Fatal("original proof did not reach the registry", view.Commands)
	}
}
