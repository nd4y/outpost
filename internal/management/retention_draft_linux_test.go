package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
)

func TestManagementRetentionPlanDispatchesSignedStepsAndReconcilesReleases(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	f.enroll(t)
	ctx := context.Background()
	newPeer := func() *fixture {
		t.Helper()
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		peer := *f
		peer.e.Node, peer.e.PublicKey, peer.node = identity(pub), pub, key
		raw, e := SignEnrollment(peer.e, f.owner)
		must(t, e)
		_, e = f.r.ApplyEnrollment(ctx, f.p, id("enroll-"+peer.e.Node), "INITIAL_ENROLLMENT", raw, 0)
		must(t, e)
		return &peer
	}
	a, b := newPeer(), newPeer()
	maint, signer, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	writer, writerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	cfg := configFixture(t, f)
	cfg.Domains[0].Trust.Maintenance, cfg.Domains[0].Trust.Writer = maint, writer
	cfg.Domains[0].RetirementMinimumCopies = 2
	cfg.Nodes = append(cfg.Nodes, policy.Node{ID: a.e.Node, Class: "trusted"}, policy.Node{ID: b.e.Node, Class: "trusted"})
	cfg.Domains[0].Placement.Holders = []string{f.e.Node, a.e.Node, b.e.Node}
	trust := cfg.Domains[0].Trust
	configure := func(peer *fixture) (control.Config, []byte) {
		t.Helper()
		c := cfg
		c.Node = peer.e.Node
		kinds := []string{"retention"}
		if peer == f {
			kinds = append(kinds, "maintenance")
		}
		grant, e := command.SignAuthority(command.Authority{
			Format: command.AuthorityFormat, Service: f.options.Signer.Public().(ed25519.PublicKey),
			Node: c.Node, Tenant: f.e.Tenant, Domain: trust.Domain, Repository: trust.Repository,
			WriterEpoch: trust.Epoch, AuthorityEpoch: 1, Kinds: kinds,
			NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix,
		}, f.owner)
		must(t, e)
		c.Commands = []json.RawMessage{grant}
		input := configurationMutation(t, f, c, "retention-config-"+c.Node, 0)
		preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, c.Node, input)
		must(t, e)
		input.PreviewDigest = preview.CandidateDigest
		_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, c.Node, input)
		must(t, e)
		return c, grant
	}
	targetCfg, targetAuthority := configure(f)
	_, authorityA := configure(a)
	_, authorityB := configure(b)
	now := time.Now().Unix()
	root, payload := []byte("synthetic kit"), []byte("synthetic ciphertext")
	rootRef := generation.Object{ID: storage.Hash(root), Bytes: len(root)}
	payloadRef := generation.Object{ID: storage.Hash(payload), Bytes: len(payload)}
	rawCatalog, e := generation.SignCatalog(generation.Catalog{
		Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch,
		Sequence: 1, SnapshotUnix: now, Policy: 1, KitFormat: generation.KitFormat,
		Kits: []generation.Kit{{File: id("file"), Version: id("version"), Root: rootRef, Objects: []generation.Object{payloadRef}}},
	}, writerKey)
	must(t, e)
	objects := map[string][]byte{rootRef.ID: root, payloadRef.ID: payload}
	openCopy := func(peer *fixture) *generation.Replica {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "replica")
		must(t, os.Mkdir(dir, 0700))
		r, e := generation.OpenWorkerAt(nil, dir, trust, true, peer.node)
		must(t, e)
		t.Cleanup(func() { r.Close() })
		_, e = r.Receive(ctx, rawCatalog, func(o generation.Object) ([]byte, error) { return objects[o.ID], nil })
		must(t, e)
		return r
	}
	ra, rb := openCopy(a), openCopy(b)
	generationID := storage.Hash(rawCatalog)
	op := id("planned-retirement")
	request := RetentionDraftRequest{Format: RetentionDraftRequestFormat, Preview: generation.Permit{
		Format: generation.PermitWindowFormat, Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch,
		Revision: 3, Operation: op, Retire: []string{generationID},
		Window: &generation.PermitWindow{Node: f.e.Node, StartUnix: now, ExpiresUnix: now + 300},
	}, HoldCommands: []string{id("hold-a1"), id("hold-a2"), id("hold-b")}}
	sort.Strings(request.HoldCommands)
	path := "/api/v1/tenants/" + f.e.Tenant + "/domains/" + trust.Domain + "/retention/draft"
	status, raw := h.request(t, h.owner, "POST", path, request)
	var empty RetentionDraft
	if status != 200 {
		t.Fatalf("draft %d %s", status, raw)
	}
	must(t, json.Unmarshal(raw, &empty))
	if empty.State != "INSUFFICIENT_EVIDENCE" || empty.Permit != nil {
		t.Fatal(empty)
	}
	if status, _ = h.request(t, h.viewer, "POST", path, request); status != 403 {
		t.Fatal("viewer can prepare deletion draft", status)
	}

	planInput := request
	planInput.Format = RetentionPlanRequestFormat
	planPath := "/api/v1/tenants/" + f.e.Tenant + "/domains/" + trust.Domain + "/retention/plans"
	lost := errors.New("lost reply after durable plan")
	f.r.Fault = func(point string) error {
		if point == "management-retention-plan-durable" {
			return lost
		}
		return nil
	}
	if status, _ = h.request(t, h.owner, "POST", planPath, planInput); status != 503 {
		t.Fatal("expected simulated lost response", status)
	}
	var waiting RetentionPlanStatus
	status, raw = h.request(t, h.owner, "GET", planPath+"/"+op, nil)
	if status != 200 {
		t.Fatalf("plan status %d %s", status, raw)
	}
	must(t, json.Unmarshal(raw, &waiting))
	if waiting.State != "WAITING_FOR_HOLDS" || waiting.Authorization != "NONE" || waiting.Draft == nil || waiting.Draft.Permit != nil {
		t.Fatal(waiting)
	}
	if status, _ = h.request(t, h.viewer, "GET", planPath+"/"+op, nil); status != 403 {
		t.Fatal("viewer can access a retirement plan", status)
	}
	closeGrant, e := generation.SignRetentionProtection(generation.RetentionProtection{
		Format: generation.RetentionProtectionFormat, Node: f.e.Node, Domain: trust.Domain,
		Repository: trust.Repository, Epoch: trust.Epoch, Operation: op, Action: "CLOSE",
		NotBefore: now - 60, ExpiresUnix: now + 300,
	}, signer)
	must(t, e)
	closeReq := command.Request{Operation: id("close"), Reason: "OWNER_MAINTENANCE", Tenant: f.e.Tenant,
		Domain: trust.Domain, Kind: "retention", ExpectedRevision: 1, Authority: targetAuthority,
		ExpiresUnix: now + 300, RetentionGrant: closeGrant}
	closeStep := RetentionStepRequest{Format: RetentionStepRequestFormat, Node: f.e.Node, Command: closeReq}
	status, raw = h.request(t, h.owner, "POST", planPath+"/"+op+"/steps", closeStep)
	if status != 200 {
		t.Fatalf("stage %d %s", status, raw)
	}
	var staged RetentionStepReceipt
	must(t, json.Unmarshal(raw, &staged))
	if staged.Operation != closeReq.Operation || staged.Plan != op {
		t.Fatal(staged)
	}
	f.reopen(t)
	plan, e := f.r.RegisterRetentionPlan(ctx, f.p, f.e.Tenant, trust.Domain, planInput)
	must(t, e)
	if plan.RegistrationRevision != waiting.Plan.RegistrationRevision || plan.RegisteredUnix != waiting.Plan.RegisteredUnix {
		t.Fatal("registration replay changed the original record", plan)
	}
	altered := planInput
	altered.Preview.Revision++
	if _, e = f.r.RegisterRetentionPlan(ctx, f.p, f.e.Tenant, trust.Domain, altered); !errors.Is(e, ErrConflict) {
		t.Fatal("plan could be rewritten", e)
	}
	checkPlan := func(expected string, closeRequired bool) RetentionPlanStatus {
		t.Helper()
		result, e := f.r.RetentionPlanStatus(ctx, f.p, f.e.Tenant, trust.Domain, op, time.Minute)
		must(t, e)
		if result.State != expected || result.CloseRequired != closeRequired || result.Authorization != "NONE" ||
			result.Plan.RegistrationRevision != plan.RegistrationRevision {
			t.Fatal(result)
		}
		return result
	}

	stage := func(peer *fixture, req command.Request) RetentionStepReceipt {
		t.Helper()
		in := RetentionStepRequest{Format: RetentionStepRequestFormat, Node: peer.e.Node, Command: req}
		receipt, e := f.r.StageRetentionStep(ctx, f.p, f.e.Tenant, trust.Domain, op, in)
		must(t, e)
		return receipt
	}
	requireReconcile := func(actors []Principal, operation, expected string) {
		t.Helper()
		result, e := f.r.Reconcile(ctx, actors, 0, 16)
		must(t, e)
		for _, item := range result.Items {
			if item.Operation == operation && item.State == expected {
				return
			}
		}
		t.Fatalf("expected %s for %s, got %+v", expected, operation, result.Items)
	}
	requireReconcile([]Principal{f.p}, closeReq.Operation, "WAITING_PREREQUISITE")
	if replay := stage(f, closeReq); replay != staged {
		t.Fatal("stage replay changed original receipt", replay)
	}

	protection := func(peer *fixture, operation, action string) generation.RetentionProtection {
		return generation.RetentionProtection{Format: generation.RetentionProtectionFormat, Node: peer.e.Node, Domain: trust.Domain,
			Repository: trust.Repository, Epoch: trust.Epoch, Operation: operation, Action: action, NotBefore: now - 60, ExpiresUnix: now + 300}
	}
	holdGrant := func(peer *fixture, suffix string) generation.RetentionProtection {
		grant := protection(peer, id("pin-"+suffix), "HOLD")
		grant.Generation = generationID
		grant.Retirement = &generation.RetirementBinding{Node: f.e.Node, Operation: op}
		return grant
	}
	requestProtection := func(authority []byte, label string, g generation.RetentionProtection) command.Request {
		t.Helper()
		grant, e := generation.SignRetentionProtection(g, signer)
		must(t, e)
		return command.Request{Operation: id(label), Reason: "OWNER_MAINTENANCE", Tenant: f.e.Tenant,
			Domain: trust.Domain, Kind: "retention", ExpectedRevision: 1, Authority: authority, ExpiresUnix: now + 300, RetentionGrant: grant}
	}
	queue := func(peer *fixture, r *generation.Replica, req command.Request) (CommandObservation, []byte, Principal) {
		t.Helper()
		_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, peer.e.Node, req)
		must(t, e)
		node := Principal{Actor: peer.e.Node, Roles: []string{"node"}, Scopes: []Scope{{f.e.Tenant, trust.Domain}}}
		list, _, e := f.r.Commands(ctx, node, f.e.Tenant, peer.e.Node, 0, 32)
		must(t, e)
		var raw []byte
		var env command.Envelope
		for _, queued := range list {
			env, _, e = command.VerifyEnvelope(queued.Document, f.options.Owner)
			must(t, e)
			if env.Request.Operation == req.Operation {
				raw = queued.Document
				break
			}
		}
		if raw == nil {
			t.Fatal("protection command missing from queue", req.Operation)
		}
		receipt, e := r.ApplyRetentionProtection(ctx, req.RetentionGrant, nil)
		must(t, e)
		proof, e := json.Marshal(receipt)
		must(t, e)
		ack := command.Ack{Format: command.AckFormat, Node: peer.e.Node, Operation: req.Operation,
			EnvelopeDigest: storage.Hash(raw), State: "COMPLETE", StartedUnix: env.AdmittedUnix,
			ObservedUnix: time.Now().Unix(), ResultDigest: storage.Hash(proof)}
		signedAck, e := command.SignAck(ack, raw, f.options.Owner, peer.node, time.Now())
		must(t, e)
		return CommandObservation{Operation: req.Operation, EnvelopeDigest: ack.EnvelopeDigest, Kind: "retention",
			Phase: "COMPLETE", StartedUnix: ack.StartedUnix, FinishedUnix: ack.ObservedUnix, Attempts: 1,
			ResultDigest: ack.ResultDigest, RetentionProof: proof}, signedAck, node
	}
	hold := func(peer *fixture, r *generation.Replica, authority []byte, suffix string) (CommandObservation, []byte, Principal) {
		t.Helper()
		return queue(peer, r, requestProtection(authority, "hold-"+suffix, holdGrant(peer, suffix)))
	}
	observe := func(peer *fixture, sequence uint64, commands ...CommandObservation) {
		t.Helper()
		r := Report{Format: CommandReportFormat, Node: peer.e.Node, Tenant: f.e.Tenant, Domain: trust.Domain,
			EnrollmentRevision: 1, ConfigurationRevision: 1, Sequence: sequence, ObservedUnix: time.Now().Unix(),
			InventoryState: "OBSERVED", Generations: []Generation{{Generation: generationID, Sequence: 1, CreatedUnix: now,
				Target: peer.e.Node, Status: "COMPLETE", Pinned: true, Verification: "NONE", Objects: 2}},
			Jobs: []Job{}, Commands: commands, Space: Space{State: "UNKNOWN"}}
		raw, e := SignReport(r, peer.e, peer.node, time.Now())
		must(t, e)
		_, e = f.r.PublishReport(ctx, peer.e.Node, f.e.Tenant, peer.e.Node, raw)
		must(t, e)
	}
	a1Req := requestProtection(authorityA, "hold-a1", holdGrant(a, "a1"))
	a1Step := RetentionStepRequest{Format: RetentionStepRequestFormat, Node: a.e.Node, Command: a1Req}
	f.r.Fault = func(point string) error {
		if point == "management-retention-step-durable" {
			return lost
		}
		return nil
	}
	if _, e = f.r.StageRetentionStep(ctx, f.p, f.e.Tenant, trust.Domain, op, a1Step); !errors.Is(e, lost) {
		t.Fatal("staging fault was not reached", e)
	}
	f.reopen(t)
	stage(a, a1Req)
	requireReconcile(nil, a1Req.Operation, "BLOCKED")
	requireReconcile([]Principal{f.p}, a1Req.Operation, "PUBLISHED")
	a1, ack, node := queue(a, ra, a1Req)
	_, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, a.e.Node, a1.Operation, ack)
	must(t, e)
	a2, ack, node := hold(a, ra, authorityA, "a2")
	_, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, a.e.Node, a2.Operation, ack)
	must(t, e)
	b1, ack, node := hold(b, rb, authorityB, "b")
	observe(a, 1, a1, a2)
	observe(b, 1, b1)
	check := func(state string, sources int) RetentionDraft {
		t.Helper()
		result, e := f.r.PrepareRetentionDraft(ctx, f.p, f.e.Tenant, trust.Domain, request, time.Minute)
		must(t, e)
		if result.State != state || result.Authorization != "NONE" || len(result.Sources) != sources ||
			(result.Permit != nil) != (state == "READY_TO_SIGN") {
			t.Fatal(result)
		}
		return result
	}
	check("INSUFFICIENT_EVIDENCE", 1)
	_, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, b.e.Node, b1.Operation, ack)
	must(t, e)
	wrong := b1
	wrong.EnvelopeDigest = id("other-envelope")
	observe(b, 2, wrong)
	check("INSUFFICIENT_EVIDENCE", 1)
	observe(b, 3, b1)
	before, e := f.r.store.Read("registry.json")
	must(t, e)
	result := check("READY_TO_SIGN", 2)
	ready := checkPlan("READY_TO_SIGN", false)
	if ready.Draft == nil || ready.Draft.Permit == nil || len(ready.Draft.Sources) != 2 {
		t.Fatal("registered plan did not recover the coverage", ready)
	}
	after, e := f.r.store.Read("registry.json")
	must(t, e)
	if !bytes.Equal(before, after) || len(result.Permit.Signature) != 0 || result.Permit.Revision != request.Preview.Revision {
		t.Fatal("draft changed state or local authority", result)
	}
	signed, e := generation.SignPermit(*result.Permit, signer)
	must(t, e)
	_, e = targetCfg.MaintenancePermit(command.Request{Kind: "maintenance", Domain: trust.Domain,
		Operation: op, ExpiresUnix: now + 300, MaintenancePermit: signed})
	must(t, e)
	reused := request
	reused.Preview.Operation = a1.Operation
	reused.HoldCommands = []string{a2.Operation, b1.Operation}
	sort.Strings(reused.HoldCommands)
	if _, e = f.r.PrepareRetentionDraft(ctx, f.p, f.e.Tenant, trust.Domain, reused, time.Minute); !errors.Is(e, ErrConflict) {
		t.Fatal("retirement draft reused a command operation", e)
	}
	req := command.Request{Operation: op, Reason: "OWNER_MAINTENANCE", Tenant: f.e.Tenant, Domain: trust.Domain,
		Kind: "maintenance", ExpectedRevision: targetCfg.Revision, Authority: targetAuthority,
		ExpiresUnix: now + 300, MaintenancePermit: signed}
	wrongPermit := *result.Permit
	wrongPermit.Revision++
	req.MaintenancePermit, e = generation.SignPermit(wrongPermit, signer)
	must(t, e)
	if _, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req); !errors.Is(e, ErrConflict) {
		t.Fatal("planned operation accepted a different replica revision", e)
	}
	req.MaintenancePermit = signed
	stage(f, req)
	f.r.Fault = func(point string) error {
		if point == "management-command-intent-durable" {
			return lost
		}
		return nil
	}
	requireReconcile([]Principal{f.p}, req.Operation, "BLOCKED")
	f.reopen(t)
	checkPlan("RETIREMENT_INTENT_RECORDED", false)
	requireReconcile([]Principal{f.p}, req.Operation, "PUBLISHED")
	checkPlan("RETIREMENT_QUEUED", false)
	targetNode := Principal{Actor: f.e.Node, Roles: []string{"node"}, Scopes: []Scope{{f.e.Tenant, trust.Domain}}}
	list, _, e := f.r.Commands(ctx, targetNode, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(list) != 1 {
		t.Fatal("operation replay queued a duplicate", list)
	}
	ack = commandAck(t, f, list[0].Document)
	done, e := f.r.AcknowledgeCommand(ctx, targetNode, f.e.Tenant, f.e.Node, op, ack)
	must(t, e)
	f.reopen(t)
	afterRestart := checkPlan("RETIREMENT_REPORTED_COMPLETE", true)
	if afterRestart.Retirement == nil || *afterRestart.Retirement != done {
		t.Fatal("plan lost original retirement acknowledgement", afterRestart)
	}

	a3, _, _ := hold(a, ra, authorityA, "a3")
	undelivered := requestProtection(authorityA, "hold-a4", holdGrant(a, "a4"))
	_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, a.e.Node, undelivered)
	must(t, e)
	targetReplica := openCopy(f)
	requireReconcile([]Principal{f.p}, closeReq.Operation, "PUBLISHED")
	closeObservation, closeAck, closeNode := queue(f, targetReplica, closeReq)
	checkPlan("CLOSURE_PENDING", true)
	state, e := f.r.retentionState(ctx)
	must(t, e)
	otherEpoch := request.Preview
	otherEpoch.Epoch++
	if !hasPlannedClose(state, f.e.Tenant, request.Preview) || hasPlannedClose(state, f.e.Tenant, otherEpoch) {
		t.Fatal("close intent crossed a repository epoch")
	}
	newHold := requestProtection(authorityA, "hold-a5", holdGrant(a, "a5"))
	if _, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, a.e.Node, newHold); !errors.Is(e, ErrConflict) {
		t.Fatal("new hold admitted after close intent", e)
	}
	_, e = f.r.AcknowledgeCommand(ctx, closeNode, f.e.Tenant, f.e.Node, closeObservation.Operation, closeAck)
	must(t, e)
	observe(f, 1, closeObservation)
	observe(a, 2, a1, a2, a3)
	closed := checkPlan("CLOSED_AWAITING_RELEASES", false)
	if closed.Closure == nil || !bytes.Equal(closed.Closure.Proof, closeObservation.RetentionProof) || len(closed.Holds) != 5 {
		t.Fatal("closure or registered holds lost", closed)
	}
	unconfirmed := 0
	for _, h := range closed.Holds {
		if h.State == "HOLD_UNCONFIRMED" {
			unconfirmed++
		}
	}
	if unconfirmed != 2 {
		t.Fatal("pending hold wrongly reported as confirmed", closed.Holds)
	}
	closure, e := generation.VerifyRetentionProtectionReceipt(closed.Closure.Proof, f.e.Node)
	must(t, e)
	releaseRequest := func(peer *fixture, authority []byte, old CommandObservation) command.Request {
		t.Helper()
		pin, e := generation.VerifyRetentionProtectionReceipt(old.RetentionProof, peer.e.Node)
		must(t, e)
		g := protection(peer, pin.Operation, "RELEASE")
		g.Generation, g.HoldDigest, g.Retirement, g.Closure = pin.Generation, pin.HoldDigest, pin.Retirement, &closure
		return requestProtection(authority, "release-"+old.Operation, g)
	}
	releasedA := []CommandObservation{a1, a2, a3}
	for _, old := range []CommandObservation{a1, a2, a3} {
		c, ack, node := queue(a, ra, releaseRequest(a, authorityA, old))
		_, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, a.e.Node, c.Operation, ack)
		must(t, e)
		releasedA = append(releasedA, c)
	}
	pendingRelease := holdGrant(a, "a4")
	pendingRelease.Action, pendingRelease.HoldDigest = "RELEASE", storage.Hash(undelivered.RetentionGrant)
	pendingRelease.Closure, pendingRelease.PendingHold = &closure, undelivered.RetentionGrant
	fenced, fenceAck, fenceNode := queue(a, ra, requestProtection(authorityA, "release-undelivered", pendingRelease))
	_, e = f.r.AcknowledgeCommand(ctx, fenceNode, f.e.Tenant, a.e.Node, fenced.Operation, fenceAck)
	must(t, e)
	if _, e = ra.ApplyRetentionProtection(ctx, undelivered.RetentionGrant, nil); !errors.Is(e, generation.ErrConflict) {
		t.Fatal("late delivery recreated a settled hold", e)
	}
	releasedA = append(releasedA, fenced)
	releaseB := releaseRequest(b, authorityB, b1)
	stage(b, releaseB)
	requireReconcile([]Principal{f.p}, releaseB.Operation, "PUBLISHED")
	c, ack, node := queue(b, rb, releaseB)
	observe(a, 3, releasedA...)
	observe(b, 4, b1, c)
	f.reopen(t)
	partial := checkPlan("CLOSED_AWAITING_RELEASES", false)
	pending := 0
	for _, h := range partial.Holds {
		if h.Release == nil {
			pending++
		}
	}
	if pending != 1 {
		t.Fatal("loss of release acknowledgement was hidden", partial.Holds)
	}
	_, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, b.e.Node, c.Operation, ack)
	must(t, e)
	f.reopen(t)
	settled := checkPlan("SETTLED", false)
	for _, h := range settled.Holds {
		if h.State != "RELEASED" || h.Release == nil {
			t.Fatal("hold settled without its release", settled)
		}
	}
}
