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

func TestManagementRetentionPlanReconcilesAcknowledgedHolds(t *testing.T) {
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

	hold := func(peer *fixture, r *generation.Replica, authority []byte, suffix string) (CommandObservation, []byte, Principal) {
		t.Helper()
		grant, e := generation.SignRetentionProtection(generation.RetentionProtection{
			Format: generation.RetentionProtectionFormat, Node: peer.e.Node, Domain: trust.Domain,
			Repository: trust.Repository, Epoch: trust.Epoch, Operation: id("pin-" + suffix), Generation: generationID,
			Action: "HOLD", NotBefore: now - 60, ExpiresUnix: now + 300,
			Retirement: &generation.RetirementBinding{Node: f.e.Node, Operation: op},
		}, signer)
		must(t, e)
		req := command.Request{Operation: id("hold-" + suffix), Reason: "OWNER_MAINTENANCE", Tenant: f.e.Tenant,
			Domain: trust.Domain, Kind: "retention", ExpectedRevision: 1, Authority: authority, ExpiresUnix: now + 300, RetentionGrant: grant}
		_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, peer.e.Node, req)
		must(t, e)
		node := Principal{Actor: peer.e.Node, Roles: []string{"node"}, Scopes: []Scope{{f.e.Tenant, trust.Domain}}}
		list, _, e := f.r.Commands(ctx, node, f.e.Tenant, peer.e.Node, 0, 1)
		must(t, e)
		if len(list) != 1 {
			t.Fatal(list)
		}
		env, _, e := command.VerifyEnvelope(list[0].Document, f.options.Owner)
		must(t, e)
		receipt, e := r.ApplyRetentionProtection(ctx, grant, nil)
		must(t, e)
		proof, e := json.Marshal(receipt)
		must(t, e)
		ack := command.Ack{Format: command.AckFormat, Node: peer.e.Node, Operation: req.Operation,
			EnvelopeDigest: storage.Hash(list[0].Document), State: "COMPLETE", StartedUnix: env.AdmittedUnix,
			ObservedUnix: time.Now().Unix(), ResultDigest: storage.Hash(proof)}
		signedAck, e := command.SignAck(ack, list[0].Document, f.options.Owner, peer.node, time.Now())
		must(t, e)
		return CommandObservation{Operation: req.Operation, EnvelopeDigest: ack.EnvelopeDigest, Kind: "retention",
			Phase: "COMPLETE", StartedUnix: ack.StartedUnix, FinishedUnix: ack.ObservedUnix, Attempts: 1,
			ResultDigest: ack.ResultDigest, RetentionProof: proof}, signedAck, node
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
	a1, ack, node := hold(a, ra, authorityA, "a1")
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
	f.r.Fault = func(point string) error {
		if point == "management-command-intent-durable" {
			return lost
		}
		return nil
	}
	if _, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req); !errors.Is(e, lost) {
		t.Fatal("command intent fault not reached", e)
	}
	f.reopen(t)
	checkPlan("RETIREMENT_INTENT_RECORDED", false)
	_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
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
}
