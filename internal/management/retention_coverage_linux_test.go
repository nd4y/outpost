package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func configureRetentionWitness(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	document, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("retention-enroll-"+f.e.Node), "INITIAL_ENROLLMENT", document, 0)
	must(t, e)
	cfg := configFixture(t, f)
	cfg.Nodes[0].Class = f.e.Class
	cfg.Domains[0].Placement.AllowedClasses = []string{f.e.Class}
	input := configurationMutation(t, f, cfg, f.e.Node, 0)
	preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	input.PreviewDigest = preview.CandidateDigest
	_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
}

func publishRetentionWitness(t *testing.T, f *fixture, sequence uint64, gen Generation) string {
	t.Helper()
	gen.Target = f.e.Node
	now := time.Now()
	report := Report{Format: CatalogReportFormat, Node: f.e.Node, Tenant: f.e.Tenant, Domain: id("domain"), EnrollmentRevision: f.e.Revision, ConfigurationRevision: 1, Sequence: sequence, ObservedUnix: now.Unix(), InventoryState: "OBSERVED", Generations: []Generation{gen}, Jobs: []Job{}, Space: Space{State: "UNKNOWN"}}
	raw, e := SignReport(report, f.e, f.node, now)
	must(t, e)
	_, e = f.r.PublishReport(context.Background(), f.e.Node, f.e.Tenant, f.e.Node, raw)
	must(t, e)
	return storage.Hash(raw)
}

func TestManagementRetentionCoverageUsesCurrentPinnedSurvivors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	configureRetentionWitness(t, f)
	newPeer := func(class string) *fixture {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		peer := *f
		peer.e.Node, peer.e.PublicKey, peer.e.Class, peer.node = identity(pub), pub, class, key
		configureRetentionWitness(t, &peer)
		return &peer
	}
	second, untrusted := newPeer("trusted"), newPeer("untrusted")
	gen := Generation{Generation: id("retained"), Sequence: 4, CreatedUnix: time.Now().Unix() - 300, Status: "COMPLETE", Verification: "CIPHERTEXT", VerifiedUnix: time.Now().Unix(), Pinned: true, Objects: 3}
	digest := publishRetentionWitness(t, f, 1, gen)
	publishRetentionWitness(t, second, 1, gen)
	publishRetentionWitness(t, untrusted, 1, gen)
	roster := []string{f.e.Node, second.e.Node, untrusted.e.Node}
	sort.Strings(roster)
	request := RetentionCoverageRequest{Format: RetentionCoverageRequestFormat, Nodes: roster, RetiringNodes: []string{second.e.Node}, Generations: []string{gen.Generation}, MinimumCopies: 1}
	check := func(state string, count int) RetentionCoverage {
		t.Helper()
		out, e := f.r.PreviewRetentionCoverage(ctx, f.p, f.e.Tenant, id("domain"), request, time.Minute)
		must(t, e)
		if out.Authorization != "NONE" || len(out.Generations) != 1 || out.Generations[0].State != state || len(out.Generations[0].Witnesses) != count {
			t.Fatal(out)
		}
		return out
	}
	before, e := f.r.store.Read("registry.json")
	must(t, e)
	result := check("OBSERVED_MINIMUM_MET", 1)
	witness := result.Generations[0].Witnesses[0]
	if witness.Node != f.e.Node || witness.ReportDigest != digest || witness.VerifiedUnix != gen.VerifiedUnix {
		t.Fatal(witness)
	}
	request.MinimumCopies = 2
	check("INSUFFICIENT_EVIDENCE", 1)
	after, e := f.r.store.Read("registry.json")
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("preview changed the durable registry")
	}
	request.RetiringNodes = []string{untrusted.e.Node}
	check("OBSERVED_MINIMUM_MET", 2)
	gen.Sequence++
	publishRetentionWitness(t, f, 2, gen)
	check("CONFLICTING_EVIDENCE", 2)
	gen.VerifiedUnix = time.Now().Unix() - 120
	publishRetentionWitness(t, f, 3, gen)
	check("INSUFFICIENT_EVIDENCE", 1)
	gen.VerifiedUnix = time.Now().Unix()
	gen.Pinned = false
	publishRetentionWitness(t, f, 4, gen)
	check("INSUFFICIENT_EVIDENCE", 1)
}

func TestManagementRetentionCoverageHTTPSRolesAndBounds(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	f.enroll(t)
	path := "/api/v1/tenants/" + f.e.Tenant + "/domains/" + id("domain") + "/retention/preview"
	request := RetentionCoverageRequest{Format: RetentionCoverageRequestFormat, Nodes: []string{f.e.Node}, RetiringNodes: []string{f.e.Node}, Generations: []string{id("retained")}, MinimumCopies: 1}
	status, raw := h.request(t, h.owner, "POST", path, request)
	var result RetentionCoverage
	if status != 200 {
		t.Fatalf("preview %d %s", status, raw)
	}
	must(t, json.Unmarshal(raw, &result))
	if result.Authorization != "NONE" || result.Generations[0].State != "INSUFFICIENT_EVIDENCE" {
		t.Fatal(result)
	}
	status, _ = h.request(t, h.viewer, "POST", path, request)
	if status != 403 {
		t.Fatal("viewer accessed retention preview", status)
	}
	foreign := "/api/v1/tenants/" + f.e.Tenant + "/domains/" + id("foreign") + "/retention/preview"
	status, _ = h.request(t, h.owner, "POST", foreign, request)
	if status != 403 {
		t.Fatal("foreign scope accepted", status)
	}
	request.Nodes = append(request.Nodes, f.e.Node)
	status, _ = h.request(t, h.owner, "POST", path, request)
	if status != 400 {
		t.Fatal("duplicate node accepted", status)
	}
}
