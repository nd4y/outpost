package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func completeObservationReport(f *fixture, sequence, revision uint64, observed int64) Report {
	return Report{
		Format: CatalogReportFormat, Node: f.e.Node, Tenant: f.e.Tenant, Domain: id("domain"),
		EnrollmentRevision: f.e.Revision, ConfigurationRevision: revision,
		Sequence: sequence, ObservedUnix: observed, InventoryState: "OBSERVED",
		Generations: []Generation{{
			Generation: id("captured-generation"), Target: f.e.Node, Sequence: 3,
			CreatedUnix: observed - 1, Status: "COMPLETE", Verification: "NONE",
		}},
		Jobs:  []Job{},
		Space: Space{State: "UNKNOWN"},
	}
}

func acceptCompleteObservationReport(t *testing.T, f *fixture, report Report) []byte {
	t.Helper()
	raw, err := SignReport(report, f.e, f.node, time.Now())
	must(t, err)
	_, err = f.r.PublishReport(context.Background(), f.e.Node, f.e.Tenant, f.e.Node, raw)
	must(t, err)
	return raw
}

func TestManagementCompleteObservationHTTPSOriginalAgeAndScope(t *testing.T) {
	h := newHTTPFixtureWithReportAge(t, false, time.Minute)
	f := h.f
	configureRetentionWitness(t, f)
	ctx := context.Background()
	signed := completeObservationReport(f, 1, 1, time.Now().Unix()-1)
	raw := acceptCompleteObservationReport(t, f, signed)
	item := signed.Generations[0]
	state, err := f.r.retentionState(ctx)
	must(t, err)
	expect := CompleteObservation{
		Format: CompleteObservationFormat, Tenant: f.e.Tenant, Node: f.e.Node,
		Domain: signed.Domain, Repository: id("repository"), WriterEpoch: 1,
		Generation: item.Generation, GenerationSequence: item.Sequence,
		EnrollmentRevision: f.e.Revision, ConfigurationRevision: 1,
		ConfigurationDigest: state.Configurations[f.e.Node].Digest,
		ReportDigest:        storage.Hash(raw),
		ReportSequence:      signed.Sequence,
		ObservedUnix:        signed.ObservedUnix,
	}
	path := h.base() + "/domains/" + signed.Domain + "/generations/" + item.Generation + "/complete-observation"
	before, err := f.r.store.Read("registry.json")
	must(t, err)
	reportFileName := reportFile(reportKey(f.e.Node, signed.Domain), state.Reports[reportKey(f.e.Node, signed.Domain)].Slot)
	beforeReport, err := f.r.store.Read(reportFileName)
	must(t, err)
	status, body := h.request(t, h.owner, http.MethodGet, path, nil)
	if status != http.StatusOK {
		t.Fatalf("complete observation: %d %s", status, body)
	}
	var got CompleteObservation
	must(t, json.Unmarshal(body, &got))
	if got != expect {
		t.Fatalf("complete observation does not match signed report and policy: %+v", got)
	}
	replayed, err := f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, raw)
	must(t, err)
	if replayed.ObservedUnix != expect.ObservedUnix || replayed.ResultDigest != expect.ReportDigest {
		t.Fatal("replay changed source report identity", replayed)
	}
	for _, row := range []struct {
		name   string
		query  string
		status int
		viewer bool
	}{
		{"viewer", path, http.StatusForbidden, true},
		{"foreign-domain", h.base() + "/domains/" + id("foreign-domain") + "/generations/" + item.Generation + "/complete-observation", http.StatusForbidden, false},
		{"foreign-tenant", "/api/v1/tenants/" + id("foreign-tenant") + "/nodes/" + f.e.Node + "/domains/" + signed.Domain + "/generations/" + item.Generation + "/complete-observation", http.StatusForbidden, false},
		{"other-generation", h.base() + "/domains/" + signed.Domain + "/generations/" + id("other") + "/complete-observation", http.StatusNotFound, false},
		{"unknown-query", path + "?limit=1", http.StatusBadRequest, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			client := h.owner
			if row.viewer {
				client = h.viewer
			}
			code, data := h.request(t, client, http.MethodGet, row.query, nil)
			if code != row.status {
				t.Fatalf("unexpected status: %d %s", code, data)
			}
			var failure httpFailure
			must(t, json.Unmarshal(data, &failure))
			if failure.Format != "outpost-management-error-1" {
				t.Fatal("observation disclosed for an inadmissible request")
			}
		})
	}
	after, err := f.r.store.Read("registry.json")
	must(t, err)
	afterReport, err := f.r.store.Read(reportFileName)
	must(t, err)
	if !bytes.Equal(before, after) || !bytes.Equal(beforeReport, afterReport) {
		t.Fatal("readback or exact replay changed retained evidence")
	}
	f.reopen(t)
	got, err = f.r.ObserveComplete(ctx, f.p, f.e.Tenant, f.e.Node, signed.Domain, item.Generation, time.Minute)
	must(t, err)
	if got != expect {
		t.Fatal("reopen changed original evidence", got)
	}
}

func TestManagementCompleteObservationConcealsForeignPendingEnrollment(t *testing.T) {
	for _, row := range []struct {
		name       string
		sameTenant bool
	}{
		{"other-tenant", false},
		{"other-domain", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx := context.Background()
			h := newHTTPFixture(t)
			f := h.f
			f.enroll(t)
			tenant := id("other-tenant")
			if row.sameTenant {
				tenant = f.e.Tenant
			}
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			must(t, err)
			foreign := f.e
			foreign.Tenant, foreign.Node, foreign.PublicKey = tenant, identity(pub), pub
			otherDomain := id(row.name + "-domain")
			foreign.Domains = []DomainAdmission{{otherDomain, id(row.name + "-repository"), 1}}
			foreignOwner := Principal{Actor: id(row.name + "-owner"), Roles: []string{"owner"}, Scopes: []Scope{{tenant, otherDomain}}}
			raw, err := SignEnrollment(foreign, f.owner)
			must(t, err)
			_, err = f.r.ApplyEnrollment(ctx, foreignOwner, id(row.name+"-enroll"), "INITIAL_ENROLLMENT", raw, 0)
			must(t, err)

			path := "/api/v1/tenants/" + f.e.Tenant + "/nodes/" + foreign.Node + "/domains/" + id("domain") +
				"/generations/" + id("selected-generation") + "/complete-observation"
			beforeStatus, before := h.request(t, h.owner, http.MethodGet, path, nil)
			if beforeStatus != http.StatusNotFound {
				t.Fatalf("foreign holder disclosed: %d %s", beforeStatus, before)
			}
			foreign.Revision++
			foreign.Revoked = true
			raw, err = SignEnrollment(foreign, f.owner)
			must(t, err)
			f.r.Fault = interruptAt("management-enrollment-intent-durable")
			defer func() { f.r.Fault = nil }()
			_, err = f.r.ApplyEnrollment(ctx, foreignOwner, id(row.name+"-revoke"), "REVOKE", raw, foreign.Revision-1)
			if err == nil {
				t.Fatal("missing interruption after foreign revocation intent")
			}
			state, err := f.r.retentionState(ctx)
			must(t, err)
			pending, err := f.r.pendingEnrollment(ctx, state, foreign.Node)
			must(t, err)
			if !pending {
				t.Fatal("foreign revocation was not durably pending")
			}
			afterStatus, after := h.request(t, h.owner, http.MethodGet, path, nil)
			if afterStatus != beforeStatus || !bytes.Equal(after, before) {
				t.Fatalf("foreign revocation disclosed: %d %s", afterStatus, after)
			}
		})
	}
}

func TestManagementCompleteObservationRejectsUnreadyOrExpiredReports(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	configureRetentionWitness(t, f)
	now := time.Now().Unix()
	for i, row := range []struct {
		name, inventory, status string
		target                  string
		observedUnix            int64
	}{
		{"stale", "OBSERVED", "COMPLETE", f.e.Node, now - 15},
		{"unknown-inventory", "UNKNOWN", "COMPLETE", f.e.Node, now},
		{"foreign-target", "OBSERVED", "COMPLETE", id("other-node"), now},
		{"incomplete", "OBSERVED", "INCOMPLETE", f.e.Node, now},
		{"corrupt", "OBSERVED", "CORRUPT", f.e.Node, now},
	} {
		t.Run(row.name, func(t *testing.T) {
			report := completeObservationReport(f, uint64(i+1), 1, row.observedUnix)
			report.InventoryState = row.inventory
			report.Generations[0].Target = row.target
			report.Generations[0].Status = row.status
			acceptCompleteObservationReport(t, f, report)
			got, err := f.r.ObserveComplete(ctx, f.p, f.e.Tenant, f.e.Node, report.Domain, report.Generations[0].Generation, 5*time.Second)
			if !errors.Is(err, ErrUnavailable) || got != (CompleteObservation{}) {
				t.Fatal("unready or expired evidence disclosed", got, err)
			}
		})
	}
	untrusted := newFixture(t)
	untrusted.e.Class = "untrusted"
	configureRetentionWitness(t, untrusted)
	report := completeObservationReport(untrusted, 1, 1, time.Now().Unix())
	acceptCompleteObservationReport(t, untrusted, report)
	got, err := untrusted.r.ObserveComplete(ctx, untrusted.p, untrusted.e.Tenant, untrusted.e.Node, report.Domain, report.Generations[0].Generation, time.Minute)
	if !errors.Is(err, ErrUnavailable) || got != (CompleteObservation{}) {
		t.Fatal("untrusted holder evidence disclosed", got, err)
	}
}

func TestManagementCompleteObservationRejectsOldPolicyAndPendingRevocation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	configureRetentionWitness(t, f)
	signed := completeObservationReport(f, 1, 1, time.Now().Unix())
	acceptCompleteObservationReport(t, f, signed)
	observe := func() (CompleteObservation, error) {
		return f.r.ObserveComplete(ctx, f.p, f.e.Tenant, f.e.Node, signed.Domain, signed.Generations[0].Generation, time.Minute)
	}
	_, err := observe()
	must(t, err)
	before, err := f.r.retentionState(ctx)
	must(t, err)
	cfg, _, err := f.r.configuration(ctx, before, f.e.Node)
	must(t, err)
	cfg.Revision++
	input := configurationMutation(t, f, cfg, "complete-observation-new-policy", cfg.Revision-1)
	preview, err := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, err)
	input.PreviewDigest = preview.CandidateDigest
	_, err = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, err)
	if got, err := observe(); !errors.Is(err, ErrUnavailable) || got != (CompleteObservation{}) {
		t.Fatal("old policy evidence disclosed", got, err)
	}
	signed = completeObservationReport(f, 2, cfg.Revision, time.Now().Unix())
	acceptCompleteObservationReport(t, f, signed)
	got, err := observe()
	must(t, err)
	if got.ConfigurationRevision != cfg.Revision || got.ConfigurationDigest != input.PreviewDigest {
		t.Fatal("current policy evidence not bound", got)
	}
	next := f.e
	next.Revision++
	next.Revoked = true
	raw, err := SignEnrollment(next, f.owner)
	must(t, err)
	f.r.Fault = interruptAt("management-enrollment-intent-durable")
	_, err = f.r.ApplyEnrollment(ctx, f.p, id("complete-observation-revoke"), "REVOKE", raw, f.e.Revision)
	if err == nil {
		t.Fatal("missing interruption after revocation intent")
	}
	f.reopen(t)
	if got, err := observe(); !errors.Is(err, ErrConflict) || got != (CompleteObservation{}) {
		t.Fatal("pending revocation left old evidence visible", got, err)
	}
	_, err = f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
	must(t, err)
	if got, err := observe(); !errors.Is(err, ErrUnavailable) || got != (CompleteObservation{}) {
		t.Fatal("revoked holder still visible", got, err)
	}
}
