package management

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestManagementConfigurationPreviewReportsObservedVolumeShortfall(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	f.enroll(t)
	ctx := context.Background()
	current := configFixture(t, f)
	initial := configurationMutation(t, f, current, "preview-space-initial", 0)
	preview, err := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, initial)
	must(t, err)
	initial.PreviewDigest = preview.CandidateDigest
	_, err = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, initial)
	must(t, err)

	candidate := current
	candidate.Revision++
	candidate.Limits.CapacityBytes = 48 << 20
	input := configurationMutation(t, f, candidate, "preview-space-next", current.Revision)
	path := h.base() + "/configuration/preview"
	checkPreview := func(t *testing.T, expected string) Preview {
		t.Helper()
		status, raw := h.request(t, h.owner, http.MethodPost, path, input)
		if status != http.StatusOK {
			t.Fatalf("preview %d %s", status, raw)
		}
		var out Preview
		must(t, json.Unmarshal(raw, &out))
		if out.CapacityState != expected || out.EstimatedBytes != nil || out.CurrentRevision != current.Revision {
			t.Fatalf("capacity preview = %+v, want %s with no assignment estimate", out, expected)
		}
		return out
	}
	checkPreview(t, "UNKNOWN")
	const unknown, short = "UNKNOWN", "OBSERVED_INSUFFICIENT"
	tests := []struct {
		name, scope, expected             string
		reportAge, spaceAge               int64
		configRevision                    uint64
		freeMiB, accountedMiB, pendingMiB int64
	}{
		{name: "stale signed report", scope: "VOLUME", expected: unknown, reportAge: 30, spaceAge: 30, configRevision: 1, freeMiB: 1},
		{name: "recent report with stale measurement", scope: "VOLUME", expected: unknown, spaceAge: 30, configRevision: 1, freeMiB: 1},
		{name: "earlier installed revision", scope: "VOLUME", expected: unknown, configRevision: 0, freeMiB: 1},
		{name: "missing volume scope", expected: unknown, configRevision: 1, freeMiB: 1},
		{name: "observed headroom is not an assignment estimate", scope: "VOLUME", expected: unknown, configRevision: 1, freeMiB: 11, accountedMiB: 37, pendingMiB: 3},
		{name: "pending reservations reduce physical headroom", scope: "VOLUME", expected: short, configRevision: 1, freeMiB: 10, accountedMiB: 13, pendingMiB: 3},
		{name: "accounted usage and pending reservations exceed usable capacity", scope: "VOLUME", expected: short, configRevision: 1, freeMiB: 32, accountedMiB: 38, pendingMiB: 3},
		{name: "filesystem cannot keep configured reserve", scope: "VOLUME", expected: short, configRevision: 1, freeMiB: 7},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			physical, free := int64(80)<<20, tc.freeMiB<<20
			space := Space{State: "OBSERVED", Scope: tc.scope, PhysicalBytes: &physical, FreeBytes: &free, ObservedUnix: now.Unix() - tc.spaceAge}
			if tc.accountedMiB != 0 {
				accounted := tc.accountedMiB << 20
				space.AccountedBytes = &accounted
			}
			if tc.pendingMiB != 0 {
				pending := tc.pendingMiB << 20
				space.ReservedBytes = &pending
			}
			report := Report{
				Format: ReportFormat, Node: f.e.Node, Tenant: f.e.Tenant, Domain: current.Domains[0].Trust.Domain,
				EnrollmentRevision: f.e.Revision, Sequence: uint64(i + 1), ConfigurationRevision: tc.configRevision,
				ObservedUnix: now.Unix() - tc.reportAge, Generations: []Generation{}, Jobs: []Job{}, Space: space,
			}
			signed, err := SignReport(report, f.e, f.node, now)
			must(t, err)
			_, err = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, signed)
			must(t, err)
			preview = checkPreview(t, tc.expected)
		})
	}
	input.PreviewDigest = preview.CandidateDigest
	status, raw := h.request(t, h.owner, http.MethodPut, h.base()+"/configuration", input)
	if status != http.StatusOK {
		t.Fatalf("capacity advisory changed signed policy apply: %d %s", status, raw)
	}
}
