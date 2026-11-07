package management

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestExternalCopyReportVersionBindingAndOriginalAgeOverHTTPS(t *testing.T) {
	h := newHTTPFixture(t)
	r, _, client := reporterFixture(t, h)
	defer r.Close()
	ctx := context.Background()
	now := time.Now().Unix() - 20
	snapshot := reporterSnapshot(t, h.f, now)
	snapshot.ExternalState = "OBSERVED"
	snapshot.Jobs = append(snapshot.Jobs, Job{Operation: id("cloud-op"), Domain: id("domain"), Generation: id("generation"), Kind: "UPLOAD", Phase: "COMPLETE", UpdatedUnix: now})
	snapshot.ExternalCopies = []ExternalCopy{{Operation: id("cloud-op"), Generation: id("generation"), Target: id("cloud-target"), State: "OBSERVED_COMPLETE", Verification: "cached-target-readback", VerifiedUnix: now - 300, ReceiptDigest: id("original-cloud-receipt")}}
	raw, e := r.Enqueue(ctx, snapshot)
	must(t, e)
	report, e := VerifyReport(raw, h.f.e, time.Now())
	must(t, e)
	if report.Format != ExternalReportFormat {
		t.Fatal(report.Format)
	}
	_, e = r.Deliver(ctx, client)
	must(t, e)
	code, body := h.request(t, h.viewer, "GET", h.base()+"/domains/"+id("domain")+"/report", nil)
	if code != 200 {
		t.Fatal(code, string(body))
	}
	var view ReportView
	must(t, json.Unmarshal(body, &view))
	if view.Format != "outpost-management-report-view-5" || view.ExternalState != "OBSERVED" || len(view.ExternalCopies) != 1 || view.ExternalCopies[0] != snapshot.ExternalCopies[0] || view.ObservedUnix != now {
		t.Fatal(view)
	}
	// Renewing the report does not renew a target readback.
	snapshot.ObservedUnix = now + 1
	_, e = r.Enqueue(ctx, snapshot)
	must(t, e)
	_, e = r.Deliver(ctx, client)
	must(t, e)
	view, e = h.f.r.Report(ctx, h.f.p, h.f.e.Tenant, h.f.e.Node, id("domain"), time.Second)
	must(t, e)
	if view.State != "STALE" || view.ExternalCopies[0].VerifiedUnix != now-300 {
		t.Fatal("old proof refreshed", view)
	}
	for _, format := range []string{ReportFormat, CommandReportFormat, RecoveryReportFormat, CatalogReportFormat} {
		copy := report
		copy.Format = format
		if _, e = SignReport(copy, h.f.e, h.f.node, time.Now()); e == nil {
			t.Fatal("old format accepted new claims")
		}
	}
	for _, mutate := range []func(*Report){
		func(r *Report) { r.ExternalCopies[0].VerifiedUnix = r.ObservedUnix + 1 },
		func(r *Report) { r.ExternalCopies[0].Generation = id("other-generation") },
		func(r *Report) { r.ExternalCopies[0].Target = "https://private.invalid" },
		func(r *Report) { r.ExternalCopies[0].ReceiptDigest = "" },
		func(r *Report) { r.ExternalCopies[0].State = "UNCONFIRMED" },
		func(r *Report) { r.ExternalCopies = append(r.ExternalCopies, r.ExternalCopies[0]) },
		func(r *Report) { r.ExternalCopies = nil },
		func(r *Report) { r.Jobs[len(r.Jobs)-1].Kind = "PEER" },
		func(r *Report) { r.ExternalState = "CURRENT" },
	} {
		var bad Report
		must(t, json.Unmarshal(raw, &bad))
		mutate(&bad)
		if _, e = SignReport(bad, h.f.e, h.f.node, time.Now()); e == nil {
			t.Fatal("invalid external observation accepted")
		}
	}
}
