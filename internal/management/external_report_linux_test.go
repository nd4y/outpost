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

func TestExternalAuditReportCarriesLossAndOriginalReceiptOverHTTPS(t *testing.T) {
	h := newHTTPFixture(t)
	r, _, client := reporterFixture(t, h)
	defer r.Close()
	ctx := context.Background()
	now := time.Now().Unix() - 20
	snapshot := reporterSnapshot(t, h.f, now)
	snapshot.ExternalState = "OBSERVED"
	job := Job{Operation: id("audited-cloud-op"), Domain: id("domain"), Generation: id("generation"), Kind: "UPLOAD", Phase: "COMPLETE", UpdatedUnix: now - 200}
	audit := ExternalAuditObservation{State: "MISSING", ObservedUnix: now - 3, FinishedUnix: now - 3, ExpiresUnix: now + 1}
	copy := ExternalCopy{Operation: job.Operation, Generation: job.Generation, Target: id("audited-cloud-target"), State: "OBSERVED_COMPLETE",
		Verification: "full-target-readback", VerifiedUnix: now - 201, ReceiptDigest: id("historical-audited-receipt"), Audit: &audit}
	snapshot.Jobs = append(snapshot.Jobs, job)
	snapshot.ExternalCopies = []ExternalCopy{copy}
	raw, err := r.Enqueue(ctx, snapshot)
	must(t, err)
	signed, err := VerifyReport(raw, h.f.e, time.Now())
	must(t, err)
	if signed.Format != ExternalAuditReportFormat {
		t.Fatal("audit omitted from versioned report", signed.Format)
	}
	_, err = r.Deliver(ctx, client)
	must(t, err)
	code, body := h.request(t, h.viewer, "GET", h.base()+"/domains/"+id("domain")+"/report", nil)
	if code != 200 {
		t.Fatal(code, string(body))
	}
	var view ReportView
	must(t, json.Unmarshal(body, &view))
	if view.Format != "outpost-management-report-view-6" || len(view.ExternalCopies) != 1 ||
		view.ExternalCopies[0].Audit == nil || *view.ExternalCopies[0].Audit != audit ||
		view.ExternalCopies[0].VerifiedUnix != copy.VerifiedUnix || view.ExternalCopies[0].ReceiptDigest != copy.ReceiptDigest {
		t.Fatal("scope or age changed in the view", view)
	}
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Format = ExternalReportFormat },
		func(r *Report) { r.ExternalCopies[0].Audit = nil },
		func(r *Report) { r.ExternalCopies[0].Audit.State = "COMPLETE" },
		func(r *Report) { r.ExternalCopies[0].Audit.ExpiresUnix = now - 4 },
		func(r *Report) { r.ExternalCopies[0].Audit.ObservedUnix = now - 301 },
		func(r *Report) { r.ExternalCopies[0].Audit.FinishedUnix = now + 1 },
		func(r *Report) {
			duplicate := job
			duplicate.Operation = id("second-audit-same-target")
			r.Jobs = append(r.Jobs, duplicate)
			extra := copy
			extra.Operation = duplicate.Operation
			r.ExternalCopies = append(r.ExternalCopies, extra)
		},
	} {
		var bad Report
		must(t, json.Unmarshal(raw, &bad))
		mutate(&bad)
		if _, err = SignReport(bad, h.f.e, h.f.node, time.Now()); err == nil {
			t.Fatal("invalid scheduled observation accepted")
		}
	}
}
