package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/recovery"
	"testing"
	"time"
)

func observedScrub(now int64, operation string) CommandObservation {
	return CommandObservation{Operation: operation, EnvelopeDigest: id("envelope" + operation), Kind: "scrub", Phase: "COMPLETE", Generation: id("generation"), StartedUnix: now - 30, FinishedUnix: now - 10, Attempts: 1, VerifiedObjects: 2, TotalObjects: 2, Verification: "CIPHERTEXT", VerifiedUnix: now - 15, ResultDigest: id("result" + operation)}
}

func TestCommandObservationReportVersionBoundsAndOriginalAgeOverHTTPS(t *testing.T) {
	h := newHTTPFixture(t)
	r, options, client := reporterFixture(t, h)
	defer r.Close()
	ctx := context.Background()
	observed := time.Now().Unix() - 20
	snapshot := reporterSnapshot(t, h.f, observed)
	for i := 0; i < 3; i++ {
		snapshot.Commands = append(snapshot.Commands, observedScrub(observed, id(fmt.Sprint(i))))
	}
	raw, e := r.Enqueue(ctx, snapshot)
	must(t, e)
	report, e := VerifyReport(raw, h.f.e, time.Now())
	must(t, e)
	if report.Format != CommandReportFormat || len(report.Commands) != 3 {
		t.Fatal("missing versioned commands")
	}
	// A queued report survives an independent reader and retains exact bytes.
	must(t, r.Close())
	r, e = OpenReporter(options)
	must(t, e)
	defer r.Close()
	pending, e := r.Pending(ctx)
	must(t, e)
	if !bytes.Equal(pending, raw) {
		t.Fatal("pending report changed")
	}
	_, e = r.Deliver(ctx, client)
	must(t, e)
	base := h.base() + "/domains/" + id("domain") + "/command-status?limit=2"
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 2; page++ {
		url := base
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		status, body := h.request(t, h.viewer, "GET", url, nil)
		if status != 200 {
			t.Fatalf("%d %s", status, body)
		}
		var out struct {
			Format       string
			ObservedUnix int64
			State        string
			Items        []CommandObservation
			NextCursor   string
		}
		must(t, json.Unmarshal(body, &out))
		if out.Format != "outpost-management-command-status-1" || out.ObservedUnix != observed || out.State != "STALE" {
			t.Fatal("transport refreshed old observation", out)
		}
		for _, c := range out.Items {
			if seen[c.Operation] || c.VerifiedUnix != observed-15 || c.FinishedUnix != observed-10 {
				t.Fatal("lost original result age", c)
			}
			seen[c.Operation] = true
		}
		cursor = out.NextCursor
	}
	if len(seen) != 3 || cursor != "" {
		t.Fatal("lost pagination", len(seen))
	}
	status, _ := h.request(t, h.unknown, "GET", base, nil)
	if status == 200 {
		t.Fatal("unauthorized command history")
	}
	view, e := h.f.r.Report(ctx, h.f.p, h.f.e.Tenant, h.f.e.Node, id("domain"), time.Second)
	must(t, e)
	if view.Format != "outpost-management-report-view-2" || len(view.Commands) != 3 {
		t.Fatal(view)
	}
	legacy := report
	legacy.Format = ReportFormat
	if _, e = SignReport(legacy, h.f.e, h.f.node, time.Now()); e == nil {
		t.Fatal("new fields silently claimed old contract")
	}
	legacy.Commands = nil
	old, e := SignReport(legacy, h.f.e, h.f.node, time.Now())
	must(t, e)
	if _, e = VerifyReport(old, h.f.e, time.Now()); e != nil {
		t.Fatal("old report compatibility lost", e)
	}
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Commands = append(r.Commands, r.Commands[0]) },
		func(r *Report) { r.Commands[0].VerifiedUnix = r.ObservedUnix + 1 },
		func(r *Report) { r.Commands[0].VerifiedObjects = 3 },
		func(r *Report) { r.Commands[0].Phase = "RUNNING" },
		func(r *Report) { r.Commands[0].Kind = "restore" },
	} {
		var bad Report
		must(t, json.Unmarshal(raw, &bad))
		mutate(&bad)
		if _, e = SignReport(bad, h.f.e, h.f.node, time.Now()); e == nil {
			t.Fatal("inconsistent command observation signed")
		}
	}
}

func TestRecoveryReportVersionAndOriginalTimeOverHTTPS(t *testing.T) {
	h := newHTTPFixture(t)
	r, _, client := reporterFixture(t, h)
	defer r.Close()
	ctx := context.Background()
	now := time.Now().Unix() - 20
	snapshot := reporterSnapshot(t, h.f, now)
	result := recovery.Receipt{Format: recovery.ReceiptFormat, Operation: id("restore"), Binding: id("restore-envelope"), Preset: id("private-preset"), VerifiedUnix: now - 5, Restored: generation.RecoveryReceipt{Generation: id("generation"), Epoch: 1, Sequence: 2, CheckpointMatch: true, Restored: filekit.RecoverySummary{Files: 1, Bytes: 32}}}
	snapshot.Commands = []CommandObservation{{Operation: result.Operation, EnvelopeDigest: result.Binding, Kind: "restore", Phase: "COMPLETE", Generation: result.Restored.Generation, StartedUnix: now - 10, FinishedUnix: now - 3, Attempts: 1, Verification: "DECRYPTED", VerifiedUnix: result.VerifiedUnix, ResultDigest: id("restore-result"), Restore: &result}}
	raw, e := r.Enqueue(ctx, snapshot)
	must(t, e)
	report, e := VerifyReport(raw, h.f.e, time.Now())
	must(t, e)
	if report.Format != RecoveryReportFormat {
		t.Fatal("missing reader fence")
	}
	_, e = r.Deliver(ctx, client)
	must(t, e)
	view, e := h.f.r.Report(ctx, h.f.p, h.f.e.Tenant, h.f.e.Node, id("domain"), time.Second)
	must(t, e)
	if view.Format != "outpost-management-report-view-3" || view.State != "STALE" || view.Commands[0].VerifiedUnix != now-5 {
		t.Fatal("report refreshed recovery", view)
	}
	status, body := h.request(t, h.viewer, "GET", h.base()+"/domains/"+id("domain")+"/command-status?limit=1", nil)
	if status != 200 {
		t.Fatalf("%d %s", status, body)
	}
	var page struct {
		Format string
		Items  []CommandObservation
	}
	must(t, json.Unmarshal(body, &page))
	if page.Format != "outpost-management-command-status-2" || len(page.Items) != 1 || page.Items[0].Restore.VerifiedUnix != now-5 {
		t.Fatal("restore page lost version/original age", page)
	}
	for _, format := range []string{ReportFormat, CommandReportFormat} {
		copy := report
		copy.Format = format
		if _, e = SignReport(copy, h.f.e, h.f.node, time.Now()); e == nil {
			t.Fatal("new result accepted old format")
		}
	}
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Commands[0].Restore.Binding = id("wrong-envelope") },
		func(r *Report) { r.Commands[0].Restore.Restored.Restored.Bytes = -1 },
		func(r *Report) { r.Commands[0].Restore.Restored.Sequence = 1 << 63 },
		func(r *Report) { r.Commands[0].VerifiedUnix++ },
		func(r *Report) { r.Commands[0].Restore.Restored.CheckpointMatch = false },
	} {
		var bad Report
		must(t, json.Unmarshal(raw, &bad))
		mutate(&bad)
		if _, e = SignReport(bad, h.f.e, h.f.node, time.Now()); e == nil {
			t.Fatal("invalid recovery report signed")
		}
	}
}
