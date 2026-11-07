package worker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func commandEnrollment(t *testing.T, f *fixture) []byte {
	t.Helper()
	grant, e := management.VerifyEnrollment(workerEnrollment(t, f, 0), f.nodes[0].owner)
	must(t, e)
	grant.Tenant = storage.Hash([]byte("tenant"))
	raw, e := management.SignEnrollment(grant, f.owner)
	must(t, e)
	return raw
}

func TestWorkerCommandReportQueuedScrubAndOriginalCompletionWithoutTenantLeak(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	cfg, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	_, e := w.ExecuteCommand(ctx, makeCommand("pause", "", 1))
	must(t, e)
	scrub := makeCommand("scrub", f.generation, 2)
	_, e = w.ExecuteCommand(ctx, scrub)
	must(t, e)
	stop := start(t, w)
	defer stop()
	wait(t, func() bool { s, e := w.Status(ctx); return e == nil && s.Revision == cfg.Revision })
	enrollment := commandEnrollment(t, f)
	snapshot, e := w.ManagementSnapshot(ctx, enrollment, f.domain.Trust.Domain)
	must(t, e)
	if len(snapshot.Commands) != 1 || snapshot.Commands[0].Phase != "QUEUED" || snapshot.Commands[0].Verification != "" || snapshot.Commands[0].FinishedUnix != 0 || len(snapshot.Jobs) != 0 {
		t.Fatal("queued action claimed outcome", snapshot.Commands)
	}
	_, e = w.ExecuteCommand(ctx, makeCommand("resume", "", 3))
	must(t, e)
	record := waitAction(t, w, scrub)
	stop()
	snapshot, e = w.ManagementSnapshot(ctx, enrollment, f.domain.Trust.Domain)
	must(t, e)
	var original ScrubReceipt
	must(t, json.Unmarshal(record.Result, &original))
	c := snapshot.Commands[0]
	if c.Phase != "COMPLETE" || c.VerifiedUnix != original.VerifiedAt || c.Verification != "CIPHERTEXT" || c.ResultDigest != storage.Hash(record.Result) || c.VerifiedObjects != uint64(original.VerifiedObjects) {
		t.Fatal("actual scrub observation lost", c)
	}
	reporter, e := w.OpenReporter(ctx, storage.Hash([]byte("report-target")), f.domain.Trust.Domain, enrollment, true)
	must(t, e)
	defer reporter.Close()
	raw, e := reporter.Enqueue(ctx, snapshot)
	must(t, e)
	grant, e := management.VerifyEnrollment(enrollment, w.owner)
	must(t, e)
	report, e := management.VerifyReport(raw, grant, time.Now())
	must(t, e)
	if report.Format != management.ExternalReportFormat || len(report.Commands) != 1 || report.Generations[0].VerifiedUnix != 0 {
		t.Fatal("command observation recertified whole inventory")
	}
	other, e := w.ManagementSnapshot(ctx, workerEnrollment(t, f, 0), f.domain.Trust.Domain)
	must(t, e)
	if len(other.Commands) != 0 {
		t.Fatal("command result leaked across tenant enrollment")
	}
}

func TestWorkerCommandReportMaintenanceRetainsReplicaOutcome(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	replica, _, makeCommand := maintenanceCommandFixture(t, f)
	w := f.nodes[0]
	ctx := context.Background()
	op := storage.Hash([]byte("maintenance-report"))
	permit := maintenancePermit(t, f, replica, op, f.maintenance, f.generation)
	raw := makeCommand(permit, op, 1)
	_, e := w.ExecuteCommand(ctx, raw)
	must(t, e)
	stop := start(t, w)
	record := waitAction(t, w, raw)
	stop()
	snapshot, e := w.ManagementSnapshot(ctx, commandEnrollment(t, f), f.domain.Trust.Domain)
	must(t, e)
	var original MaintenanceReceipt
	must(t, json.Unmarshal(record.Result, &original))
	if len(snapshot.Commands) != 1 || snapshot.Commands[0].Maintenance == nil || *snapshot.Commands[0].Maintenance != original.Result || snapshot.Commands[0].ResultDigest != storage.Hash(record.Result) {
		t.Fatal("maintenance result lost", snapshot.Commands)
	}
	if e = snapshot.Commands[0].Validate(snapshot.ObservedUnix); e != nil {
		t.Fatal(e)
	}
}
