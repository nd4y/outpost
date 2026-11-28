package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/storage"
)

func TestManagementVerifiedRestoresUseExactAuthenticatedScope(t *testing.T) {
	for _, tc := range []struct {
		name       string
		versions   []string
		scope      string
		wrongEpoch bool
	}{
		{name: "whole", scope: "WHOLE_GENERATION"},
		{name: "selected", versions: []string{id("version")}, scope: "SELECTED_VERSIONS"},
		{name: "signed-wrong-epoch", scope: "WHOLE_GENERATION", wrongEpoch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHTTPFixture(t)
			f := h.f
			_, request, node := commandFixture(t, f)
			ctx := context.Background()
			request.Kind = "restore"
			request.Generation = id("generation")
			request.Preset = id("trusted-restore-preset")
			request.Versions = tc.versions
			request.Operation = id("verified-restore")
			_, err := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, request)
			must(t, err)
			items, _, err := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
			must(t, err)
			if len(items) != 1 {
				t.Fatal("restore envelope missing", items)
			}
			envelope := items[0].Document
			effect, authority, err := command.VerifyEnvelope(envelope, f.options.Owner)
			must(t, err)
			verified := effect.AdmittedUnix
			finished := time.Now().Unix()
			epoch := authority.WriterEpoch
			if tc.wrongEpoch {
				epoch++
			}
			const logicalBytes = int64(9007199254740993)
			result := recovery.Receipt{Format: recovery.ReceiptFormat, Operation: request.Operation, Binding: storage.Hash(envelope), Preset: request.Preset, VerifiedUnix: verified, Restored: generation.RecoveryReceipt{Generation: request.Generation, Epoch: epoch, Sequence: 1, CheckpointMatch: true, Restored: filekit.RecoverySummary{Files: 1, Bytes: logicalBytes}}}
			payload, err := json.Marshal(result)
			must(t, err)
			ack := command.Ack{Format: command.AckFormat, Node: f.e.Node, Operation: request.Operation, EnvelopeDigest: result.Binding, State: "COMPLETE", StartedUnix: verified, ObservedUnix: finished, ControlRevision: 1, ResultDigest: storage.Hash(payload)}
			signedAck, err := command.SignAck(ack, envelope, f.options.Owner, f.node, time.Now())
			must(t, err)

			report, err := VerifyReport(f.report(t, 1, finished), f.e, time.Now())
			must(t, err)
			report.Format = RecoveryReportFormat
			other := report.Generations[0]
			other.Target = id("other-target")
			report.Generations = append(report.Generations, other)
			observation := CommandObservation{Operation: request.Operation, EnvelopeDigest: result.Binding, Kind: "restore", Phase: "COMPLETE", Generation: request.Generation, StartedUnix: verified, FinishedUnix: finished, Attempts: 1, Verification: "DECRYPTED", VerifiedUnix: verified, ResultDigest: ack.ResultDigest, Restore: &result}
			report.Commands = []CommandObservation{observation}
			path := h.base() + "/domains/" + request.Domain + "/verified-restores"
			check := func(want []VerifiedRestore) {
				t.Helper()
				signed, err := SignReport(report, f.e, f.node, time.Now())
				must(t, err)
				_, err = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, signed)
				must(t, err)
				for _, suffix := range []string{"", "?include=earliest-retained-whole-restore"} {
					selected := append([]VerifiedRestore(nil), want...)
					if suffix != "" && len(selected) != 0 && !tc.wrongEpoch && tc.scope == "WHOLE_GENERATION" {
						selected[0].EarliestRetainedWholeRestore = &RetainedWholeRestore{Operation: request.Operation, VerifiedUnix: verified}
					}
					status, body := h.request(t, h.viewer, "GET", path+suffix, nil)
					if status != 200 {
						t.Fatalf("GET verified restores: %d %s", status, body)
					}
					var got struct {
						Format         string
						DocumentDigest string
						Items          []VerifiedRestore
					}
					must(t, json.Unmarshal(body, &got))
					if got.Format != "outpost-management-verified-restores-1" || got.DocumentDigest != storage.Hash(signed) || got.Items == nil || len(got.Items) != len(selected) || len(selected) > 0 && !reflect.DeepEqual(got.Items[0], selected[0]) {
						t.Fatalf("verified restores %q: got %+v, want %+v", suffix, got, selected)
					}
					if suffix == "" && bytes.Contains(body, []byte("earliestRetainedWholeRestore")) {
						t.Fatal("default legacy projection included an unrequested field")
					}
				}
				report.Sequence++
			}
			check(nil)
			_, err = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, f.e.Node, request.Operation, signedAck)
			must(t, err)
			want := VerifiedRestore{Operation: request.Operation, Generation: request.Generation, Target: f.e.Node, VerifiedUnix: verified, Scope: tc.scope}
			if tc.scope == "WHOLE_GENERATION" {
				want.LogicalMeasurement = &LogicalMeasurement{Operation: request.Operation, LogicalBytes: logicalBytes, MeasuredUnix: verified}
			}
			check([]VerifiedRestore{want})
			foreign := h.base() + "/domains/" + id("foreign-domain") + "/verified-restores"
			if status, _ := h.request(t, h.viewer, "GET", foreign+"?include=earliest-retained-whole-restore", nil); status != 403 && status != 404 {
				t.Fatalf("scoped viewer read an unknown domain: %d", status)
			}
			for _, bad := range []struct{ method, target string }{
				{http.MethodGet, path + "?include=earliest-retained-whole-restore&include=earliest-retained-whole-restore"},
				{http.MethodGet, path + "?include=unrecognized"},
				{http.MethodGet, path + "?include=earliest-retained-whole-restore&extra=1"},
				{http.MethodGet, path + "?unrecognized=1"},
				{http.MethodGet, h.base() + "/domains/" + request.Domain + "/report?include=earliest-retained-whole-restore"},
				{http.MethodPost, path + "?include=earliest-retained-whole-restore"},
			} {
				if status, _ := h.request(t, h.viewer, bad.method, bad.target, nil); status != http.StatusBadRequest {
					t.Fatalf("%s %s: status = %d, want 400", bad.method, bad.target, status)
				}
			}
			report.Commands[0].ResultDigest = id("wrong-result-digest")
			check(nil)
			report.Commands[0] = observation
			report.Generations = report.Generations[1:]
			check(nil)
		})
	}
}

func TestVerifiedRestoreLogicalMeasurementSurvivesSelectedRestore(t *testing.T) {
	selected := VerifiedRestore{Operation: id("selected"), VerifiedUnix: 30, Scope: "SELECTED_VERSIONS"}
	whole := VerifiedRestore{Operation: id("whole"), VerifiedUnix: 20, Scope: "WHOLE_GENERATION"}
	previous := updateVerifiedRestore(VerifiedRestore{}, selected, 123, false)
	if previous.LogicalMeasurement != nil {
		t.Fatal("selected restore established a logical generation size", previous)
	}
	previous = updateVerifiedRestore(previous, whole, 0, false)
	want := LogicalMeasurement{Operation: whole.Operation, LogicalBytes: 0, MeasuredUnix: 20}
	if previous.Operation != selected.Operation || previous.VerifiedUnix != 30 || previous.LogicalMeasurement == nil || *previous.LogicalMeasurement != want {
		t.Fatal("newer selection hid an older whole-generation measurement", previous)
	}
	older := VerifiedRestore{Operation: id("older whole"), VerifiedUnix: 10, Scope: "WHOLE_GENERATION"}
	previous = updateVerifiedRestore(previous, older, 99, false)
	if previous.Operation != selected.Operation || *previous.LogicalMeasurement != want {
		t.Fatal("an older whole-generation receipt replaced the latest measurement", previous)
	}
}

func TestVerifiedRestoreEarliestRetainedWholePreservesLatestAndLegacyJSON(t *testing.T) {
	legacy := []byte(`{"operationId":"selected","generation":"generation","target":"node","verifiedUnix":30,"scope":"SELECTED_VERSIONS","logicalMeasurement":{"operationId":"newest-whole","logicalBytes":"64","measuredUnix":20}}`)
	var current VerifiedRestore
	must(t, json.Unmarshal(legacy, &current))
	if current.EarliestRetainedWholeRestore != nil {
		t.Fatal("legacy JSON fabricated an earliest restore")
	}
	encoded, err := json.Marshal(current)
	must(t, err)
	if !bytes.Equal(encoded, legacy) {
		t.Fatalf("legacy JSON changed: %s", encoded)
	}
	selected := VerifiedRestore{Operation: "earlier-selected", VerifiedUnix: 5, Scope: "SELECTED_VERSIONS"}
	current = updateVerifiedRestore(current, selected, 1, true)
	if current.EarliestRetainedWholeRestore != nil {
		t.Fatal("selected versions established a whole-generation milestone")
	}
	newest := VerifiedRestore{Operation: "newest-whole", VerifiedUnix: 20, Scope: "WHOLE_GENERATION"}
	current = updateVerifiedRestore(current, newest, 64, true)
	older := VerifiedRestore{Operation: "older-whole", VerifiedUnix: 10, Scope: "WHOLE_GENERATION"}
	current = updateVerifiedRestore(current, older, 8, true)
	if got := current.EarliestRetainedWholeRestore; got == nil || got.Operation != older.Operation || got.VerifiedUnix != older.VerifiedUnix {
		t.Fatalf("out-of-order older evidence was lost: %+v", got)
	}
	if current.Operation != "selected" || current.VerifiedUnix != 30 || current.Scope != "SELECTED_VERSIONS" ||
		current.LogicalMeasurement == nil || current.LogicalMeasurement.Operation != newest.Operation || current.LogicalMeasurement.LogicalBytes != 64 {
		t.Fatal("earliest evidence displaced the latest restore or logical measurement", current)
	}
	later := VerifiedRestore{Operation: "later-whole", VerifiedUnix: 40, Scope: "WHOLE_GENERATION"}
	current = updateVerifiedRestore(current, later, 128, true)
	if current.Operation != later.Operation || current.LogicalMeasurement.Operation != later.Operation ||
		current.EarliestRetainedWholeRestore.Operation != older.Operation {
		t.Fatal("newest whole restore changed the retained earliest evidence", current)
	}
}
