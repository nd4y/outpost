package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/telemetry"
	"github.com/nd4y/outpost/internal/upload"
)

func TestHTTPAttemptObservationReopensAndRejectsForeignEvidence(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	ctx := context.Background()
	w := f.nodes[0]
	must(t, w.admit(ctx, f.config(t, 0, nil)))
	started := time.Now().Add(-5 * time.Second)
	a := upload.HTTPAttempt{
		Node: w.node, Domain: f.domain.Trust.Domain, Target: storage.Hash([]byte("target")),
		Operation: storage.Hash([]byte("operation")), Plan: storage.Hash([]byte("plan")),
		Attempt: 1, StartedMillis: started.UnixMilli(), Outcome: "STARTED",
	}
	must(t, w.writeExternalHTTPAttempt(ctx, a))

	reader, err := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, err)
	defer reader.Close()
	snapshot := management.Snapshot{ObservedUnix: time.Now().Unix(), ExternalState: "OBSERVED",
		ExternalCopies: []management.ExternalCopy{{Target: a.Target, Operation: a.Operation}},
	}
	observe := func(name string) *int64 {
		t.Helper()
		r := telemetry.Record{ObservedUnix: snapshot.ObservedUnix}
		reader.addExternalHTTPMetrics(ctx, a.Domain, 1, snapshot, &r)
		_, err := telemetry.Encode(w.node, a.Domain, r)
		must(t, err)
		for _, m := range r.Metrics {
			if m.Target == a.Target && m.Name == name {
				return m.Value
			}
		}
		t.Fatalf("missing scoped metric %s", name)
		return nil
	}
	const requestBytes = "external_http_attempt_request_body_bytes"
	if value := observe(requestBytes); value != nil {
		t.Fatal("unfinished attempt has a byte count", *value)
	}
	finished := a
	finished.Outcome = "SUCCEEDED"
	finished.FinishedMillis = started.Add(time.Second).UnixMilli()
	finished.Counts = &storage.HTTPBodyCounts{Requests: 1, PutRequests: 1, RequestBytes: 17}
	must(t, w.writeExternalHTTPAttempt(ctx, finished))
	must(t, w.writeExternalHTTPAttempt(ctx, finished))
	if value := observe(requestBytes); value == nil || *value != 17 {
		t.Fatal("reopened measurement differs", value)
	}
	if value := observe("external_http_attempt_observed_timestamp_seconds"); value == nil || *value != finished.FinishedMillis/1000 {
		t.Fatal("reopened measurement lost original time", value)
	}
	snapshot.ExternalCopies[0].Operation = storage.Hash([]byte("unrelated"))
	if value := observe(requestBytes); value != nil {
		t.Fatal("another operation exposed an observation", *value)
	}
	snapshot.ExternalCopies[0].Operation = a.Operation

	a.Attempt++
	a.StartedMillis = started.Add(2 * time.Second).UnixMilli()
	must(t, w.writeExternalHTTPAttempt(ctx, a))
	must(t, w.writeExternalHTTPAttempt(ctx, finished))
	if value := observe(requestBytes); value != nil {
		t.Fatal("old completion replaced current start", *value)
	}
	path := filepath.Join(w.dir, externalHTTPDirectory, externalHTTPName(a.Domain, a.Target))
	raw, err := os.ReadFile(path)
	must(t, err)
	changed := bytes.Replace(raw, []byte(`"attempt":2`), []byte(`"attempt":3`), 1)
	if bytes.Equal(raw, changed) {
		t.Fatal("fixture did not change the signed attempt")
	}
	must(t, os.WriteFile(path, changed, 0600))
	if value := observe(requestBytes); value != nil {
		t.Fatal("invalid observation was exported", *value)
	}
	a.Attempt++
	if err := w.writeExternalHTTPAttempt(ctx, a); !errors.Is(err, telemetry.ErrInvalid) {
		t.Fatal("invalid evidence was overwritten", err)
	}
}

func TestHTTPAttemptObservationSelectsBoundedTargetPages(t *testing.T) {
	w := Worker{node: storage.Hash([]byte("node"))}
	domain := storage.Hash([]byte("domain"))
	snapshot := management.Snapshot{ExternalState: "OBSERVED", InventoryState: "OBSERVED"}
	for i := 0; i < 17; i++ {
		id := fmt.Sprintf("%064x", i+1)
		snapshot.ExternalCopies = append(snapshot.ExternalCopies, management.ExternalCopy{Target: id, Operation: id})
	}
	const interval = 30
	for page, want := range []int{8, 8, 1} {
		snapshot.ObservedUnix = int64(interval * (10002 + page))
		r, err := TelemetryRecord(snapshot, w.node)
		must(t, err)
		w.addExternalHTTPMetrics(context.Background(), domain, interval, snapshot, &r)
		_, err = telemetry.Encode(w.node, domain, r)
		must(t, err)
		seen := 0
		for _, m := range r.Metrics {
			switch m.Name {
			case "external_http_targets_in_scope":
				if m.Value == nil || *m.Value != 17 {
					t.Fatal("incorrect target coverage", m)
				}
			case "external_http_targets_selected":
				if m.Value == nil || *m.Value != int64(want) {
					t.Fatal("incorrect page coverage", m)
				}
			case "external_http_attempt_requests":
				id := fmt.Sprintf("%064x", page*8+seen+1)
				if m.Target != id || m.Value != nil {
					t.Fatal("wrong target page or fabricated count", page, m)
				}
				seen++
			default:
				if strings.HasPrefix(m.Name, "external_http_attempt_") && m.Value != nil {
					t.Fatal("unavailable record produced a measurement", m)
				}
			}
		}
		if seen != want {
			t.Fatal("missing target page", page, seen)
		}
	}
}
