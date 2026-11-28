package worker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/telemetry"
)

func telemetryProfile(f *fixture, target, endpoint string) TelemetryProfile {
	return TelemetryProfile{Format: TelemetryProfileFormat, Endpoint: endpoint, Identity: target, Domain: f.domain.Trust.Domain, EnrollmentFile: filepath.Join(f.base, "enrollment.json"), MaxBytes: 64 << 10, MaxItems: 2, IntervalSeconds: 60, Enabled: true}
}

type telemetrySendFunc func(context.Context, telemetry.Message) telemetry.Outcome

func (f telemetrySendFunc) Send(ctx context.Context, m telemetry.Message) telemetry.Outcome {
	return f(ctx, m)
}
func TestWorkerTelemetrySharedQuotaRefusesSendWithoutLosingQueue(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w := f.nodes[0]
	cfg := f.config(t, 0, nil)
	ctx := context.Background()
	must(t, w.admit(ctx, cfg))
	p := telemetryProfile(f, f.nodes[1].node, "https://127.0.0.1:1")
	q, e := w.OpenTelemetry(ctx, p, workerEnrollment(t, f, 0), true)
	must(t, e)
	defer q.Close()
	r := telemetry.Record{ObservedUnix: time.Now().Unix(), Events: []telemetry.Event{{Kind: "STATE_CHANGED", State: "COMPLETE"}}}
	must(t, q.Enqueue(ctx, 1, r))
	before, e := q.Status(ctx)
	must(t, e)
	finish, e := w.budget.Reserve(ctx, "telemetry/another-writer.json", 850<<10)
	must(t, e)
	defer finish(false)
	_, e = q.Deliver(ctx, telemetrySendFunc(func(context.Context, telemetry.Message) telemetry.Outcome {
		t.Fatal("sent without durable attempt admission")
		return telemetry.Outcome{}
	}))
	if !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal(e)
	}
	after, e := q.Status(ctx)
	must(t, e)
	if after.Cursor != before.Cursor || after.Pending != before.Pending || after.Digest != before.Digest || after.Attempts != 0 {
		t.Fatal("accepted queue changed under physical quota", before, after)
	}
	snapshot, e := w.ManagementSnapshot(ctx, workerEnrollment(t, f, 0), p.Domain)
	must(t, e)
	if len(snapshot.Generations) != 1 || snapshot.Generations[0].Status != "COMPLETE" {
		t.Fatal("backup inventory changed")
	}
}

func TestWorkerTelemetrySlowSinkFullQueueDoesNotStopBackupRestore(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, _ := f.jobs()
	cfg := f.config(t, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push})
	ctx := context.Background()
	w := f.nodes[0]
	must(t, w.admit(ctx, cfg))
	observer, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer observer.Close()
	cert, target := f.ca.node(t)
	started, release := make(chan struct{}), make(chan struct{})
	firstFinished := make(chan struct{})
	var once sync.Once
	var capturedMu sync.Mutex
	var captured [][]byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedMu.Lock()
		captured = append(captured, body)
		capturedMu.Unlock()
		first := false
		once.Do(func() { first = true; close(started) })
		defer func() {
			if first {
				close(firstFinished)
			}
		}()
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.ca.pool}
	server.StartTLS()
	defer server.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	p := telemetryProfile(f, target, server.URL)
	p.MaxItems = 1
	q, e := observer.OpenTelemetry(ctx, p, workerEnrollment(t, f, 0), true)
	must(t, e)
	defer q.Close()
	if observer.budget != nil || q.ownedBudget == nil {
		t.Fatal("observer stole execution budget")
	}
	client, e := telemetry.NewClient(server.URL, w.cert, f.ca.pool, w.node, target)
	must(t, e)
	defer client.Close()
	// The fixture's five-second job and RPC budgets are unchanged. Observe
	// startup and ordinary durable retries on HDD without treating them as a
	// disk SLA; the receiver must stay blocked through transfer and restore.
	// Its HTTP client's existing 15-second transport timeout is unchanged.
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := observer.TelemetryOnce(bounded, p, q, client); done <- e }()
	<-started
	// The waiting HTTP request owns only the telemetry delivery lease.
	r := telemetry.Record{ObservedUnix: time.Now().Unix(), Events: []telemetry.Event{{Kind: "STATE_CHANGED", State: "UNAVAILABLE"}}}
	if e = q.Enqueue(ctx, 2, r); !errors.Is(e, telemetry.ErrCapacity) {
		unblock()
		t.Fatal("queue limit", e)
	}
	stopB := start(t, f.nodes[1])
	stopA := start(t, w)
	waitFor(t, 60*time.Second, func() bool { return complete(w, push.Operation) })
	stopA()
	stopB()
	replica, e := generation.Open(filepath.Join(DomainDirectory(f.nodes[1].dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	kit := filepath.Join(f.base, "telemetry-independent-kit")
	must(t, replica.ExportKit(ctx, f.generation, f.version, kit))
	reader, e := filekit.OpenStore(kit, f.dataOwner, false)
	must(t, e)
	defer reader.Close()
	output := filepath.Join(f.base, "telemetry-restored")
	_, e = reader.Restore(ctx, f.version, output)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(output, "dataset/\u0434\u0430\u043d\u043d\u044b\u0435.bin"))
	must(t, e)
	if !bytes.Equal(got, f.content) {
		t.Fatal("backup restore changed")
	}
	select {
	case <-firstFinished:
		t.Fatal("telemetry receiver recovered before independent backup and restore")
	default:
	}
	before, e := q.Status(ctx)
	must(t, e)
	if before.Cursor != 1 || before.Pending != 1 || before.Accepted != 0 {
		t.Fatal("unavailable receiver lost or acknowledged queued telemetry", before)
	}
	t.Logf("WORKER_TELEMETRY_BLOCKED_BACKUP_PASS bytes=%d rpcMillis=%d operationMillis=%d receiverStillBlocked=true", len(f.content), cfg.Limits.AttemptMillis, cfg.Limits.OperationTimeout().Milliseconds())
	unblock()
	must(t, <-done)
	s, e := q.Status(ctx)
	must(t, e)
	if s.Accepted == 0 {
		// A normal transport timeout can occur while the receiver is down.
		// Retry the durably retained request after recovery, without changing
		// its deadline, acknowledgement or retry policy.
		_, e = observer.TelemetryOnce(bounded, p, q, client)
		must(t, e)
		s, e = q.Status(ctx)
		must(t, e)
	}
	capturedMu.Lock()
	defer capturedMu.Unlock()
	for _, body := range captured {
		for _, secret := range [][]byte{[]byte("\u0434\u0430\u043d\u043d\u044b\u0435.bin"), []byte(f.base), f.content[:64]} {
			if bytes.Contains(body, secret) {
				t.Fatal("private data exported")
			}
		}
	}
	if s.Cursor != 1 || s.Pending != 1 || s.Accepted != 1 {
		t.Fatal("pending log lost", s)
	}
}
func TestWorkerTelemetryProjectionKeepsOriginalAgeAndDomainScope(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w := f.nodes[0]
	cfg := f.config(t, 0, nil)
	ctx := context.Background()
	must(t, w.admit(ctx, cfg))
	raw := workerEnrollment(t, f, 0)
	s, e := w.ManagementSnapshot(ctx, raw, f.domain.Trust.Domain)
	must(t, e)
	original := time.Now().Add(-time.Hour).Unix()
	s.Generations[0].Verification = "CIPHERTEXT"
	s.Generations[0].VerifiedUnix = original
	record, e := TelemetryRecord(s, w.node)
	must(t, e)
	found := false
	for _, m := range record.Metrics {
		if m.Name == "copy_verified_timestamp_seconds" {
			found = true
			if m.Value == nil || *m.Value != original {
				t.Fatal("verification age refreshed")
			}
		}
	}
	if !found {
		t.Fatal("verification absent")
	}
	p := telemetryProfile(f, f.nodes[1].node, "https://127.0.0.1:1")
	p.Domain = f.nodes[1].node
	if q, e := w.OpenTelemetry(ctx, p, raw, true); e == nil {
		q.Close()
		t.Fatal("foreign domain admitted")
	}
	p.Domain = f.domain.Trust.Domain
	q, e := w.OpenTelemetry(ctx, p, raw, true)
	must(t, e)
	defer q.Close()
	other := p
	other.Domain = f.nodes[1].node
	if _, e = w.TelemetryOnce(ctx, other, q, nil); !errors.Is(e, telemetry.ErrConflict) {
		t.Fatal("runtime profile crossed queue domain", e)
	}
	g, e := management.VerifyEnrollment(raw, w.owner)
	must(t, e)
	g.Revision++
	g.Revoked = true
	revoked, e := management.SignEnrollment(g, f.owner)
	must(t, e)
	must(t, q.Renew(ctx, revoked))
	_, e = w.TelemetryOnce(ctx, p, q, nil)
	if !errors.Is(e, management.ErrDenied) {
		t.Fatal("revoked telemetry sampled", e)
	}
}

func TestWorkerTelemetryReportsObservedLocalReplicaDamage(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	ctx := context.Background()
	w := f.nodes[0]
	must(t, w.admit(ctx, f.config(t, 0, nil)))
	enrollment := workerEnrollment(t, f, 0)
	domain := f.domain.Trust.Domain
	gauge := func(s management.Snapshot) *int64 {
		t.Helper()
		r, err := telemetryRecord(s, w.node, true)
		must(t, err)
		if r.ObservedUnix != s.ObservedUnix {
			t.Fatal("new timestamp assigned to local damage observation")
		}
		for _, m := range r.Metrics {
			if m.Name != "damaged_local_generations" {
				continue
			}
			if m.Target != "" {
				t.Fatal("local inventory metric acquired another scope", m)
			}
			messages, err := telemetry.Encode(w.node, domain, telemetry.Record{ObservedUnix: r.ObservedUnix, Metrics: []telemetry.Metric{m}})
			must(t, err)
			if len(messages) != 1 || messages[0].Signal != "metrics" ||
				bytes.Contains(messages[0].Body, []byte(`"name":"outpost_damaged_local_generations"`)) != (m.Value != nil) ||
				!bytes.Contains(messages[0].Body, []byte(`"name":"outpost_damaged_local_generations_known"`)) {
				t.Fatal("unexpected OTLP encoding for local damage", m)
			}
			return m.Value
		}
		t.Fatal("local damage metric missing")
		return nil
	}

	s, err := w.ManagementSnapshot(ctx, enrollment, domain)
	must(t, err)
	if got := gauge(s); got == nil || *got != 0 {
		t.Fatal("observed intact replica did not yield a known zero")
	}
	catalog := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica", "catalogs", f.generation)
	must(t, os.WriteFile(catalog, []byte("intentionally damaged fixture"), 0600))
	s, err = w.ManagementSnapshot(ctx, enrollment, domain)
	must(t, err)
	if len(s.Generations) != 1 || s.Generations[0].Status != "CORRUPT" {
		t.Fatalf("authenticated local inventory did not retain catalog damage: %+v", s.Generations)
	}
	if got := gauge(s); got == nil || *got != 1 {
		t.Fatal("observed corruption did not yield one damaged generation")
	}
	unconfigured, err := TelemetryRecord(s, w.node)
	must(t, err)
	for _, m := range unconfigured.Metrics {
		if m.Name == "damaged_local_generations" {
			t.Fatal("default sampling introduced a new metric into a compatible queue")
		}
	}
	s.Generations[0].Target = f.nodes[1].node
	if gauge(s) != nil {
		t.Fatal("another target's status was used as measured local damage")
	}
	s.Generations = nil
	if gauge(s) != nil {
		t.Fatal("missing inventory entries were reported as measured zero")
	}
	s.InventoryState = "UNAVAILABLE"
	s.Generations = []management.Generation{}
	if gauge(s) != nil {
		t.Fatal("unavailable inventory was reported as measured zero")
	}
}

func TestWorkerTelemetryLocalDamageProfilePreservesQueueOnReopen(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	ctx := context.Background()
	w := f.nodes[0]
	must(t, w.admit(ctx, f.config(t, 0, nil)))
	p := telemetryProfile(f, f.nodes[1].node, "https://127.0.0.1:1")
	legacyProfile, err := json.Marshal(p)
	must(t, err)
	if bytes.Contains(legacyProfile, []byte("observeLocalReplicaDamage")) {
		t.Fatal("default telemetry profile acquired a schema field")
	}
	profile := filepath.Join(f.base, "telemetry-profile.json")
	must(t, os.WriteFile(profile, legacyProfile, 0600))
	loaded, err := LoadTelemetryProfile(profile)
	must(t, err)
	if loaded != p {
		t.Fatal("existing profile did not round trip")
	}
	enrollment := workerEnrollment(t, f, 0)
	q, err := w.OpenTelemetry(ctx, p, enrollment, true)
	must(t, err)
	at := time.Now().Unix()
	legacy := telemetry.Record{ObservedUnix: at, Metrics: []telemetry.Metric{{Name: "report_observed_timestamp_seconds", Value: &at}}}
	must(t, q.Enqueue(ctx, 1, legacy))
	existing, err := q.Status(ctx)
	must(t, err)
	must(t, q.Close())

	p.ObserveLocalReplicaDamage = true
	q, err = w.OpenTelemetry(ctx, p, nil, false)
	must(t, err)
	reopened, err := q.Status(ctx)
	must(t, err)
	if reopened != existing {
		t.Fatal("sampling option changed the legacy pending receipt")
	}
	step, err := w.TelemetryOnce(ctx, p, q, telemetrySendFunc(func(_ context.Context, m telemetry.Message) telemetry.Outcome {
		if m.Digest != existing.Digest {
			t.Fatal("first delivery was not the already accepted record")
		}
		return telemetry.Outcome{State: "ACCEPTED"}
	}))
	must(t, err)
	if step.Queue.Pending != 1 || step.Queue.Accepted != 1 {
		t.Fatal("sampling option lost the held record or its new measurement", step)
	}
	must(t, q.Close())

	p.ObserveLocalReplicaDamage = false
	q, err = w.OpenTelemetry(ctx, p, nil, false)
	must(t, err)
	defer q.Close()
	delivered := 0
	for range 2 {
		_, err = q.Deliver(ctx, telemetrySendFunc(func(_ context.Context, m telemetry.Message) telemetry.Outcome {
			if m.Signal == "metrics" && bytes.Contains(m.Body, []byte(`"name":"outpost_damaged_local_generations"`)) {
				delivered++
			}
			return telemetry.Outcome{State: "ACCEPTED"}
		}))
		must(t, err)
	}
	end, err := q.Status(ctx)
	must(t, err)
	if delivered != 1 || end.Pending != 0 || end.Accepted != 3 {
		t.Fatal("new samples could not be drained after disabling the option", delivered, end)
	}
}
