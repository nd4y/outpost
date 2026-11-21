package management

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func untilReporter(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reporting state did not converge")
}
func TestReporterDispatchRetriesWithoutNewObservationAndKeepsDeadlineOnRestart(t *testing.T) {
	h := newHTTPFixture(t)
	r, o, c := reporterFixture(t, h)
	cfg := DispatchConfig{Format: DispatchFormat, Revision: 1, Enabled: true, IntervalSeconds: 3600, RetrySeconds: 1, AttemptSeconds: 2}
	must(t, r.SetDispatch(context.Background(), cfg))
	var captures, failures atomic.Int64
	h.f.r.Fault = func(point string) error {
		if point == "management-report-pointer-durable" && failures.Add(1) == 1 {
			return errors.New("lost reply")
		}
		return nil
	}
	observed := time.Now().Unix() - 60
	snapshot := reporterSnapshot(t, h.f, observed)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.RunDispatch(ctx, c, func(context.Context, []byte, string) (Snapshot, error) { captures.Add(1); return snapshot, nil })
	}()
	untilReporter(t, func() bool {
		s, e := r.DispatchStatus(context.Background())
		if e != nil || s.Phase != "READY" || s.LastAttemptUnix == 0 {
			return false
		}
		pending, e := r.Pending(context.Background())
		return e == nil && pending == nil
	})
	status, e := r.DispatchStatus(context.Background())
	must(t, e)
	if captures.Load() != 1 || failures.Load() < 1 || status.NextUnix <= time.Now().Unix() {
		t.Fatal("retry refreshed snapshot or lost schedule", captures.Load(), status)
	}
	view, e := h.f.r.Report(context.Background(), h.f.p, h.f.e.Tenant, h.f.e.Node, id("domain"), time.Second)
	must(t, e)
	if view.ObservedUnix != observed || view.Sequence != 1 || view.State != "STALE" {
		t.Fatal("scheduled replay changed age", view)
	}
	cancel()
	if e = <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	must(t, r.Close())
	r, e = OpenReporter(o)
	must(t, e)
	defer r.Close()
	after, e := r.DispatchStatus(context.Background())
	must(t, e)
	if after.NextUnix != status.NextUnix || after.Config != status.Config {
		t.Fatal("restart reset schedule")
	}
	short, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stop()
	e = r.RunDispatch(short, c, func(context.Context, []byte, string) (Snapshot, error) { captures.Add(1); return snapshot, nil })
	if !errors.Is(e, context.DeadlineExceeded) || captures.Load() != 1 {
		t.Fatal("early restart capture", e, captures.Load())
	}
	cfg.IntervalSeconds = 1
	if e = r.SetDispatch(context.Background(), cfg); !errors.Is(e, ErrConflict) {
		t.Fatal("same revision changed schedule")
	}
}

func TestReporterDispatchPauseCancelsBlockedHTTPAndPreservesPending(t *testing.T) {
	testReporterDispatchCancellation(t, false)
}
func TestReporterDispatchRevocationCancelsBlockedHTTP(t *testing.T) {
	testReporterDispatchCancellation(t, true)
}
func testReporterDispatchCancellation(t *testing.T, revoke bool) {
	h := newHTTPFixture(t)
	r, o, _ := reporterFixture(t, h)
	defer r.Close()
	cfg := DispatchConfig{Format: DispatchFormat, Revision: 1, Enabled: true, IntervalSeconds: 3600, RetrySeconds: 1, AttemptSeconds: 30}
	must(t, r.SetDispatch(context.Background(), cfg))
	entered, disconnected := make(chan struct{}), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.Copy(io.Discard, req.Body)
		close(entered)
		<-req.Context().Done()
		close(disconnected)
	}))
	server.TLS = h.server.TLS.Clone()
	server.StartTLS()
	defer server.Close()
	tlsCfg := h.node.Transport.(*http.Transport).TLSClientConfig
	client, e := NewReportClient(server.URL, o.Target, h.f.e.Node, tlsCfg.Certificates[0], tlsCfg.RootCAs, 30*time.Second)
	must(t, e)
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	snapshot := reporterSnapshot(t, h.f, time.Now().Unix()-10)
	go func() {
		done <- r.RunDispatch(ctx, client, func(context.Context, []byte, string) (Snapshot, error) { return snapshot, nil })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	raw, e := r.Pending(context.Background())
	must(t, e)
	if len(raw) == 0 {
		t.Fatal("network before durable queue")
	}
	if revoke {
		grant := h.f.e
		grant.Revision++
		grant.Revoked = true
		signed, e := SignEnrollment(grant, h.f.owner)
		must(t, e)
		must(t, r.Renew(context.Background(), signed))
	} else {
		cfg.Revision++
		cfg.Enabled = false
		must(t, r.SetDispatch(context.Background(), cfg))
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("pause did not cancel blocked HTTPS")
	}
	cancel()
	if e = <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	state, e := r.DispatchStatus(context.Background())
	must(t, e)
	pending, e := r.Pending(context.Background())
	must(t, e)
	if !revoke && (state.Phase != "PAUSED" || !bytes.Equal(raw, pending)) {
		t.Fatal("pause lost durable pending observation")
	}
	if revoke {
		queue, e := r.Status(context.Background())
		must(t, e)
		if queue.EnrollmentActive || pending != nil || queue.Sequence != 1 {
			t.Fatal("revocation lost fence", queue)
		}
	}
}
