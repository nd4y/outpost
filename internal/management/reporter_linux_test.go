package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/teststore"
)

func reporterFixture(t *testing.T, h *httpFixture) (*Reporter, ReporterOptions, *ReportClient) {
	t.Helper()
	f := h.f
	f.enroll(t)
	raw, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	o := ReporterOptions{Directory: filepath.Join(teststore.Root(t), "reporter"), Owner: f.options.Owner, Signer: f.node, Target: identity(f.options.Signer.Public().(ed25519.PublicKey)), Domain: id("domain"), Enrollment: raw, Initialize: true}
	r, e := OpenReporter(o)
	must(t, e)
	o.Initialize = false
	o.Enrollment = nil
	cfg := h.node.Transport.(*http.Transport).TLSClientConfig
	c, e := NewReportClient(h.server.URL, o.Target, f.e.Node, cfg.Certificates[0], cfg.RootCAs, time.Second)
	must(t, e)
	t.Cleanup(c.Close)
	return r, o, c
}
func reporterSnapshot(t *testing.T, f *fixture, observed int64) Snapshot {
	t.Helper()
	report, e := VerifyReport(f.report(t, 1, observed), f.e, time.Now())
	must(t, e)
	return Snapshot{EnrollmentRevision: f.e.Revision, ConfigurationRevision: 1, ObservedUnix: observed, Generations: report.Generations, Jobs: report.Jobs, Space: report.Space}
}
func TestReporterLostReplyRestartAndUnknownVerificationRemainHonest(t *testing.T) {
	h := newHTTPFixture(t)
	r, o, c := reporterFixture(t, h)
	ctx := context.Background()
	snap := reporterSnapshot(t, h.f, time.Now().Unix()-60)
	snap.Generations[0].LogicalBytes = nil
	snap.Generations[0].Verification = "NONE"
	snap.Generations[0].VerifiedUnix = 0
	raw, e := r.Enqueue(ctx, snap)
	must(t, e)
	if _, e = r.Enqueue(ctx, snap); !errors.Is(e, ErrConflict) {
		t.Fatal("pending observation overwritten", e)
	}
	// The registry committed, but its response is lost. Reopening the local
	// queue must send the same bytes, sequence and old observation time.
	h.f.r.Fault = func(point string) error {
		if point == "management-report-pointer-durable" {
			return errors.New("reply lost")
		}
		return nil
	}
	if _, e = r.Deliver(ctx, c); e == nil {
		t.Fatal("lost reply acknowledged")
	}
	h.f.r.Fault = nil
	must(t, r.Close())
	r, e = OpenReporter(o)
	must(t, e)
	defer r.Close()
	pending, e := r.Pending(ctx)
	must(t, e)
	if !bytes.Equal(raw, pending) {
		t.Fatal("pending bytes changed")
	}
	receipt, e := r.Deliver(ctx, c)
	must(t, e)
	if receipt != reportReceipt(raw, snap.ObservedUnix) {
		t.Fatal("receipt changed observation age")
	}
	view, e := h.f.r.Report(ctx, h.f.p, h.f.e.Tenant, h.f.e.Node, id("domain"), 5*time.Second)
	must(t, e)
	if view.Sequence != 1 || view.State != "STALE" || view.ObservedUnix != snap.ObservedUnix || view.Generations[0].LogicalBytes != nil || view.Generations[0].VerifiedUnix != 0 || view.Generations[0].Verification != "NONE" {
		t.Fatal("manufactured knowledge", view)
	}
	pending, e = r.Pending(ctx)
	must(t, e)
	if pending != nil {
		t.Fatal("ack did not retire telemetry")
	}
	raw, e = r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix()))
	must(t, e)
	report, e := VerifyReport(raw, h.f.e, time.Now())
	must(t, e)
	if report.Sequence != 2 {
		t.Fatal("counter reset")
	}
}

func TestReporterGrantRenewalCapacityAndStateLossFailClosed(t *testing.T) {
	h := newHTTPFixture(t)
	r, o, c := reporterFixture(t, h)
	defer r.Close()
	ctx := context.Background()
	old, e := r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix()-20))
	must(t, e)
	bad := o
	bad.Target = id("different-service")
	if q, e := OpenReporter(bad); e == nil {
		q.Close()
		t.Fatal("service rebound")
	}
	revised := h.f.e
	revised.Revision++
	raw, e := SignEnrollment(revised, h.f.owner)
	must(t, e)
	must(t, r.Renew(ctx, raw))
	if _, e = r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix())); !errors.Is(e, ErrConflict) {
		t.Fatal("snapshot from obsolete grant relabeled", e)
	}
	pending, e := r.Pending(ctx)
	must(t, e)
	if pending != nil {
		t.Fatal("old grant telemetry retained for new grant")
	}
	original, e := SignEnrollment(h.f.e, h.f.owner)
	must(t, e)
	if e = r.Renew(ctx, original); e == nil {
		t.Fatal("grant rollback")
	}
	_, e = h.f.r.ApplyEnrollment(ctx, h.f.p, id("renewed"), "POLICY_CHANGE", raw, 1)
	must(t, e)
	h.f.e = revised
	r.store.Admit = func(string, int) (func(bool) error, error) { return nil, ErrCapacity }
	if _, e = r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix())); !errors.Is(e, ErrCapacity) {
		t.Fatal("quota ignored", e)
	}
	r.store.Admit = nil
	next, e := r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix()))
	must(t, e)
	report, e := VerifyReport(next, revised, time.Now())
	must(t, e)
	if report.Sequence != 2 || bytes.Equal(next, old) {
		t.Fatal("renewal reset sequence")
	}
	_, e = r.Deliver(ctx, c)
	must(t, e)
	revoked := revised
	revoked.Revision++
	revoked.Revoked = true
	raw, e = SignEnrollment(revoked, h.f.owner)
	must(t, e)
	must(t, r.Renew(ctx, raw))
	if _, e = r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix())); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked reporter admitted", e)
	}
	must(t, os.Remove(filepath.Join(o.Directory, "reporter.json")))
	if q, e := OpenReporter(o); e == nil {
		q.Close()
		t.Fatal("lost journal silently recreated")
	}
	reset := o
	reset.Initialize = true
	reset.Enrollment = original
	if q, e := OpenReporter(reset); e == nil {
		q.Close()
		t.Fatal("explicit init reset a previously admitted lost counter")
	}
}

func TestReporterHTTPPinFalseAckRedirectAndIndependentQueueLock(t *testing.T) {
	h := newHTTPFixture(t)
	r, o, c := reporterFixture(t, h)
	defer r.Close()
	ctx := context.Background()
	raw, e := r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix()-20))
	must(t, e)
	cfg := h.node.Transport.(*http.Transport).TLSClientConfig
	wrong, e := NewReportClient(h.server.URL, id("wrong-pin"), h.f.e.Node, cfg.Certificates[0], cfg.RootCAs, time.Second)
	must(t, e)
	defer wrong.Close()
	if _, e = wrong.Publish(ctx, h.f.e, raw); e == nil {
		t.Fatal("wrong server pin accepted")
	}
	// Start a second real TLS endpoint with the same admitted identity, never
	// replace transport authentication with an in-memory fake round tripper.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		receipt := reportReceipt(raw, time.Now().Unix())
		json.NewEncoder(w).Encode(receipt)
	}))
	s.TLS = h.server.TLS.Clone()
	s.StartTLS()
	defer s.Close()
	slow, e := NewReportClient(s.URL, o.Target, h.f.e.Node, cfg.Certificates[0], cfg.RootCAs, time.Second)
	must(t, e)
	defer slow.Close()
	done := make(chan error, 1)
	go func() { _, e := r.Deliver(ctx, slow); done <- e }()
	<-entered
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	pending, e := r.Pending(bounded)
	if e != nil || !bytes.Equal(pending, raw) {
		close(release)
		t.Fatal("network held queue lock", e)
	}
	close(release)
	if e = <-done; !errors.Is(e, ErrInvalid) {
		t.Fatal("false timestamp ack accepted", e)
	}
	pending, e = r.Pending(ctx)
	must(t, e)
	if !bytes.Equal(pending, raw) {
		t.Fatal("false ack discarded telemetry")
	}
	redirects := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, h.server.URL+req.URL.Path, http.StatusTemporaryRedirect)
	}))
	redirects.TLS = h.server.TLS.Clone()
	redirects.StartTLS()
	defer redirects.Close()
	rc, e := NewReportClient(redirects.URL, o.Target, h.f.e.Node, cfg.Certificates[0], cfg.RootCAs, time.Second)
	must(t, e)
	defer rc.Close()
	if _, e = r.Deliver(ctx, rc); e == nil {
		t.Fatal("followed report redirect")
	}
	_, e = r.Deliver(ctx, c)
	must(t, e)
}

type reporterCrashInput struct {
	Options         ReporterOptions
	Snapshot        Snapshot
	Point, Endpoint string
	Certificate     [][]byte
	Roots           [][]byte
}

func TestReporterSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_REPORTER_KILL")
	if file == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var in reporterCrashInput
	must(t, json.Unmarshal(raw, &in))
	r, e := OpenReporter(in.Options)
	must(t, e)
	defer r.Close()
	r.Fault = func(point string) error {
		if point == in.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	if in.Point == "management-reporter-pending-durable" {
		_, e = r.Enqueue(context.Background(), in.Snapshot)
		must(t, e)
	} else {
		roots := x509.NewCertPool()
		for _, der := range in.Roots {
			cert, e := x509.ParseCertificate(der)
			must(t, e)
			roots.AddCert(cert)
		}
		c, e := NewReportClient(in.Endpoint, in.Options.Target, identity(in.Options.Signer.Public().(ed25519.PublicKey)), tls.Certificate{Certificate: in.Certificate, PrivateKey: in.Options.Signer}, roots, time.Second)
		must(t, e)
		defer c.Close()
		_, e = r.Deliver(context.Background(), c)
		must(t, e)
	}
	t.Fatal("kill point absent")
}
func TestReporterSIGKILLKeepsPendingRemoteAckAndLocalAck(t *testing.T) {
	for _, point := range []string{"management-reporter-pending-durable", "management-reporter-remote-acknowledged", "management-reporter-ack-durable"} {
		t.Run(point, func(t *testing.T) {
			h := newHTTPFixture(t)
			r, o, c := reporterFixture(t, h)
			ctx := context.Background()
			snapshot := reporterSnapshot(t, h.f, time.Now().Unix()-60)
			if point != "management-reporter-pending-durable" {
				_, e := r.Enqueue(ctx, snapshot)
				must(t, e)
			}
			must(t, r.Close())
			// Obtain the already verified fixture CA through its TLS handshake chain.
			response, e := h.node.Get(h.server.URL + "/api/v1/session")
			must(t, e)
			response.Body.Close()
			var roots [][]byte
			for _, chain := range response.TLS.VerifiedChains {
				roots = append(roots, chain[len(chain)-1].Raw)
			}
			in := reporterCrashInput{Options: o, Snapshot: snapshot, Point: point, Endpoint: h.server.URL, Certificate: h.node.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate, Roots: roots}
			// Functions are deliberately absent from the serialized child input.
			file := filepath.Join(filepath.Dir(o.Directory), "reporter-child.json")
			raw, e := json.Marshal(map[string]any{"Options": map[string]any{"Directory": o.Directory, "Owner": o.Owner, "Signer": o.Signer, "Target": o.Target, "Domain": o.Domain}, "Snapshot": in.Snapshot, "Point": in.Point, "Endpoint": in.Endpoint, "Certificate": in.Certificate, "Roots": in.Roots})
			must(t, e)
			must(t, os.WriteFile(file, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestReporterSIGKILLChild$")
			cmd.Env = append(os.Environ(), "OUTPOST_REPORTER_KILL="+file)
			output, e := cmd.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("child did not terminate %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong signal %v %s", e, output)
			}
			r, e = OpenReporter(o)
			must(t, e)
			defer r.Close()
			pending, e := r.Pending(ctx)
			must(t, e)
			if point == "management-reporter-ack-durable" {
				if pending != nil {
					t.Fatal("durable ack lost")
				}
			} else {
				if pending == nil {
					t.Fatal("pending lost")
				}
				_, e = r.Deliver(ctx, c)
				must(t, e)
			}
			view, e := h.f.r.Report(ctx, h.f.p, h.f.e.Tenant, h.f.e.Node, id("domain"), time.Second)
			must(t, e)
			if view.Sequence != 1 || view.ObservedUnix != snapshot.ObservedUnix || view.State != "STALE" {
				t.Fatal("restart changed age", view)
			}
			raw, e = r.Enqueue(ctx, reporterSnapshot(t, h.f, time.Now().Unix()))
			must(t, e)
			report, e := VerifyReport(raw, h.f.e, time.Now())
			must(t, e)
			if report.Sequence != 2 {
				t.Fatal("sequence reset")
			}
		})
	}
}
