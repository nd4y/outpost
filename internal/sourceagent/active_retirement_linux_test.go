package sourceagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/worker"
)

func TestExpiredActiveRetirementRequiresAllAdmissionProofs(t *testing.T) {
	if os.Getenv("OUTPOST_EXPIRY_INTEGRATION") != "1" {
		t.Skip("real expiry integration is exercised on the dedicated HDD")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 190*time.Second)
	defer cancel()
	f := newFixtureLifetime(t, 75)
	w, err := worker.Open(worker.Options{Directory: filepath.Join(f.base, "inspection-worker"), Node: f.grant.Ingress,
		Owner: f.b.Local.Owner, Certificate: f.destination, Roots: f.roots, Initialize: true})
	must(t, err)
	t.Cleanup(func() { w.Close() })
	var admissionCalls atomic.Int32
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/intent") {
			admissionCalls.Add(1)
		}
		w.ServeHTTP(out, r)
		return true
	}
	planner, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	cfg := control.Config{
		Format: control.SettlementConfigFormat, Node: f.grant.Ingress, Revision: 1,
		NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix,
		Limits: control.Limits{Parallel: 2, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20},
		Nodes:  []policy.Node{{ID: f.grant.Source, Class: "trusted"}, {ID: f.grant.Ingress, Class: "trusted", Endpoint: f.server.URL}},
		Domains: []control.Domain{{Trust: f.grant.Trust, Planner: planner, Placement: policy.Placement{
			Domain: f.grant.Trust.Domain, AllowedClasses: []string{"trusted"}, Holders: []string{f.grant.Ingress},
			Transit: []string{f.grant.Source}, Edges: []policy.Edge{{From: f.grant.Source, To: f.grant.Ingress, Mode: "push"}},
		}}},
		Ingress: []json.RawMessage{f.authority},
	}
	apply := func() func() {
		raw, err := control.Sign(cfg, f.ownerSigner)
		must(t, err)
		must(t, w.Accept(ctx, raw))
		return runCaptureWorker(t, ctx, w)
	}
	stop := apply()
	must(t, f.a.Next(ctx))
	crash := errors.New("simulated interruption after durable source fence")
	f.a.Fault = func(point string) error {
		if point == "source-agent-active-durable" {
			return crash
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, crash) || admissionCalls.Load() != 0 {
		t.Fatal("source did not stop before receiver admission", err, admissionCalls.Load())
	}
	stop()
	timer := time.NewTimer(time.Until(time.Unix(f.grant.ExpiresUnix, 0)) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.reopen(t)
	provision := func(purpose string) (control.SettlementAdmission, func()) {
		req, err := f.a.SettlementPreviewFor(ctx, purpose, "")
		must(t, err)
		item, err := SignSettlementAdmission(req, f.ownerSigner)
		must(t, err)
		cfg.Ingress, cfg.Settlements = nil, []control.SettlementAdmission{item}
		cfg.NotBefore = time.Now().Unix()
		cfg.ExpiresUnix = cfg.NotBefore + 300
		cfg.Revision++
		return item, apply()
	}
	retry := func(call func() error) error {
		for {
			err := call()
			if !errors.Is(err, ingress.ErrUnavailable) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	inspection, stop := provision(ingress.SettlementInspect)
	var report ingress.Reconciliation
	must(t, retry(func() error {
		var err error
		report, err = f.a.Reconcile(ctx, inspection)
		return err
	}))
	if report.Phase != "NOT_ADMITTED" {
		t.Fatal("missing authenticated nonadmission proof", report)
	}
	if err = f.a.RetireActive(ctx, inspection, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("read-only inspection authorized retirement", err)
	}
	stop()
	retirement, stop := provision(ingress.SettlementRetire)
	defer stop()
	f.a.Fault = func(point string) error {
		if point == "source-active-retirement-durable" {
			return crash
		}
		return nil
	}
	if err = retry(func() error { return f.a.RetireActive(ctx, retirement, nil) }); !errors.Is(err, crash) {
		t.Fatal("did not preserve pending state after audit write", err)
	}
	f.reopen(t)
	must(t, f.a.RetireActive(ctx, retirement, nil))
	must(t, f.a.RetireActive(ctx, retirement, nil))
	f.reopen(t)
	status, err := f.a.Status(ctx)
	must(t, err)
	if status.Phase != "ABANDONED" || status.Generation != "" || admissionCalls.Load() != 0 {
		t.Fatal("retirement advanced the generation or contacted a write route", status)
	}
	t.Log("inspection kept ACTIVE; fresh owner authorization and receiver proof allowed restart-safe retirement")
}
