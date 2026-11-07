package management

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
)

// Opt-in loopback fixture for the isolated browser runner. This is not a
// product server or a substitute for worker execution/restore acceptance.
func TestManagementBrowserFixture(t *testing.T) {
	dir := os.Getenv("OUTPOST_BROWSER_FIXTURE")
	if dir == "" {
		t.Skip("isolated browser runner only")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute fixture output required")
	}
	must(t, os.Mkdir(dir, 0700))
	h := newHTTPFixture(t)
	f := h.f
	cfg := domainPolicyFixture(t, h)
	pending := command.Request{Operation: id("browser-unpublished"), Reason: "OPERATOR_REQUEST", Tenant: f.e.Tenant, Domain: id("domain"), Kind: "pause", ExpectedRevision: cfg.Revision, Authority: cfg.Commands[0], ExpiresUnix: time.Now().Unix() + 600}
	f.r.Fault = interruptAt("management-command-intent-durable")
	if _, e := f.r.AdmitCommand(context.Background(), f.p, f.e.Tenant, f.e.Node, pending); e == nil {
		t.Fatal("missing pending fixture interruption")
	}
	f.r.Fault = nil
	h.handler.(*httpService).origin = h.server.URL
	h.handler.(*httpService).timeout = 5 * time.Second
	view, e := VerifyReport(f.report(t, 1, time.Now().Unix()-20), f.e, time.Now())
	must(t, e)
	view.ConfigurationRevision = cfg.Revision
	for i := 0; i < 61; i++ {
		view.Jobs = append(view.Jobs, Job{Operation: id(fmt.Sprint("browser-job-", i)), Domain: view.Domain, Generation: id("generation"), Kind: "PEER", Phase: "QUEUED", UpdatedUnix: view.ObservedUnix})
	}
	view.Format = ExternalReportFormat
	view.ExternalState = "OBSERVED"
	for i := 0; i < 2; i++ {
		view.Jobs[i].Kind = "UPLOAD"
	}
	view.ExternalCopies = []ExternalCopy{
		{Operation: view.Jobs[0].Operation, Generation: view.Jobs[0].Generation, Target: id("browser-cloud-target"), State: "OBSERVED_COMPLETE", Verification: "cached-target-readback", VerifiedUnix: view.ObservedUnix - 300, ReceiptDigest: id("browser-cloud-receipt")},
		{Operation: view.Jobs[1].Operation, Generation: view.Jobs[1].Generation, Target: id("browser-pending-target"), State: "UNCONFIRMED", Verification: "NONE"},
	}
	raw, e := SignReport(view, f.e, f.node, time.Now())
	must(t, e)
	_, e = f.r.PublishReport(context.Background(), f.e.Node, f.e.Tenant, f.e.Node, raw)
	must(t, e)
	cfg.Revision++
	cfg.Limits.Parallel++
	raw, e = control.Sign(cfg, f.owner)
	must(t, e)
	config := filepath.Join(dir, "policy-next.json")
	must(t, os.WriteFile(config, raw, 0600))
	cfg.Revision++
	cfg.Limits.Parallel++
	raw, e = control.Sign(cfg, f.owner)
	must(t, e)
	future := filepath.Join(dir, "policy-future.json")
	must(t, os.WriteFile(future, raw, 0600))
	clients := map[string]map[string]string{}
	for name, client := range map[string]*http.Client{"owner": h.owner, "viewer": h.viewer, "unknown": h.unknown} {
		cert := client.Transport.(*http.Transport).TLSClientConfig.Certificates[0]
		key, e := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		must(t, e)
		certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		must(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
		must(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
		clients[name] = map[string]string{"certPath": certPath, "keyPath": keyPath}
	}
	meta := map[string]any{"url": h.server.URL, "clients": clients, "tenant": f.e.Tenant, "node": f.e.Node, "domain": id("domain"), "otherDomain": id("second-domain"), "generation": id("generation"), "preset": id("browser-recovery-preset"), "config": config, "futureConfig": future, "observedUnix": view.ObservedUnix, "pendingCommand": pending, "cloudTarget": id("browser-cloud-target"), "pendingTarget": id("browser-pending-target"), "cloudVerifiedUnix": view.ObservedUnix - 300, "otherTarget": cfg.Targets[1].ID}
	raw, e = json.Marshal(meta)
	must(t, e)
	must(t, os.WriteFile(filepath.Join(dir, "ready.json"), raw, 0600))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(4 * time.Minute):
		t.Fatal("browser runner deadline")
	}
}
