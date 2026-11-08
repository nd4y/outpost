package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

func TestSourceSettlementCLIUsesCurrentWorkerAndPreviousFormatFence(t *testing.T) {
	current, previous := os.Getenv("OUTPOST_SETTLEMENT_CURRENT_CLI"), os.Getenv("OUTPOST_SETTLEMENT_PREVIOUS_CLI")
	if current == "" && previous == "" {
		t.Skip("explicit current and previous CLI artifacts required")
	}
	expected := os.Getenv("OUTPOST_SETTLEMENT_PREVIOUS_SHA256")
	if !filepath.IsAbs(current) || !filepath.IsAbs(previous) || !storage.ID(expected) {
		t.Fatal("incomplete executable selection")
	}
	file, e := os.Open(previous)
	must(t, e)
	bin, e := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	must(t, e)
	must(t, file.Close())
	if len(bin) > 64<<20 || storage.Hash(bin) != expected {
		t.Fatal("previous executable digest mismatch")
	}
	old, e := os.CreateTemp("/tmp", "outpost-settlement-previous-*")
	must(t, e)
	oldCLI := old.Name()
	t.Cleanup(func() { os.Remove(oldCLI) })
	_, e = old.Write(bin)
	must(t, e)
	must(t, old.Chmod(0700))
	must(t, old.Close())
	f := newFixtureLifetime(t, 8)
	ctx := context.Background()
	write := func(name string, v any) string {
		t.Helper()
		raw, e := json.Marshal(v)
		must(t, e)
		name = filepath.Join(f.base, name)
		must(t, os.WriteFile(name, raw, 0600))
		return name
	}
	run := func(binary string, success bool, args ...string) []byte {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		out, e := exec.CommandContext(bounded, binary, args...).CombinedOutput()
		if bounded.Err() != nil || (e == nil) != success {
			t.Fatalf("CLI %s success=%v: %v %s", args[0], success, e, out)
		}
		return out
	}
	sourcePath := write("source-bootstrap.json", f.b)
	ownerPath := write("owner-signing-key.json", map[string]any{"privateKey": f.ownerSigner})
	vol := filepath.Join(f.base, "receiver-volume")
	must(t, os.Mkdir(vol, 0700))
	probe, e := volume.Probe(ctx, vol)
	must(t, e)
	binding, e := volume.Enroll(ctx, vol, probe, f.grant.Ingress, 1)
	must(t, e)
	certPath, keyPath := filepath.Join(f.base, "receiver.pem"), filepath.Join(f.base, "receiver-key.pem")
	must(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.destination.Certificate[0]}), 0600))
	key, e := x509.MarshalPKCS8PrivateKey(f.destination.PrivateKey)
	must(t, e)
	must(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	b := worker.Bootstrap{Format: worker.BootstrapFormat, Volume: binding, Directory: filepath.Join(vol, "worker"), Node: f.grant.Ingress, Owner: f.b.Local.Owner, CertificateFile: certPath, PrivateKeyFile: keyPath, CAFile: f.b.Local.CAFile}
	receiverPath := write("receiver-bootstrap.json", b)
	run(current, true, "worker-init", "--bootstrap", receiverPath)
	w, closeWorker, e := b.Open(false)
	must(t, e)
	t.Cleanup(closeWorker)
	var lose atomic.Bool
	var original ingress.Receipt
	f.registryMu.Lock()
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool {
		if lose.Load() && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/catalog") {
			buffer := &settlementReplyBuffer{ResponseRecorder: httptest.NewRecorder(), underlying: out}
			w.ServeHTTP(buffer, r)
			var reply struct {
				Receipt *ingress.Receipt `json:"receipt"`
			}
			if buffer.Code == 200 && json.Unmarshal(buffer.Body.Bytes(), &reply) == nil && reply.Receipt != nil {
				original = *reply.Receipt
				http.Error(out, "lost reply", 503)
				return true
			}
			for k, v := range buffer.Header() {
				out.Header()[k] = append([]string(nil), v...)
			}
			out.WriteHeader(buffer.Code)
			_, _ = out.Write(buffer.Body.Bytes())
			return true
		}
		w.ServeHTTP(out, r)
		return true
	}
	f.registryMu.Unlock()
	planner, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	c := control.Config{Format: control.Format, Node: f.grant.Ingress, Revision: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix,
		Limits:  control.Limits{Parallel: 1, AttemptMillis: 5000, PollSeconds: 1, CapacityBytes: 256 << 20, ReserveBytes: 16 << 20, SpoolBytes: 64 << 20, TelemetryBytes: 1 << 20},
		Nodes:   []policy.Node{{ID: f.grant.Source, Class: "trusted"}, {ID: f.grant.Ingress, Class: "trusted", Endpoint: f.b.Endpoint}},
		Domains: []control.Domain{{Trust: f.grant.Trust, Planner: planner, Placement: policy.Placement{Domain: f.grant.Trust.Domain, AllowedClasses: []string{"trusted"}, Holders: []string{f.grant.Ingress}, Transit: []string{f.grant.Source}, Edges: []policy.Edge{{From: f.grant.Source, To: f.grant.Ingress, Mode: "push"}}}}},
		Ingress: []json.RawMessage{f.authority}}
	apply := func(name string, c control.Config) string {
		t.Helper()
		input := write(name+"-input.json", c)
		signed := filepath.Join(f.base, name+"-signed.json")
		run(current, true, "config-sign", "--key", ownerPath, "--input", input, "--output", signed)
		run(current, true, "config-apply", "--bootstrap", receiverPath, "--input", signed)
		return signed
	}
	normal := apply("normal", c)
	run(oldCLI, true, "config-apply", "--bootstrap", receiverPath, "--input", normal)
	startWorker := func() func() {
		t.Helper()
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- w.Run(runCtx) }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cancel()
			select {
			case e := <-done:
				must(t, e)
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not join")
			}
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			s, e := w.Status(ctx)
			if e == nil && s.Phase == "ACTIVE" && s.Revision == c.Revision {
				return stop
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("receiver view did not start")
		return stop
	}
	stop := startWorker()
	lose.Store(true)
	run(current, true, "source-next", "--bootstrap", sourcePath)
	run(current, false, "source-run", "--bootstrap", sourcePath)
	stop()
	f.registryMu.Lock()
	lose.Store(false)
	completed := original.Generation != ""
	f.registryMu.Unlock()
	if !completed {
		t.Fatal("CLI test did not reach durable receipt")
	}
	f.expire(t)
	status := run(current, true, "source-status", "--bootstrap", sourcePath)
	if !bytes.Contains(status, []byte("SEALED")) {
		t.Fatal("expired source status did not retain sealed operation")
	}
	request, admission := filepath.Join(f.base, "settlement-request.json"), filepath.Join(f.base, "settlement-admission.json")
	run(current, true, "source-settlement-preview", "--bootstrap", sourcePath, "--output", request)
	run(current, true, "source-settlement-sign", "--key", ownerPath, "--input", request, "--output", admission)
	raw, e := os.ReadFile(admission)
	must(t, e)
	var item control.SettlementAdmission
	must(t, json.Unmarshal(raw, &item))
	var grant ingress.Settlement
	must(t, json.Unmarshal(item.Grant, &grant))
	c.Format, c.Revision, c.NotBefore, c.ExpiresUnix = control.SettlementConfigFormat, 2, grant.NotBefore, grant.ExpiresUnix
	c.Ingress, c.Settlements = nil, []control.SettlementAdmission{item}
	signed := apply("settlement", c)
	run(oldCLI, false, "config-apply", "--bootstrap", receiverPath, "--input", signed)
	stop = startWorker()
	result := run(current, true, "source-settle", "--bootstrap", sourcePath, "--input", admission)
	var out struct {
		Result Status `json:"result"`
	}
	must(t, json.Unmarshal(result, &out))
	if out.Result.Phase != "COMPLETE" || out.Result.Generation != original.Generation || out.Result.Sequence != 1 {
		t.Fatal("CLI settlement selected wrong head", out)
	}
	run(current, true, "source-settle", "--bootstrap", sourcePath, "--input", admission)
	run(oldCLI, true, "source-status", "--bootstrap", sourcePath)
	stop()
	if !bytes.Contains(run(current, true, "version"), []byte(control.SettlementConfigFormat)) {
		t.Fatal("new reader contract absent")
	}
	t.Log("actual CLI preview/sign/config-apply/settle and previous control2 refusal passed; original generation", original.Generation)
}
