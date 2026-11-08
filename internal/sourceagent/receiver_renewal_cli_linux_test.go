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
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

func TestReceiverRenewalCLIUsesSameRootAndPreservesVersions(t *testing.T) {
	current, previous := os.Getenv("OUTPOST_RECEIVER_RENEWAL_CURRENT_CLI"), os.Getenv("OUTPOST_RECEIVER_RENEWAL_PREVIOUS_CLI")
	if current == "" && previous == "" {
		t.Skip("explicit current and previous CLI artifacts required")
	}
	expected := os.Getenv("OUTPOST_RECEIVER_RENEWAL_PREVIOUS_SHA256")
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
	f := newFixtureLifetime(t, 12)
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
	f.registryMu.Lock()
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool { w.ServeHTTP(out, r); return true }
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
	firstBytes, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	stop := startWorker()
	run(current, true, "source-next", "--bootstrap", sourcePath)
	run(current, true, "source-run", "--bootstrap", sourcePath)
	var first struct {
		Result Status `json:"result"`
	}
	must(t, json.Unmarshal(run(current, true, "source-status", "--bootstrap", sourcePath), &first))
	stop()
	if first.Result.Sequence != 1 || first.Result.Phase != "COMPLETE" {
		t.Fatal("first capture incomplete", first)
	}
	registryPath := filepath.Join(worker.DomainDirectory(b.Directory, f.grant.Trust), "ingress/state/registry.json")
	original, e := os.ReadFile(registryPath)
	must(t, e)
	f.expire(t)
	authority := f.grant
	authority.Revision, authority.NotBefore, authority.ExpiresUnix, authority.Signature = 2, time.Now().Unix()-1, time.Now().Unix()+3600, nil
	unsigned := write("fresh-authority-input.json", authority)
	freshPath := filepath.Join(f.base, "fresh-authority.json")
	run(current, true, "source-authority-sign", "--key", ownerPath, "--input", unsigned, "--output", freshPath)
	fresh, e := os.ReadFile(freshPath)
	must(t, e)
	c.Revision, c.NotBefore, c.ExpiresUnix = 2, authority.NotBefore, authority.ExpiresUnix
	c.Ingress = []json.RawMessage{fresh}
	apply("renewal", c)
	for _, point := range []string{"ingress-renewal-legacy-durable", "ingress-renewal-committed"} {
		input := write(point+".json", receiverRenewalChild{Bootstrap: b, Previous: f.authority, Fresh: fresh, Domain: f.grant.Trust.Domain, Point: point})
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestReceiverRenewalSIGKILLChild$")
		cmd.Env = append(os.Environ(), "OUTPOST_RECEIVER_RENEWAL_KILL="+input)
		output, err := cmd.CombinedOutput()
		timed := bounded.Err()
		cancel()
		exit, ok := err.(*exec.ExitError)
		if !ok || timed != nil {
			t.Fatalf("child %s: %v %s", point, err, output)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("wrong child exit: %v %s", err, output)
		}
		after, e := os.ReadFile(registryPath)
		must(t, e)
		if point == "ingress-renewal-legacy-durable" && !bytes.Equal(after, original) {
			t.Fatal("uncommitted migration changed registry")
		}
		if point == "ingress-renewal-committed" && !bytes.Contains(after, []byte(ingress.RenewedRegistryFormat)) {
			t.Fatal("committed registry missing")
		}
		t.Log("actual SIGKILL", point)
	}
	var migrated struct {
		Result ingress.RegistryRenewal `json:"result"`
	}
	args := []string{"worker-ingress-renew", "--bootstrap", receiverPath, "--domain", f.grant.Trust.Domain, "--trust", f.b.AuthorityFile, "--input", freshPath}
	must(t, json.Unmarshal(run(current, true, args...), &migrated))
	if migrated.Result.Revision != 2 || migrated.Result.LegacyDigest != storage.Hash(original) {
		t.Fatal("migration lost original anchor", migrated)
	}
	run(current, true, args...)
	beforeOld, e := os.ReadFile(registryPath)
	must(t, e)
	run(oldCLI, false, "worker-run", "--bootstrap", receiverPath)
	afterOld, e := os.ReadFile(registryPath)
	must(t, e)
	if !bytes.Equal(beforeOld, afterOld) {
		t.Fatal("previous worker changed registry2")
	}
	run(current, true, "source-renew", "--bootstrap", sourcePath, "--input", freshPath)
	secondBytes := bytes.Clone(firstBytes)
	secondBytes[len(secondBytes)/2] ^= 1
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), secondBytes, 0600))
	stop = startWorker()
	run(current, true, "source-next", "--bootstrap", sourcePath)
	run(current, true, "source-run", "--bootstrap", sourcePath)
	var second struct {
		Result Status `json:"result"`
	}
	must(t, json.Unmarshal(run(current, true, "source-status", "--bootstrap", sourcePath), &second))
	stop()
	if second.Result.Phase != "COMPLETE" || second.Result.Sequence != 2 || second.Result.Generation == first.Result.Generation {
		t.Fatal("same receiver did not advance", second)
	}
	trust := write("recovery-trust.json", f.grant.Trust)
	for index, id := range []string{first.Result.Generation, second.Result.Generation} {
		out := filepath.Join(f.base, "renewal-restored-"+id)
		run(current, true, "restore-replica", "--key", f.b.DataKeyFile, "--trust", trust, "--store", filepath.Join(worker.DomainDirectory(b.Directory, f.grant.Trust), "replica"), "--generation", id, "--output", out)
		got, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		want := firstBytes
		if index == 1 {
			want = secondBytes
		}
		if !bytes.Equal(got, want) {
			t.Fatal("restored wrong retained generation", index)
		}
	}
	t.Logf("actual CLI renewed same receiver after expiry and two SIGKILL points; previous reader refused; old/new %d-byte generations restored", len(firstBytes))
}

type receiverRenewalChild struct {
	Bootstrap       worker.Bootstrap
	Previous, Fresh []byte
	Domain, Point   string
}

func TestReceiverRenewalSIGKILLChild(t *testing.T) {
	path := os.Getenv("OUTPOST_RECEIVER_RENEWAL_KILL")
	if path == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(path)
	must(t, e)
	var input receiverRenewalChild
	must(t, json.Unmarshal(raw, &input))
	w, close, e := input.Bootstrap.Open(false)
	must(t, e)
	defer close()
	w.Fault = func(point string) error {
		if point == input.Point {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	_, e = w.RenewIngress(context.Background(), input.Domain, input.Previous, input.Fresh)
	must(t, e)
	t.Fatal("SIGKILL point not reached")
}
