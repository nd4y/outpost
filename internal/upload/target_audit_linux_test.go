package upload

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

type targetAuditFixture struct {
	Plan        []byte
	Authority   Authority
	Worker      string
	Certificate []byte
	Directory   string
	Receipt     string
	Window      string
	ExpiresUnix int64
}

func TestTargetAuditWindowProcess(t *testing.T) {
	path := os.Getenv("OUTPOST_TARGET_AUDIT_FIXTURE")
	if path == "" {
		t.Skip("subprocess fixture")
	}
	raw, err := os.ReadFile(path)
	must(t, err)
	var config targetAuditFixture
	must(t, json.Unmarshal(raw, &config))
	plan, err := Verify(config.Plan, config.Authority)
	must(t, err)
	cert, err := x509.ParseCertificate(config.Certificate)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	backend, err := storage.New(plan.Profile, storage.Credentials{Access: config.Worker, Secret: "test-secret-a", ExpiresUnix: config.ExpiresUnix}, roots)
	must(t, err)
	defer backend.Close()
	store, err := statefile.Open(config.Directory, readback.MaxPage, false)
	must(t, err)
	defer store.Close()
	receipt, err := AuditTargetPlan(context.Background(), config.Plan, config.Authority, config.Worker, backend, TargetAuditWindow{ID: config.Window, MaxAgeSeconds: 3600, Store: store})
	must(t, err)
	raw, err = json.Marshal(receipt)
	must(t, err)
	must(t, os.WriteFile(config.Receipt, raw, 0600))
}

func TestTargetAuditWindowResumesAfterSIGKILLAndFencesFreshProof(t *testing.T) {
	f := fixtureBytes(t, 512<<10)
	var armed atomic.Bool
	var readsMu sync.Mutex
	reads := map[string]int{}
	hit := make(chan struct{})
	var nextPart string
	target := f.server(t, "webdav", 0, func(_ http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
		if r.Method != http.MethodGet {
			return false
		}
		readsMu.Lock()
		reads[key]++
		readsMu.Unlock()
		if armed.Load() && key == nextPart && armed.CompareAndSwap(true, false) {
			close(hit)
			<-r.Context().Done()
			return true
		}
		return false
	})
	ctx := context.Background()
	raw := f.plan(t, target, 1, 1000)
	plan, err := Verify(raw, f.authority)
	must(t, err)
	blob := plan.Blobs[0]
	for _, candidate := range plan.Blobs {
		if len(candidate.Parts) > len(blob.Parts) {
			blob = candidate
		}
	}
	if len(blob.Parts) < 2 {
		t.Fatal("fixture did not produce multipart ciphertext")
	}
	journalDir := filepath.Join(f.base, "publish")
	must(t, os.Mkdir(journalDir, 0700))
	worker := f.workers[0].ID
	journal, err := Open(journalDir, raw, worker, f.authority, true)
	must(t, err)
	defer journal.Close()
	backend := f.backend(t, target, 0)
	_, err = journal.Run(ctx, f.replicas[0], backend, f.keys[0])
	must(t, err)
	writes := target.Snapshot().Writes
	proofDir := filepath.Join(f.base, "audit-cache")
	store, err := statefile.Open(proofDir, readback.MaxPage, true)
	must(t, err)
	must(t, store.Close())
	config := targetAuditFixture{
		Plan: raw, Authority: f.authority, Worker: worker, Certificate: target.HTTP.Certificate().Raw, Directory: proofDir,
		Receipt: filepath.Join(f.base, "audit-receipt.json"), Window: storage.Hash([]byte("audit-window")),
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}
	fixture := filepath.Join(f.base, "target-audit-fixture.json")
	data, err := json.Marshal(config)
	must(t, err)
	must(t, os.WriteFile(fixture, data, 0600))
	bin, err := os.Executable()
	must(t, err)
	child := func() *exec.Cmd {
		cmd := exec.Command(bin, "-test.run=^TestTargetAuditWindowProcess$", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), "OUTPOST_TARGET_AUDIT_FIXTURE="+fixture)
		return cmd
	}
	readsMu.Lock()
	reads = map[string]int{}
	nextPart = "part-" + blob.Parts[1].ID
	readsMu.Unlock()
	armed.Store(true)
	first := child()
	must(t, first.Start())
	select {
	case <-hit:
	case <-time.After(8 * time.Second):
		_ = first.Process.Kill()
		_ = first.Wait()
		t.Fatal("audit did not retain first part before the next read")
	}
	sample := time.Now().Unix()
	must(t, first.Process.Kill())
	var exit *exec.ExitError
	if err = first.Wait(); !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatal("audit process did not receive SIGKILL", err)
	}
	if _, err = os.Stat(config.Receipt); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("interrupted audit published a receipt", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if output, err := child().CombinedOutput(); err != nil {
		t.Fatal("failed to reopen actual window", err, string(output))
	}
	data, err = os.ReadFile(config.Receipt)
	must(t, err)
	var receipt TargetAuditReceipt
	must(t, json.Unmarshal(data, &receipt))
	if receipt.Window != config.Window || receipt.Plan != storage.Hash(raw) || receipt.Generation != f.id ||
		receipt.Target != backend.Profile().ID() || receipt.ObservedUnix > sample || receipt.FinishedUnix <= sample {
		t.Fatal("resumed window changed observation age", receipt)
	}
	readsMu.Lock()
	firstReads, nextReads := reads["part-"+blob.Parts[0].ID], reads[nextPart]
	readsMu.Unlock()
	if firstReads != 1 || nextReads != 2 || !reflect.DeepEqual(writes, target.Snapshot().Writes) {
		t.Fatal("resume reread durable progress or wrote target", firstReads, nextReads)
	}
	store, err = statefile.Open(proofDir, readback.MaxPage, false)
	must(t, err)
	defer store.Close()
	before := target.Snapshot().Requests
	if _, err = AuditTargetPlan(ctx, raw, f.authority, storage.Hash([]byte("foreign")), backend, TargetAuditWindow{ID: config.Window, MaxAgeSeconds: 3600, Store: store}); !errors.Is(err, ErrDenied) || target.Snapshot().Requests != before {
		t.Fatal("foreign executor reached target", err)
	}
	correct, err := backend.ReadBlob(ctx, blob.Object)
	must(t, err)
	expected, err := f.replicas[0].ReadObject(ctx, f.id, blob.Object)
	must(t, err)
	if !bytes.Equal(correct, expected) {
		t.Fatal("read-only audit changed healthy bytes")
	}
	partPath := target.Path("part-" + blob.Parts[0].ID)
	part, err := os.ReadFile(partPath)
	must(t, err)
	part[0] ^= 1
	must(t, os.WriteFile(partPath, part, 0600))
	for _, window := range []TargetAuditWindow{
		{ID: storage.Hash([]byte("fresh-window")), MaxAgeSeconds: 3600, Store: store},
		{ID: config.Window, MaxAgeSeconds: 3599, Store: store},
	} {
		if proof, err := AuditTargetPlan(ctx, raw, f.authority, worker, backend, window); !errors.Is(err, storage.ErrIntegrity) || proof.Format != "" {
			t.Fatal("another scope reused old supporting evidence", proof, err)
		}
	}
}
