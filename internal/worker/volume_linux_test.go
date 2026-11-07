package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/volume"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func bindFixture(t *testing.T, f *fixture, w *Worker) volume.Binding {
	t.Helper()
	root := filepath.Join(f.base, "volume-"+w.node)
	must(t, os.Mkdir(root, 0700))
	o, e := volume.Probe(context.Background(), root)
	must(t, e)
	b, e := volume.Enroll(context.Background(), root, o, w.node, 1)
	must(t, e)
	next := filepath.Join(root, "worker")
	must(t, os.Rename(w.dir, next))
	w.dir = next
	w.guard = func(ctx context.Context) error { return b.CheckHandle(ctx, w.dir, w.root) }
	return b
}

func TestWorkerVolumeLossStopsActiveViewAndDoesNotWriteFallback(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[1]
	binding := bindFixture(t, f, w)
	f.endpoint(t, nil)
	f.config(t, 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	must(t, os.Rename(filepath.Join(binding.Root, volume.Sentinel), filepath.Join(binding.Root, "saved-marker")))
	select {
	case e := <-done:
		if !errors.Is(e, volume.ErrUnavailable) {
			t.Fatal("lost volume did not stop worker", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not join")
	}
	w.mu.Lock()
	active := w.active
	w.mu.Unlock()
	if active != nil {
		t.Fatal("active view survived volume loss")
	}
	cfg := f.cfg
	cfg.Node = w.node
	cfg.Domains = []control.Domain{f.domain}
	cfg.Revision++
	raw, e := control.Sign(cfg, f.owner)
	must(t, e)
	if e = w.Accept(context.Background(), raw); !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("accepted config on lost volume", e)
	}
	out := httptest.NewRecorder()
	w.ServeHTTP(out, httptest.NewRequest("GET", "https://worker.invalid/anything", nil))
	if out.Code != 503 {
		t.Fatal("lost volume still serving", out.Code)
	}
}

func TestWorkerRootReplacementCannotRedirectNewState(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[1]
	bindFixture(t, f, w)
	held := w.dir + "-held"
	must(t, os.Rename(w.dir, held))
	must(t, os.Mkdir(w.dir, 0700))
	if e := w.check(context.Background()); !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("replacement accepted", e)
	}
	// Even an already admitted low-level transaction remains on the old handle.
	must(t, w.state.Write("descriptor-proof", []byte("owned")))
	if _, e := os.Stat(filepath.Join(held, "state", "descriptor-proof")); e != nil {
		t.Fatal(e)
	}
	names, e := os.ReadDir(w.dir)
	must(t, e)
	if len(names) != 0 {
		t.Fatal("wrote into replacement", names)
	}
	if e = w.createOrOpen(context.Background(), filepath.Join(w.dir, "new"), func(bool) error { return nil }); !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("new work admitted", e)
	}
}

func TestBootstrapRejectsLegacyUnboundFormatBeforeRuntimeCreation(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.base, "bootstrap.json")
	b := Bootstrap{Format: Format, Directory: filepath.Join(f.base, "never-created"), Node: f.nodes[0].node, Owner: f.owner.Public().(ed25519.PublicKey)}
	raw, e := json.Marshal(b)
	must(t, e)
	must(t, os.WriteFile(path, raw, 0600))
	if _, e = LoadBootstrap(path); !errors.Is(e, ErrDenied) {
		t.Fatal("unbound legacy accepted", e)
	}
	if _, _, e = b.Open(true); !errors.Is(e, ErrDenied) {
		t.Fatal("bypassed decode", e)
	}
	if _, e = os.Stat(b.Directory); !os.IsNotExist(e) {
		t.Fatal("created unbound runtime", e)
	}
}

func TestBoundBootstrapInitializesAndReopensOnlyEnrolledRuntime(t *testing.T) {
	f := newFixture(t)
	node := f.nodes[0]
	root := filepath.Join(f.base, "enrolled")
	must(t, os.Mkdir(root, 0700))
	ctx := context.Background()
	observed, e := volume.Probe(ctx, root)
	must(t, e)
	binding, e := volume.Enroll(ctx, root, observed, node.node, 1)
	must(t, e)
	certFile := filepath.Join(f.base, "cert.pem")
	keyFile := filepath.Join(f.base, "key.pem")
	caFile := filepath.Join(f.base, "ca.pem")
	must(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.cert.Certificate[0]}), 0600))
	private, e := x509.MarshalPKCS8PrivateKey(node.cert.PrivateKey)
	must(t, e)
	must(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600))
	must(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.cert.Raw}), 0600))
	b := Bootstrap{Format: BootstrapFormat, Volume: binding, Directory: filepath.Join(root, "runtime"), Node: node.node, Owner: f.owner.Public().(ed25519.PublicKey), CertificateFile: certFile, PrivateKeyFile: keyFile, CAFile: caFile}
	w, close, e := b.Open(true)
	must(t, e)
	status, e := w.Status(ctx)
	must(t, e)
	if status.Node != node.node {
		t.Fatal("wrong node")
	}
	close()
	w, close, e = b.Open(false)
	must(t, e)
	_, e = w.Status(ctx)
	must(t, e)
	close()
	must(t, os.Remove(filepath.Join(root, volume.Sentinel)))
	if _, _, e = b.Open(false); !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("reopened without marker", e)
	}
}
