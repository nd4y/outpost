package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerIngressRenewalRequiresCurrentPolicyAndStoppedWorker(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w, ctx := f.nodes[1], context.Background()
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	previous, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Ingress = []json.RawMessage{previous}
	f.config(t, 1, nil)
	stop := start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	a.Revision = 2
	fresh, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	if _, e = w.RenewIngress(ctx, a.Trust.Domain, previous, fresh); !errors.Is(e, ingress.ErrConflict) {
		t.Fatalf("running worker renewed: %v", e)
	}
	stop()
	path := filepath.Join(DomainDirectory(w.dir, a.Trust), "ingress/state/registry.json")
	before, e := os.ReadFile(path)
	must(t, e)
	if _, e = w.RenewIngress(ctx, a.Trust.Domain, previous, fresh); !errors.Is(e, ErrDenied) {
		t.Fatalf("unaccepted grant renewed: %v", e)
	}
	f.cfg.Ingress = []json.RawMessage{fresh}
	f.cfg.Revision = 2
	f.config(t, 1, nil)
	if _, e = w.RenewIngress(ctx, storage.Hash([]byte("unknown")), previous, fresh); !errors.Is(e, ErrDenied) {
		t.Fatalf("unknown domain renewed: %v", e)
	}
	budgetBefore, e := w.budget.Status(ctx)
	must(t, e)
	result, e := w.RenewIngress(ctx, a.Trust.Domain, previous, fresh)
	must(t, e)
	if result.Format != ingress.RenewedRegistryFormat || result.Revision != 2 || result.LegacyDigest != storage.Hash(before) {
		t.Fatal("wrong migration", result)
	}
	budgetAfter, e := w.budget.Status(ctx)
	must(t, e)
	if budgetAfter.Revision <= budgetBefore.Revision || len(budgetAfter.Pending) != 0 {
		t.Fatal("migration bypassed budget or left reservations")
	}
	replay, e := w.RenewIngress(ctx, a.Trust.Domain, previous, fresh)
	must(t, e)
	if replay != result {
		t.Fatal("replay changed receipt")
	}
	saved, e := os.ReadFile(filepath.Join(filepath.Dir(path), "registry-v1-"+result.LegacyDigest+".json"))
	must(t, e)
	if !bytes.Equal(saved, before) {
		t.Fatal("legacy checkpoint changed")
	}
	stop = start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 2 })
	stop()
}

func TestWorkerIngressRenewalDoesNotCreateMissingHistoryOrIgnoreGuard(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w, ctx := f.nodes[1], context.Background()
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	previous, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	a.Revision = 2
	fresh, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Ingress = []json.RawMessage{fresh}
	f.cfg.Revision = 2
	f.config(t, 1, nil)
	if _, e = w.RenewIngress(ctx, a.Trust.Domain, previous, fresh); e == nil {
		t.Fatal("missing history initialized")
	}
	path := filepath.Join(DomainDirectory(w.dir, a.Trust), "ingress")
	if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("created ingress directory", e)
	}
	blocked := errors.New("volume no longer admitted")
	w.guard = func(context.Context) error { return blocked }
	if _, e = w.RenewIngress(ctx, a.Trust.Domain, previous, fresh); !errors.Is(e, blocked) {
		t.Fatal("ignored volume guard", e)
	}
	w.guard = nil
	cancelled, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	if _, e = w.RenewIngress(cancelled, a.Trust.Domain, previous, fresh); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("ignored cancellation", e)
	}
}

func TestWorkerIngressRenewalRechecksExpiryAfterPolicyLock(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	w, ctx := f.nodes[1], context.Background()
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	previous, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Ingress = []json.RawMessage{previous}
	f.config(t, 1, nil)
	stop := start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	stop()
	path := filepath.Join(DomainDirectory(w.dir, a.Trust), "ingress/state/registry.json")
	before, e := os.ReadFile(path)
	must(t, e)
	a.Revision, a.ExpiresUnix = 2, time.Now().Unix()+2
	fresh, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Revision, f.cfg.ExpiresUnix, f.cfg.Ingress = 2, a.ExpiresUnix, []json.RawMessage{fresh}
	f.config(t, 1, nil)
	done := make(chan error, 1)
	must(t, w.cache.WithCurrent(ctx, time.Now(), func(_ control.Config, _ []byte) error {
		go func() { _, e := w.RenewIngress(ctx, a.Trust.Domain, previous, fresh); done <- e }()
		time.Sleep(time.Until(time.Unix(a.ExpiresUnix, 0)) + 30*time.Millisecond)
		return nil
	}))
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("expired authority renewed after wait")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance did not join")
	}
	after, e := os.ReadFile(path)
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("expired migration changed registry")
	}
}
