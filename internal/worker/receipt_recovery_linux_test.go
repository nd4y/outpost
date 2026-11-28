package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWorkerReceiptRecoveryUsesCurrentPlacementLeaseAndBudget(t *testing.T) {
	f := newFixture(t)
	server := f.endpoint(t, nil)
	w := f.nodes[1]
	ctx := context.Background()
	owner := f.owner.Public().(ed25519.PublicKey)
	f.cfg.ExpiresUnix = time.Now().Unix() + 6
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	araw, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Ingress = []json.RawMessage{araw}
	f.config(t, 1, nil)
	w.Fault = func(point string) error {
		if point == "capture-replica-complete" {
			return errors.New("publication before receipt")
		}
		return nil
	}
	stop := start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	i := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte("settlement-operation")), Authority: storage.Hash(araw), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: time.Now().Unix(), NotBefore: a.NotBefore, ExpiresUnix: a.ExpiresUnix, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	iraw, e := ingress.SignIntent(i, araw, owner, f.writer, time.Now())
	must(t, e)
	limits := peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1}
	client, e := ingress.NewClient(server.URL, araw, iraw, owner, f.nodes[0].cert, f.ca.pool, limits)
	must(t, e)
	defer client.Close()
	must(t, client.Begin(ctx))
	s, e := filekit.OpenStreamingStore(filepath.Join(f.base, "settlement-cache"), f.dataOwner, true, client)
	must(t, e)
	defer s.Close()
	version, e := s.Backup(ctx, filepath.Join(f.base, "input"), filekit.BackupOptions{Names: []string{"dataset/data"}})
	must(t, e)
	raw, roots, e := generation.BuildCatalog(ctx, s, []string{version.Version}, generation.Catalog{Format: generation.Format, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Sequence: i.Sequence, SnapshotUnix: i.SnapshotUnix, Policy: i.Policy}, f.writer)
	must(t, e)
	for id, b := range roots {
		_, e = client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}

	if _, _, e = client.FinishStep(ctx, raw); e == nil {
		t.Fatal("publication interruption absent")
	}
	stop()
	w.Fault = nil
	id := storage.Hash(raw)
	path := filepath.Join(DomainDirectory(w.dir, a.Trust), "ingress/current/state/session.json")
	before, e := os.ReadFile(path)
	must(t, e)
	time.Sleep(time.Until(time.Unix(a.ExpiresUnix, 0)) + 30*time.Millisecond)
	grant := ingress.ReceiptRecovery{Format: ingress.ReceiptRecoveryFormat, ID: storage.Hash([]byte("fresh local recovery")), Authority: storage.Hash(araw), Intent: storage.Hash(iraw), Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Generation: id, NotBefore: time.Now().Unix(), ExpiresUnix: time.Now().Unix() + 300}
	graw, e := ingress.SignReceiptRecovery(grant, araw, iraw, f.owner, time.Now())
	must(t, e)
	item := ingress.ReceiptRecoveryAdmission{Authority: araw, Intent: iraw, Grant: graw}
	if _, e = w.RecoverIngressReceipt(ctx, i.Domain, item); e == nil {
		t.Fatal("expired receiver policy authorized repair")
	}
	after, e := os.ReadFile(path)
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("expired policy changed session")
	}
	f.cfg.Revision, f.cfg.NotBefore, f.cfg.ExpiresUnix = 2, grant.NotBefore, grant.ExpiresUnix
	f.cfg.Ingress = nil
	f.config(t, 1, nil)
	stop = start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 2 })
	if _, e = w.RecoverIngressReceipt(ctx, i.Domain, item); !errors.Is(e, ingress.ErrConflict) {
		t.Fatal("running worker admitted local repair", e)
	}
	stop()
	if _, e = w.RecoverIngressReceipt(ctx, storage.Hash([]byte("other domain")), item); !errors.Is(e, ErrDenied) {
		t.Fatal("wrong domain admitted", e)
	}
	edges := f.domain.Placement.Edges
	f.domain.Placement.Edges = nil
	f.cfg.Revision = 3
	f.config(t, 1, nil)
	if _, e = w.RecoverIngressReceipt(ctx, i.Domain, item); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked current placement admitted", e)
	}
	f.domain.Placement.Edges = edges
	f.cfg.Revision = 4
	f.config(t, 1, nil)
	budgetBefore, e := w.budget.Status(ctx)
	must(t, e)
	receipt, e := w.RecoverIngressReceipt(ctx, i.Domain, item)
	must(t, e)
	if receipt.Generation != id || receipt.VerifiedAt >= a.ExpiresUnix {
		t.Fatal("wrong recovered publication", receipt)
	}
	budgetAfter, e := w.budget.Status(ctx)
	must(t, e)
	if budgetAfter.Revision <= budgetBefore.Revision || len(budgetAfter.Pending) != 0 {
		t.Fatal("repair bypassed budget or left reservation")
	}
	again, e := w.RecoverIngressReceipt(ctx, i.Domain, item)
	must(t, e)
	if again != receipt {
		t.Fatal("repair replay differs")
	}
	out := filepath.Join(f.base, "receiver-repair-restored")
	_, e = generation.RecoverMaterialized(ctx, filepath.Join(DomainDirectory(w.dir, a.Trust), "replica"), id, a.Trust, f.dataOwner, generation.RecoverySelection{}, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "dataset/data"))
	must(t, e)
	if !bytes.Equal(got, f.content) {
		t.Fatal("repair changed restored file")
	}
}
