package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWorkerAdmitsSourceUnderCachedPolicyAndCancelsRevokedGrant(t *testing.T) {
	f := newFixture(t)
	received := make(chan struct{}, 1)
	server := f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Outpost-Test-Stall") == "1" {
				received <- struct{}{}
			}
			next.ServeHTTP(w, r)
		})
	})
	ctx := context.Background()
	w := f.nodes[1]
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	araw, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Ingress = []json.RawMessage{araw}
	f.config(t, 1, nil)
	stop := start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	i := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte("source-op")), Authority: storage.Hash(araw), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: time.Now().Unix(), NotBefore: a.NotBefore, ExpiresUnix: a.ExpiresUnix, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	iraw, e := ingress.SignIntent(i, araw, f.owner.Public().(ed25519.PublicKey), f.writer, time.Now())
	must(t, e)
	client, e := ingress.NewClient(server.URL, araw, iraw, f.owner.Public().(ed25519.PublicKey), f.nodes[0].cert, f.ca.pool, peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1})
	must(t, e)
	defer client.Close()
	must(t, client.Begin(ctx))
	s, e := filekit.OpenStreamingStore(filepath.Join(f.base, "stream-cache"), f.dataOwner, true, client)
	must(t, e)
	defer s.Close()
	v, e := s.Backup(ctx, filepath.Join(f.base, "input"), filekit.BackupOptions{Names: []string{"dataset/data"}})
	must(t, e)
	raw, roots, e := generation.BuildCatalog(ctx, s, []string{v.Version}, generation.Catalog{Format: generation.Format, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Sequence: i.Sequence, SnapshotUnix: i.SnapshotUnix, Policy: i.Policy}, f.writer)
	must(t, e)
	for id, b := range roots {
		_, e = client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
	_, receipt, e := client.FinishStep(ctx, raw)
	must(t, e)
	if receipt == nil {
		t.Fatal("no complete receipt")
	}
	before, e := w.budget.Status(ctx)
	must(t, e)
	ack, e := client.AcknowledgeStep(ctx, *receipt)
	must(t, e)
	if !ack.Clean {
		t.Fatal("not clean")
	}
	after, e := w.budget.Status(ctx)
	must(t, e)
	if before.Used["data"] <= after.Used["data"] {
		t.Fatal("staging removal did not return quota")
	}
	stop()
	// Cached policy alone resumes the same registry and its durable fence.
	stop = start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	i.Sequence = 2
	i.Parent = receipt.Generation
	i.Operation = storage.Hash([]byte("source-op-2"))
	i.SnapshotUnix = time.Now().Unix()
	iraw, e = ingress.SignIntent(i, araw, f.owner.Public().(ed25519.PublicKey), f.writer, time.Now())
	must(t, e)
	next, e := ingress.NewClient(server.URL, araw, iraw, f.owner.Public().(ed25519.PublicKey), f.nodes[0].cert, f.ca.pool, peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1})
	must(t, e)
	defer next.Close()
	must(t, next.Begin(ctx))
	// A slow authenticated body must not hold the old policy alive. Context
	// cancellation alone does not interrupt net/http's body reader.
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[0].cert}}}
	defer transport.CloseIdleConnections()
	stall := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, e := http.NewRequest(http.MethodPut, server.URL+"/v1/tenants/"+i.Tenant+"/domains/"+i.Domain+"/captures/"+i.Operation+"/objects/"+storage.Hash([]byte("stalled-object")), reader)
	must(t, e)
	request.ContentLength = 100
	request.Header.Set("Outpost-Bytes", "100")
	request.Header.Set("Outpost-Authority", i.Authority)
	request.Header.Set("Outpost-Test-Stall", "1")
	finished := make(chan bool, 1)
	go func() {
		response, e := stall.Do(request)
		accepted := e == nil && response.StatusCode == 200
		if response != nil {
			response.Body.Close()
		}
		finished <- accepted
	}()
	_, e = writer.Write([]byte("x"))
	must(t, e)
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled request absent")
	}
	revoked := time.Now()
	f.cfg.Ingress = nil
	f.cfg.Revision = 2
	f.config(t, 1, nil)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 2 })
	if time.Since(revoked) > 3*time.Second {
		t.Fatal("revocation waited for body timeout")
	}
	writer.Close()
	select {
	case accepted := <-finished:
		if accepted {
			t.Fatal("partial body accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled request leaked after revocation")
	}
	b := []byte("denied after policy replacement")
	_, e = next.Write(ctx, filekit.Object{ID: storage.Hash(b), Bytes: len(b)}, b)
	if !errors.Is(e, ingress.ErrDenied) {
		t.Fatal("stale capability accepted", e)
	}
	stop()
	out := filepath.Join(f.base, "restored-ingress")
	_, e = generation.RecoverMaterialized(ctx, filepath.Join(DomainDirectory(w.dir, a.Trust), "replica"), receipt.Generation, a.Trust, f.dataOwner, generation.RecoverySelection{}, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "dataset/data"))
	must(t, e)
	if string(got) != string(f.content) {
		t.Fatal("policy revocation damaged previous generation")
	}
	// The ordinary signed configuration remains valid without the removed grant.
	_, e = control.Sign(f.config(t, 1, nil), f.owner)
	must(t, e)
}
