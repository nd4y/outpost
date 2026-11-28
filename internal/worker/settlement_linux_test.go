package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

type settlementBody struct {
	io.ReadCloser
	entered chan struct{}
	once    sync.Once
}

func (b *settlementBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	return b.ReadCloser.Read(p)
}

func TestWorkerSettlementReopensSameExpiredSlotAndRevokesSlowAcknowledgement(t *testing.T) {
	f := newFixture(t)
	entered := make(chan struct{})
	server := f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Outpost-Test-Stall") == "1" {
				r.Body = &settlementBody{ReadCloser: r.Body, entered: entered}
			}
			next.ServeHTTP(w, r)
		})
	})
	w := f.nodes[1]
	ctx := context.Background()
	owner := f.owner.Public().(ed25519.PublicKey)
	f.cfg.ExpiresUnix = time.Now().Unix() + 6
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Trust: f.domain.Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	araw, e := ingress.SignAuthority(a, f.owner)
	must(t, e)
	f.cfg.Ingress = []json.RawMessage{araw}
	f.config(t, 1, nil)
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
	_, original, e := client.FinishStep(ctx, raw)
	must(t, e)
	if original == nil {
		t.Fatal("no durable receipt")
	}
	stop()
	time.Sleep(time.Until(time.Unix(a.ExpiresUnix, 0)) + 30*time.Millisecond)
	grant := ingress.Settlement{Format: ingress.SettlementFormat, ID: storage.Hash([]byte("fresh-settlement")), Authority: storage.Hash(araw), Intent: storage.Hash(iraw), Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Generation: original.Generation, NotBefore: time.Now().Unix(), ExpiresUnix: time.Now().Unix() + 300}
	graw, e := ingress.SignSettlement(grant, araw, iraw, f.owner, time.Now())
	must(t, e)
	f.cfg.Format, f.cfg.Revision, f.cfg.NotBefore, f.cfg.ExpiresUnix = control.SettlementConfigFormat, 2, grant.NotBefore, grant.ExpiresUnix
	f.cfg.Ingress = nil
	f.cfg.Settlements = []control.SettlementAdmission{{Authority: araw, Intent: iraw, Grant: graw}}
	f.config(t, 1, nil)
	stop = start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 2 })
	settle, e := ingress.NewSettlementClient(server.URL, araw, iraw, graw, owner, f.nodes[0].cert, f.ca.pool, limits)
	must(t, e)
	defer settle.Close()
	got, e := settle.SettlementReceipt(ctx)
	must(t, e)
	if got != *original {
		t.Fatal("original receipt changed")
	}
	if client.Begin(ctx) == nil || settle.Begin(ctx) == nil {
		t.Fatal("expired payload write admitted")
	}
	// Reach the server with a partial acknowledgement body, bypassing the
	// settlement client's method guard, then revoke its owning configuration.
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[0].cert}}}
	defer transport.CloseIdleConnections()
	request, e := http.NewRequest(http.MethodPut, server.URL+"/v1/tenants/"+i.Tenant+"/domains/"+i.Domain+"/captures/"+i.Operation+"/ack", reader)
	must(t, e)
	request.ContentLength = 100
	request.Header.Set("Outpost-Authority", i.Authority)
	request.Header.Set("Outpost-Settlement", storage.Hash(graw))
	request.Header.Set("Outpost-Test-Stall", "1")
	done := make(chan bool, 1)
	go func() {
		response, e := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(request)
		accepted := e == nil && response.StatusCode == 200
		if response != nil {
			response.Body.Close()
		}
		done <- accepted
	}()
	_, e = writer.Write([]byte("{"))
	must(t, e)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("settlement body reader was not entered")
	}
	f.cfg.Settlements = nil
	f.cfg.Revision = 3
	startRevocation := time.Now()
	f.config(t, 1, nil)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 3 })
	if time.Since(startRevocation) > 3*time.Second {
		t.Fatal("revocation waited for body timeout")
	}
	writer.Close()
	select {
	case accepted := <-done:
		if accepted {
			t.Fatal("partial acknowledgement accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("settlement request did not join")
	}
	if _, e = settle.SettlementReceipt(ctx); e == nil {
		t.Fatal("withdrawn grant still admitted")
	}
	stop()
	// Reinstalling the explicit current policy recovers the same original slot.
	f.cfg.Revision = 4
	f.cfg.Settlements = []control.SettlementAdmission{{Authority: araw, Intent: iraw, Grant: graw}}
	f.config(t, 1, nil)
	stop = start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 4 })
	got, e = settle.SettlementReceipt(ctx)
	must(t, e)
	if got != *original {
		t.Fatal("revocation damaged receipt")
	}
	ack, e := settle.AcknowledgeStep(ctx, got)
	must(t, e)
	if !ack.Clean {
		t.Fatal("historical staging was not acknowledged")
	}
	stop()
}
