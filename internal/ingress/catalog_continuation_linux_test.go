package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func TestIngressCatalogContinuationUploadsOneCatalogAcrossBatches(t *testing.T) {
	testCatalogContinuation(t, "normal", true)
}

func TestCatalogContinuationLegacyAndWrongHint(t *testing.T) {
	for _, mode := range []string{"omit", "wrong", "raw", "duplicate", "malformed", "mixed"} {
		t.Run(mode, func(t *testing.T) { testCatalogContinuation(t, mode, false) })
	}
}

type catalogHintWriter struct {
	http.ResponseWriter
	mode    string
	corrupt bool
}

func (w catalogHintWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w catalogHintWriter) Write(p []byte) (int, error) {
	if w.corrupt {
		_, err := w.ResponseWriter.Write([]byte("{}"))
		return len(p), err
	}
	return w.ResponseWriter.Write(p)
}

func (w catalogHintWriter) WriteHeader(code int) {
	if w.mode == "omit" {
		w.Header().Del(catalogResumeHeader)
	}
	if w.mode == "wrong" {
		w.Header().Set(catalogResumeHeader, storage.Hash([]byte("different candidate")))
	}
	if w.mode == "duplicate" && w.Header().Get(catalogResumeHeader) != "" {
		w.Header().Add(catalogResumeHeader, w.Header().Get(catalogResumeHeader))
	}
	w.ResponseWriter.WriteHeader(code)
}

func testCatalogContinuation(t *testing.T, mode string, reopen bool) {
	t.Helper()
	ca := newCA(t)
	source, receiver := ca.node(t), ca.node(t)
	f := setupIDs(t, certID(t, source), certID(t, receiver))
	wire, err := newServer(f.session, receiver, ca.roots, httpLimits, 1, generation.MaxObject)
	must(t, err)
	var calls, catalogBytes atomic.Int64
	var wireMu sync.RWMutex
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wireMu.RLock()
		defer wireMu.RUnlock()
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/catalog") {
			body, e := io.ReadAll(io.LimitReader(r.Body, generation.MaxCatalog+1))
			if e != nil || len(body) > generation.MaxCatalog {
				http.Error(w, "invalid test body", http.StatusBadRequest)
				return
			}
			r.Body.Close()
			calls.Add(1)
			catalogBytes.Add(int64(len(body)))
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		if mode == "mixed" && calls.Load() == 2 && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/catalog") {
			r.Header.Del(catalogResumeHeader)
		}
		corrupt := mode == "malformed" && calls.Load() == 2 && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/catalog")
		wire.Handler.ServeHTTP(catalogHintWriter{w, mode, corrupt}, r)
	}))
	server.TLS = wire.TLSConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, f.options.Authority, f.options.Intent, f.options.Owner, source, ca.roots, httpLimits)
	must(t, err)
	t.Cleanup(client.Close)
	must(t, f.source.Close())
	f.source, err = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, client)
	must(t, err)
	ctx := context.Background()
	stats, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
	must(t, err)
	raw, roots := f.catalog(t, []string{stats.Version})
	for id, body := range roots {
		_, err = client.Write(ctx, filekit.Object{ID: id, Bytes: len(body)}, body)
		must(t, err)
	}
	complete := false
	var accepted Receipt
	for step := 0; step < 64; step++ {
		var progress generation.BatchResult
		var receipt *Receipt
		if mode == "raw" {
			status, _, body, e := client.request(ctx, http.MethodPut, "catalog", nil, raw, 8192)
			must(t, e)
			var reply finishReply
			must(t, decodeReply(body, &reply))
			if status != http.StatusAccepted && status != http.StatusOK {
				t.Fatal("legacy wire reply", status)
			}
			progress, receipt = reply.Progress, reply.Receipt
		} else {
			progress, receipt, err = client.FinishStep(ctx, raw)
			if (mode == "malformed" || mode == "mixed") && step == 1 {
				expected := ErrProtocol
				if mode == "mixed" {
					expected = ErrConflict
				}
				if !errors.Is(err, expected) {
					t.Fatal("continuation fault not observed", err)
				}
				continue
			}
			must(t, err)
		}
		if receipt != nil {
			if !progress.Complete || !client.ValidReceipt(*receipt) {
				t.Fatal("invalid completion receipt")
			}
			complete = true
			accepted = *receipt
			break
		}
		if step == 0 && reopen {
			func() {
				wireMu.Lock()
				defer wireMu.Unlock()
				must(t, f.session.Close())
				o := f.options
				o.Initialize = false
				f.session, err = OpenSession(ctx, o)
				must(t, err)
				wire, err = newServer(f.session, receiver, ca.roots, httpLimits, 1, generation.MaxObject)
				must(t, err)
			}()
		}
	}
	if !complete || calls.Load() < 2 {
		t.Fatal("fixture did not exercise multiple completion requests", complete, calls.Load())
	}
	t.Logf("catalog-body-measurement requests=%d catalog-bytes=%d total-uploaded-catalog-bytes=%d", calls.Load(), len(raw), catalogBytes.Load())
	expected := int64(len(raw))
	if mode == "malformed" || mode == "mixed" {
		expected *= 2
	} else if mode != "normal" {
		expected *= calls.Load()
	}
	if catalogBytes.Load() != expected {
		t.Fatalf("full catalog resent across bounded steps: single=%d actual=%d requests=%d", len(raw), catalogBytes.Load(), calls.Load())
	}
	must(t, f.options.Replica.VerifyComplete(ctx, storage.Hash(raw)))
	if mode == "normal" {
		_, again, e := client.FinishStep(ctx, raw)
		must(t, e)
		if again == nil || again.VerifiedAt != accepted.VerifiedAt || again.Generation != accepted.Generation || again.Operation != accepted.Operation || again.NewBytes != accepted.NewBytes {
			t.Fatal("complete retry renewed or changed the original receipt")
		}
		ack, e := f.session.Acknowledge(ctx, accepted, 256)
		must(t, e)
		if !ack.Clean {
			t.Fatal("fixture acknowledgment incomplete")
		}
		_, _, e = client.FinishStep(ctx, raw)
		if !errors.Is(e, ErrConflict) {
			t.Fatal("acknowledged candidate resumed", e)
		}
		if catalogBytes.Load() != int64(len(raw)) {
			t.Fatal("complete retry resent catalog")
		}
		must(t, f.options.Replica.VerifyComplete(ctx, storage.Hash(raw)))
	}
}

func TestCatalogContinuationRejectsMissingChangedAndAmbiguousCandidate(t *testing.T) {
	f := network(t, nil)
	ctx := t.Context()
	status, _, _, err := f.client.requestCatalog(ctx, http.MethodPut, "catalog", nil, nil, 8192, storage.Hash([]byte("absent")))
	if !errors.Is(err, ErrIncomplete) {
		t.Fatal("missing candidate accepted", status, err)
	}
	stats, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
	must(t, err)
	raw, roots := f.catalog(t, []string{stats.Version})
	for id, body := range roots {
		_, err = f.client.Write(ctx, filekit.Object{ID: id, Bytes: len(body)}, body)
		must(t, err)
	}
	progress, _, err := f.session.FinishBatch(ctx, raw, 1, generation.MaxObject)
	must(t, err)
	if progress.Complete {
		t.Fatal("fixture completed before negative cases")
	}
	digest := storage.Hash(raw)
	foreign := setup(t)
	foreignVersion, e := foreign.source.Backup(ctx, foreign.input, filekit.BackupOptions{Names: []string{"foreign/data"}})
	must(t, e)
	foreignCatalog, _ := foreign.catalog(t, []string{foreignVersion.Version})
	for _, tc := range []struct {
		name, id  string
		method    string
		body      []byte
		authority string
		operation string
		status    int
		rogue     bool
		duplicate bool
	}{
		{name: "empty-digest", id: "", status: http.StatusBadRequest},
		{name: "malformed-digest", id: "not-a-digest", status: http.StatusBadRequest},
		{name: "wrong-digest", id: storage.Hash([]byte("other")), status: http.StatusConflict},
		{name: "foreign-catalog-on-current-route", id: storage.Hash(foreignCatalog), status: http.StatusConflict},
		{name: "read-incomplete-catalog", id: digest, method: http.MethodGet, status: http.StatusPreconditionFailed},
		{name: "body-and-digest", id: digest, body: raw, status: http.StatusBadRequest},
		{name: "duplicate-digest", id: digest, duplicate: true, status: http.StatusBadRequest},
		{name: "wrong-authority", id: digest, authority: storage.Hash([]byte("wrong")), status: http.StatusForbidden},
		{name: "wrong-operation", id: digest, operation: storage.Hash([]byte("wrong operation")), status: http.StatusForbidden},
		{name: "wrong-source", id: digest, rogue: true, status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := f.sourceCert
			if tc.rogue {
				cert = f.ca.node(t)
			}
			h, _, err := peer.AuthenticatedHTTP(f.server.URL, cert, f.ca.roots, certID(t, cert), f.intent.Ingress, httpLimits)
			must(t, err)
			defer h.CloseIdleConnections()
			path := route(f.intent) + "/catalog"
			if tc.operation != "" {
				path = strings.Replace(path, f.intent.Operation, tc.operation, 1)
			}
			method := tc.method
			if method == "" {
				method = http.MethodPut
			}
			r, err := http.NewRequestWithContext(ctx, method, f.server.URL+path, bytes.NewReader(tc.body))
			must(t, err)
			authority := f.intent.Authority
			if tc.authority != "" {
				authority = tc.authority
			}
			r.Header.Set("Outpost-Authority", authority)
			r.Header.Set(catalogResumeHeader, tc.id)
			if tc.duplicate {
				r.Header.Add(catalogResumeHeader, tc.id)
			}
			response, err := h.Do(r)
			must(t, err)
			response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatal("unexpected refusal", response.StatusCode, tc.status)
			}
			f.session.mu.Lock()
			defer f.session.mu.Unlock()
			if f.session.state.Complete || !bytes.Equal(f.session.state.Catalog, raw) {
				t.Fatal("refusal altered candidate or completed generation")
			}
		})
	}
	for {
		p, r, e := f.client.FinishStep(ctx, raw)
		must(t, e)
		if r != nil {
			if !p.Complete {
				t.Fatal("incomplete receipt")
			}
			break
		}
	}
}

func TestCatalogContinuationRejectsExpiredIntent(t *testing.T) {
	f := shortSettlementRegistry(t)
	ctx := t.Context()
	must(t, f.client.Begin(ctx))
	stats, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"data"}})
	must(t, err)
	raw, roots := f.catalog(t, []string{stats.Version})
	for id, body := range roots {
		_, err = f.client.Write(ctx, filekit.Object{ID: id, Bytes: len(body)}, body)
		must(t, err)
	}
	progress, _, err := f.registry.session.FinishBatch(ctx, raw, 1, generation.MaxObject)
	must(t, err)
	if progress.Complete {
		t.Fatal("fixture completed before expiry")
	}
	// Send through the real TLS handler, bypassing the client's local expiry
	// refusal. The durable candidate alone must not authorize another batch.
	h, _, err := peer.AuthenticatedHTTP(f.server.URL, f.sourceCert, f.ca.roots, f.intent.Source, f.intent.Ingress, httpLimits)
	must(t, err)
	defer h.CloseIdleConnections()
	time.Sleep(time.Until(time.Unix(f.intent.ExpiresUnix, 0)) + 20*time.Millisecond)
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, f.server.URL+route(f.intent)+"/catalog", http.NoBody)
	must(t, err)
	r.Header.Set("Outpost-Authority", f.intent.Authority)
	r.Header.Set(catalogResumeHeader, storage.Hash(raw))
	response, err := h.Do(r)
	must(t, err)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("expired catalog continuation admitted", response.StatusCode)
	}
	f.registry.session.mu.Lock()
	defer f.registry.session.mu.Unlock()
	if f.registry.session.state.Complete || !bytes.Equal(f.registry.session.state.Catalog, raw) {
		t.Fatal("expiry refusal changed the saved candidate")
	}
}
