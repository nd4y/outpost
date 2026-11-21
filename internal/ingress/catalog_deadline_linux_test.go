package ingress

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

// The control changes only the publication batch size. Durability stalls once a
// request materializes more than one upload's payload, until that real HTTP
// request is cancelled. Bounded batches return durable HTTP 202 progress without
// relying on a performance threshold affected by race instrumentation.
func TestCatalogDeadlineBoundsAndReopenedVerificationProgress(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		name := "bounded-default"
		if legacy {
			name = "previous-large-batch-control"
		}
		t.Run(name, func(t *testing.T) {
			ca := newCA(t)
			source, receiver := ca.node(t), ca.node(t)
			f := setupIDs(t, certID(t, source), certID(t, receiver))
			ctx := context.Background()
			var requestContext atomic.Pointer[context.Context]
			joined := make(chan struct{}, 1)
			start := func(old bool) (*httptest.Server, *Client) {
				wire, err := NewServer(f.session, receiver, ca.roots, httpLimits)
				must(t, err)
				if old {
					wire, err = newServer(f.session, receiver, ca.roots, httpLimits, 256, 256<<20)
					must(t, err)
				}
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/catalog") {
						current := r.Context()
						requestContext.Store(&current)
						defer func() { requestContext.Store(nil); joined <- struct{}{} }()
					}
					wire.Handler.ServeHTTP(w, r)
				}))
				server.TLS = wire.TLSConfig
				server.StartTLS()
				t.Cleanup(server.Close)
				client, err := NewClient(server.URL, f.options.Authority, f.options.Intent, f.options.Owner, source, ca.roots, httpLimits)
				must(t, err)
				t.Cleanup(client.Close)
				return server, client
			}
			server, client := start(legacy)
			must(t, f.source.Close())
			var err error
			f.source, err = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, client)
			must(t, err)
			f.payload = make([]byte, 24<<20)
			_, err = rand.Read(f.payload)
			must(t, err)
			must(t, os.WriteFile(f.input, f.payload, 0600))
			version, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
			must(t, err)
			raw, roots := f.catalog(t, []string{version.Version})
			for id, payload := range roots {
				_, err = client.Write(ctx, filekit.Object{ID: id, Bytes: len(payload)}, payload)
				must(t, err)
			}
			f.options.Replica.Fault = func(point string) error {
				if point != "object-durable" {
					return nil
				}
				entries, err := os.ReadDir(filepath.Join(f.base, "replica/objects"))
				if err != nil {
					return err
				}
				var total int64
				for _, entry := range entries {
					info, err := entry.Info()
					if err != nil {
						return err
					}
					total += info.Size()
				}
				if total <= generation.MaxObject {
					return nil
				}
				current := requestContext.Load()
				if current == nil {
					return ErrProtocol
				}
				<-(*current).Done()
				return (*current).Err()
			}
			progress, receipt, firstErr := client.FinishStep(ctx, raw)
			select {
			case <-joined:
			case <-time.After(httpLimits.Timeout):
				t.Fatal("cancelled request did not join")
			}
			f.options.Replica.Fault = nil
			if legacy {
				if !errors.Is(firstErr, context.DeadlineExceeded) {
					t.Fatal("previous large-batch control did not reproduce the deadline")
				}
				if _, err := os.Stat(filepath.Join(f.base, "replica/verification", storage.Hash(raw))); !os.IsNotExist(err) {
					t.Fatal("cancelled old batch unexpectedly saved a complete verification checkpoint", err)
				}
			} else {
				must(t, firstErr)
				if progress.Complete || receipt != nil || progress.VerifiedObjects < 1 || progress.VerifiedObjects >= progress.TotalObjects || progress.WrittenBytes > generation.MaxObject {
					t.Fatal("default did not return bounded durable HTTP202 progress", progress, receipt)
				}
				if _, err := os.Stat(filepath.Join(f.base, "replica/verification", storage.Hash(raw))); err != nil {
					t.Fatal("bounded progress was not persisted", err)
				}
			}
			status, err := f.options.Replica.Status(ctx)
			must(t, err)
			if status.LatestComplete != "" {
				t.Fatal("partial catalog was falsely complete")
			}
			client.Close()
			server.Close()
			must(t, f.session.Close())
			f.session = nil
			must(t, f.options.Replica.Close())
			f.options.Replica, err = generation.Open(filepath.Join(f.base, "replica"), f.authority.Trust, false)
			must(t, err)
			t.Cleanup(func() { f.options.Replica.Close() })
			f.options.Initialize = false
			f.session, err = OpenSession(ctx, f.options)
			must(t, err)
			_, client = start(false)
			for steps := 0; steps < 64; steps++ {
				progress, receipt, err = client.FinishStep(ctx, raw)
				must(t, err)
				<-joined
				if progress.WrittenBytes > generation.MaxObject {
					t.Fatal("reopened default exceeded its payload batch bound", progress)
				}
				if progress.Complete {
					break
				}
			}
			if !progress.Complete || receipt == nil || receipt.Generation != storage.Hash(raw) {
				t.Fatal("reopened publication did not finish the exact catalog")
			}
			must(t, f.options.Replica.VerifyComplete(ctx, receipt.Generation))
			out := filepath.Join(f.base, "restored")
			_, err = generation.RecoverMaterialized(ctx, filepath.Join(f.base, "replica"), receipt.Generation, f.authority.Trust, f.owner, generation.RecoverySelection{}, out)
			must(t, err)
			payload, err := os.ReadFile(filepath.Join(out, "private/data"))
			must(t, err)
			if !bytes.Equal(payload, f.payload) {
				t.Fatal("reopened generation restored different bytes")
			}
			t.Logf("CATALOG_DEADLINE_CONTROL legacy=%t rpc-timeout=%s first-error=%v bytes=%d recovered=true", legacy, httpLimits.Timeout, firstErr, len(payload))
		})
	}
}
