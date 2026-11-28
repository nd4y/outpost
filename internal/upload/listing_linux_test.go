package upload

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestExternalRecoveryUsesSignedNamesDespiteIncompleteListings(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureBytes(t, 150<<10)
			provider := f.server(t, kind, 0, nil)
			objects := provider.HTTP.Config.Handler
			var listRequests atomic.Int32
			listMethod, listPath, listCode, listBody := http.MethodGet, "/objects/?list-type=2", http.StatusOK,
				`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>objects</Name><KeyCount>0</KeyCount><IsTruncated>true</IsTruncated><NextContinuationToken>page-omitted</NextContinuationToken></ListBucketResult>`
			if kind == "webdav" {
				listMethod, listPath, listCode, listBody = "PROPFIND", "/objects/", http.StatusMultiStatus,
					`<D:multistatus xmlns:D="DAV:"><D:response><D:href>/objects/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`
			}
			front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s3Listing := kind == "s3" && r.Method == http.MethodGet &&
					(r.URL.Query().Has("list-type") || strings.TrimSuffix(r.URL.Path, "/") == "/objects")
				if s3Listing || kind == "webdav" && r.Method == "PROPFIND" {
					listRequests.Add(1)
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(listCode)
					_, _ = io.WriteString(w, listBody)
					return
				}
				objects.ServeHTTP(w, r)
			}))
			t.Cleanup(front.Close)
			roots := x509.NewCertPool()
			roots.AddCert(front.Certificate())
			target := &teststore.Server{HTTP: front, Roots: roots, Options: provider.Options}
			b := f.backend(t, target, 0)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			must(t, b.Probe(ctx))

			putDependencies := func(id string, omitOne bool) []byte {
				t.Helper()
				raw, e := f.replicas[0].Catalog(ctx, id)
				must(t, e)
				refs, e := generation.Dependencies(raw, f.authority.Generation)
				must(t, e)
				if len(refs) < 2 {
					t.Fatal("expected separate signed generation dependencies")
				}
				for i, ref := range refs {
					if omitOne && i == 0 {
						continue
					}
					object, e := f.replicas[0].ReadObject(ctx, id, ref)
					must(t, e)
					must(t, b.PutBlob(ctx, ref, object))
				}
				return raw
			}
			firstRaw := putDependencies(f.id, false)
			must(t, b.Publish(ctx, firstRaw, f.authority.Generation))

			// Show that the fixture returns an apparently successful listing
			// omitting even the known, fully published first generation.
			list, e := http.NewRequestWithContext(ctx, listMethod, front.URL+listPath, nil)
			must(t, e)
			if kind == "webdav" {
				list.Header.Set("Depth", "1")
			}
			response, e := front.Client().Do(list)
			must(t, e)
			listed, e := io.ReadAll(io.LimitReader(response.Body, 4097))
			must(t, errors.Join(e, response.Body.Close()))
			if response.StatusCode != listCode || string(listed) != listBody || bytes.Contains(listed, []byte(f.id)) {
				t.Fatal("incomplete listing control did not omit the published generation")
			}

			old := append([]byte(nil), f.data...)
			changed := bytes.Repeat([]byte{0x73, 0x51, 0xcf, 0x89}, len(old)/4)
			must(t, os.WriteFile(f.input, changed, 0640))
			second, secondVersion := f.capture(t, 2, f.id)
			raw := putDependencies(second, true)
			if e = b.Publish(ctx, raw, f.authority.Generation); !errors.Is(e, storage.ErrNotFound) {
				t.Fatal("partial generation was not rejected at the exact dependency", e)
			}
			if _, e = os.Lstat(provider.Path("complete-" + second)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("incomplete listing or partial upload produced a completion marker", e)
			}

			recoveryDir := filepath.Join(teststore.Root(t), "replica")
			must(t, os.Mkdir(recoveryDir, 0700))
			replica, e := generation.Open(recoveryDir, f.authority.Generation, true)
			must(t, e)
			defer replica.Close()
			must(t, b.Recover(ctx, f.id, replica))
			if e = b.Recover(ctx, second, replica); !errors.Is(e, storage.ErrNotFound) {
				t.Fatal("partial generation unexpectedly became readable", e)
			}
			known, e := replica.Catalog(ctx, f.id)
			must(t, e)
			if !bytes.Equal(known, firstRaw) {
				t.Fatal("failed recovery changed the preceding signed generation")
			}
			if _, e = replica.Catalog(ctx, second); !errors.Is(e, generation.ErrIncomplete) {
				t.Fatal("failed recovery appeared complete in the reader", e)
			}

			raw = putDependencies(second, false)
			must(t, b.Publish(ctx, raw, f.authority.Generation))
			recoverBytes(t, f, target, f.id, f.version, old)
			recoverBytes(t, f, target, second, secondVersion, changed)
			if count := listRequests.Load(); count != 1 {
				t.Fatalf("unexpected endpoint listing requests: got %d, want only the fixture control", count)
			}
		})
	}
}
