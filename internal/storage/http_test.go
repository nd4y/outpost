package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/teststore"
)

func profile(s *teststore.Server) Profile {
	return Profile{Kind: s.Options.Kind, Endpoint: s.Endpoint(), Namespace: s.Options.Namespace, Region: func() string {
		if s.Options.Kind == "s3" {
			return s.Options.Region
		}
		return ""
	}(), MaxObjectBytes: s.Options.MaxObject, Concurrency: 2, RequestsPerSecond: 1000, Attempts: 3, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
}
func backend(t *testing.T, s *teststore.Server) *Backend {
	t.Helper()
	b, e := New(profile(s), Credentials{Access: "test-worker", Secret: "ephemeral-test-secret", ExpiresUnix: time.Now().Add(time.Minute).Unix()}, s.Roots)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(b.Close)
	return b
}
func TestProtocolMultipartAndImmutableReadback(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			s := teststore.New(t, teststore.Options{Kind: kind, Namespace: Hash([]byte(kind))})
			b := backend(t, s)
			ctx := context.Background()
			if e := b.Probe(ctx); e != nil {
				t.Fatal(e)
			}
			data := make([]byte, 150<<10)
			if _, e := rand.Read(data); e != nil {
				t.Fatal(e)
			}
			ref := generation.Object{ID: Hash(data), Bytes: len(data)}
			blob, e := Describe(ref, data, b.profile.MaxObjectBytes)
			if e != nil || len(blob.Parts) != 3 {
				t.Fatal("multipart description", e)
			}
			if e = b.PutBlob(ctx, ref, data); e != nil {
				t.Fatal(e)
			}
			changedProfile := b.profile
			changedProfile.MaxObjectBytes *= 2
			changedBackend, e := New(changedProfile, b.credentials, s.Roots)
			if e != nil {
				t.Fatal(e)
			}
			defer changedBackend.Close()
			if e = changedBackend.Probe(ctx); !errors.Is(e, ErrConflict) {
				t.Fatal("namespace layout changed silently", e)
			}
			got, e := b.ReadBlob(ctx, ref)
			if e != nil || !bytes.Equal(data, got) {
				t.Fatal("reassembled bytes differ", e)
			}
			if e = b.PutBlob(ctx, ref, data); e != nil {
				t.Fatal(e)
			}
			wrong := append([]byte(nil), data[:blob.Parts[0].Bytes]...)
			wrong[0] ^= 1
			if e = b.Put(ctx, "part-"+blob.Parts[0].ID, wrong); !errors.Is(e, ErrConflict) {
				t.Fatal("immutable object overwritten", e)
			}
			got, e = b.ReadBlob(ctx, ref)
			if e != nil || !bytes.Equal(data, got) {
				t.Fatal("duplicate changed data", e)
			}
			for _, count := range s.Snapshot().Writes {
				if count != 1 {
					t.Fatal("object rewritten")
				}
			}
			requests := s.Snapshot().Requests
			if e = b.Put(ctx, "too-large", make([]byte, b.profile.MaxObjectBytes+1)); !errors.Is(e, ErrCapacity) || s.Snapshot().Requests != requests {
				t.Fatal("local size admission failed", e)
			}
		})
	}
}

func TestProtocolProbeStaysBoundedAcrossRestartsConcurrentWorkersAndLostReply(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			var lost atomic.Bool
			s := teststore.New(t, teststore.Options{
				Kind: kind, Namespace: Hash([]byte("bounded-probe-" + kind)),
				AfterWrite: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
					if strings.HasPrefix(key, "probe-") && lost.CompareAndSwap(false, true) {
						conn, _, e := w.(http.Hijacker).Hijack()
						if e == nil {
							conn.Close()
						}
						return true
					}
					return false
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for range 4 {
				b := backend(t, s)
				if e := b.Probe(ctx); e != nil {
					t.Fatal(e)
				}
				b.Close()
			}
			result := make(chan error, 3)
			for range 3 {
				b := backend(t, s)
				go func() { result <- b.Probe(ctx) }()
			}
			for range 3 {
				if e := <-result; e != nil {
					t.Fatal(e)
				}
			}
			snapshot := s.Snapshot()
			if !lost.Load() || len(snapshot.Writes) != 2 {
				t.Fatal("probe retry accumulated objects", snapshot.Writes)
			}
			probe := ""
			for key, count := range snapshot.Writes {
				if count != 1 {
					t.Fatal("diagnostic object overwritten", key, count)
				}
				if strings.HasPrefix(key, "probe-") {
					probe = key
				}
			}
			if probe == "" || snapshot.Writes["layout"] != 1 {
				t.Fatal(snapshot.Writes)
			}
			// Corruption is preserved and refused; the probe is not silently reset.
			bad := bytes.Repeat([]byte{0x7f}, 32)
			if e := os.WriteFile(s.Path(probe), bad, 0600); e != nil {
				t.Fatal(e)
			}
			if e := backend(t, s).Probe(ctx); !errors.Is(e, ErrConflict) {
				t.Fatal("changed probe accepted", e)
			}
			got, e := os.ReadFile(s.Path(probe))
			if e != nil || !bytes.Equal(got, bad) || len(s.Snapshot().Writes) != 2 {
				t.Fatal("probe corruption overwritten", e)
			}
		})
	}
}
func TestProtocolRetriesAndLostReply(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			var throttle atomic.Int64
			var cut atomic.Bool
			s := teststore.New(t, teststore.Options{Kind: kind, Namespace: Hash([]byte(kind)), Before: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
				if r.Method == "PUT" && strings.HasPrefix(key, "part-") && throttle.Add(1) <= 2 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(429)
					return true
				}
				return false
			}, AfterWrite: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
				if strings.HasPrefix(key, "part-") && !cut.Swap(true) {
					conn, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						conn.Close()
					}
					return true
				}
				return false
			}})
			b := backend(t, s)
			data := []byte("opaque payload")
			part := generation.Object{ID: Hash(data), Bytes: len(data)}
			// First budget ends at the lost durable-write reply. A new invocation safely resumes.
			e := b.PutPart(context.Background(), part, data)
			if e != nil && !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			if e = b.PutPart(context.Background(), part, data); e != nil {
				t.Fatal(e)
			}
			if s.Snapshot().Writes["part-"+part.ID] != 1 || !cut.Load() {
				t.Fatal("duplicate or lost-reply path not exercised")
			}
		})
	}
}
func TestProtocolLongThrottlePersistsAcrossCalls(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		for _, hint := range []string{"60", "184467440737095516160"} {
			t.Run(kind+"/"+hint, func(t *testing.T) {
				s := teststore.New(t, teststore.Options{Kind: kind, Namespace: Hash([]byte(kind)), Before: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
					w.Header().Set("Retry-After", hint)
					w.WriteHeader(429)
					return true
				}})
				b := backend(t, s)
				if e := b.Put(context.Background(), "throttled", []byte("opaque")); !errors.Is(e, ErrUnavailable) {
					t.Fatal("long throttle not returned", e)
				}
				requests := s.Snapshot().Requests
				// Profile timeout must also bound local admission, without waiting 60 seconds.
				b.profile.TimeoutMillis = 20
				if _, e := b.Get(context.Background(), "throttled"); !errors.Is(e, context.DeadlineExceeded) {
					t.Fatal("queued request ignored timeout", e)
				}
				if requests != 1 || s.Snapshot().Requests != requests {
					t.Fatal("subsequent call bypassed server cooldown")
				}
			})
		}
	}
}
func TestProtocolFaultsNeverBecomeVerified(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		for _, fault := range []string{"false-ack", "truncated", "corrupt", "quota"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				var enabled atomic.Bool
				s := teststore.New(t, teststore.Options{Kind: kind, Namespace: Hash([]byte(kind + fault)), Before: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
					if !enabled.Load() || !strings.HasPrefix(key, "part-") {
						return false
					}
					if fault == "false-ack" && r.Method == "PUT" {
						w.WriteHeader(201)
						return true
					}
					if fault == "quota" && r.Method == "PUT" {
						w.WriteHeader(507)
						return true
					}
					if r.Method == "GET" && (fault == "truncated" || fault == "corrupt") {
						data := []byte("opaque-payload")
						w.Header().Set("Content-Length", strconv.Itoa(len(data)))
						if fault == "truncated" {
							data = data[:3]
						} else {
							data[0] ^= 1
						}
						_, _ = w.Write(data)
						return true
					}
					return false
				}})
				b := backend(t, s)
				data := []byte("opaque-payload")
				part := generation.Object{ID: Hash(data), Bytes: len(data)}
				if fault == "truncated" || fault == "corrupt" {
					if e := b.PutPart(context.Background(), part, data); e != nil {
						t.Fatal(e)
					}
				}
				enabled.Store(true)
				var e error
				if fault == "truncated" || fault == "corrupt" {
					_, e = b.ReadPart(context.Background(), part)
				} else {
					e = b.PutPart(context.Background(), part, data)
				}
				if e == nil {
					t.Fatal("fault accepted as verified")
				}
			})
		}
	}
}
func TestProtocolAuthorizationRoutesAndCapabilityProbe(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			var redirected atomic.Int64
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(200) }))
			defer other.Close()
			var redirect, ignoreConditional atomic.Bool
			dir := teststore.Root(t)
			ns := Hash([]byte(kind))
			s := teststore.New(t, teststore.Options{Kind: kind, Namespace: ns, Directory: dir, Before: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
				if redirect.Load() {
					http.Redirect(w, r, other.URL, 307)
					return true
				}
				if ignoreConditional.Load() && r.Method == "PUT" {
					if e := os.WriteFile(dir+"/"+ns+"-"+key, body, 0600); e != nil {
						w.WriteHeader(500)
					} else {
						w.WriteHeader(201)
					}
					return true
				}
				return false
			}})
			b := backend(t, s)
			ctx := context.Background()
			redirect.Store(true)
			if b.Probe(ctx) == nil || redirected.Load() != 0 {
				t.Fatal("unapproved redirect followed")
			}
			redirect.Store(false)
			ignoreConditional.Store(true)
			if e := b.Probe(ctx); !errors.Is(e, ErrUnsupported) {
				t.Fatal("conditional-write violation accepted", e)
			}
			ignoreConditional.Store(false)
			p := profile(s)
			p.Endpoint = strings.Replace(p.Endpoint, "https://", "http://", 1)
			if _, e := New(p, b.credentials, s.Roots); e == nil {
				t.Fatal("plaintext accepted")
			}
			p = profile(s)
			p.Namespace = Hash([]byte("unauthorized namespace"))
			wrong, e := New(p, b.credentials, s.Roots)
			if e != nil {
				t.Fatal(e)
			}
			defer wrong.Close()
			if !errors.Is(wrong.Probe(ctx), ErrDenied) {
				t.Fatal("namespace escaped")
			}
			wrongCA, e := New(profile(s), b.credentials, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer wrongCA.Close()
			if wrongCA.Probe(ctx) == nil {
				t.Fatal("untrusted TLS certificate accepted")
			}
			b.credentials.ExpiresUnix = time.Now().Unix() - 1
			if !errors.Is(b.Probe(ctx), ErrDenied) {
				t.Fatal("expired authority accepted")
			}
		})
	}
}
