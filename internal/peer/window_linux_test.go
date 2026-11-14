package peer

import (
	"context"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

type progressStopper struct {
	http.ResponseWriter
	stop  context.CancelFunc
	once  *atomic.Bool
	count *atomic.Int64
}

func (w progressStopper) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	if status == http.StatusAccepted {
		w.count.Add(1)
		if w.once.CompareAndSwap(false, true) {
			w.stop()
		}
	}
}
func TestPeerVerificationWindowResumesAfterInterruptedProgressResponse(t *testing.T) {
	f := newFixture(t)
	f.old = make([]byte, 12<<20)
	_, e := rand.Read(f.old)
	must(t, e)
	must(t, os.WriteFile(f.input, f.old, 0640))
	id, version := f.seal(t, 1, "")
	interrupted, stop := context.WithCancel(testContext)
	defer stop()
	var once atomic.Bool
	var count atomic.Int64
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(progressStopper{w, stop, &once, &count}, r)
		})
	})
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	op := generation.Hash([]byte("interrupted window"))
	if _, e = client.Push(interrupted, op, id, f.b.replica); e == nil {
		t.Fatal("interruption absent")
	}
	if count.Load() != 1 {
		t.Fatal("bounded progress not exercised", count.Load())
	}
	state, e := f.a.replica.Status(testContext)
	must(t, e)
	if state.LatestComplete != "" {
		t.Fatal("partial window published")
	}
	firstAt := time.Now().Unix()
	time.Sleep(1100 * time.Millisecond)
	client.Close()
	server.Close()
	must(t, f.a.replica.Close())
	must(t, f.b.journal.Close())
	f.a.replica, e = generation.Open(filepath.Join(f.a.dir, "replica"), f.trust, false)
	must(t, e)
	f.b.journal, e = OpenJournal(filepath.Join(f.b.dir, "journal"), f.b.id, f.trust, false)
	must(t, e)
	server = f.endpoint(t, f.a, f.policy(f.a, f.b), nil)
	client = f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	result, e := client.Push(testContext, op, id, f.b.replica)
	must(t, e)
	if result.Counters.ObjectBytesSubmitted != 0 || result.TargetReceipt.Format != WindowReceiptFormat || result.TargetReceipt.ObservedUnix > firstAt {
		t.Fatal("lost prefix or original time", result)
	}
	restore(t, f, f.a, id, version, f.old)
}

func TestPeerVerificationWindowAcceptsLegacyServerAndRejectsFalseProgress(t *testing.T) {
	for _, mode := range []string{"legacy", "wrong-operation", "no-progress", "unknown-version"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			id, _ := f.seal(t, 1, "")
			raw, e := f.b.replica.Catalog(testContext, id)
			must(t, e)
			refs, e := generation.Dependencies(raw, f.trust)
			must(t, e)
			server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "legacy" {
						r.Header.Del(windowHeader)
					}
					if mode == "unknown-version" {
						r.Header.Set(windowHeader, "99")
					}
					if strings.HasSuffix(r.URL.Path, "/complete") && (mode == "wrong-operation" || mode == "no-progress") {
						p := windowProgress{windowProgressFormat, r.Header.Get("Outpost-Operation"), id, 1, len(refs)}
						if mode == "wrong-operation" {
							p.Operation = generation.Hash([]byte("wrong"))
						} else {
							p.VerifiedObjects = 0
						}
						w.WriteHeader(http.StatusAccepted)
						respond(w, p)
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
			op := generation.Hash([]byte(mode))
			result, e := client.Push(testContext, op, id, f.b.replica)
			if mode == "legacy" {
				must(t, e)
				if result.TargetReceipt.Verification != "target-full-read" {
					t.Fatal("legacy receipt lost")
				}
				return
			}
			if e == nil {
				t.Fatal("invalid extension accepted")
			}
			job, e := f.b.journal.Read(testContext, client.binding(op, id, "push"))
			must(t, e)
			if job.Phase == "COMPLETE" || job.LastReceipt != nil {
				t.Fatal("progress became receipt")
			}
		})
	}
}
