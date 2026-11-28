package peer

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestPeerBodyBudgetsPreserveCancelledPushAndVerifiedPull(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(f.input, f.old[:1<<20], 0640))
	generationID, _ := f.seal(t, 1, "")
	const rate = MinBodyBytesPerSecond
	receive, err := storage.NewHTTPBodyBudget(rate)
	must(t, err)
	send, err := storage.NewHTTPBodyBudget(rate)
	must(t, err)
	limits := Limits{Concurrency: 2, Timeout: 15 * time.Second, Attempts: 2}
	serverLimits := limits
	serverLimits.Bodies = BodyBudgets{Receive: receive, Send: send}
	largePUT := make(chan struct{}, 1)
	server := f.endpointWithLimits(t, f.a, f.policy(f.a, f.b, f.c), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") && r.ContentLength >= 128<<10 {
				select {
				case largePUT <- struct{}{}:
				default:
				}
			}
			next.ServeHTTP(w, r)
		})
	}, serverLimits)
	pushLimits := limits
	pushLimits.Bodies.Send, err = storage.NewHTTPBodyBudget(rate)
	must(t, err)
	push, err := NewClient(server.URL, f.a.id, f.b.cert, f.ca.roots, f.policy(f.b, f.a), f.b.journal, f.trust, pushLimits)
	must(t, err)
	defer push.Close()
	op := generation.Hash([]byte("paced push"))
	attempt, cancel := context.WithTimeout(t.Context(), limits.Timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := push.Push(attempt, op, generationID, f.b.replica)
		done <- err
	}()
	select {
	case <-largePUT:
	case err := <-done:
		t.Fatalf("push ended before its bulk PUT: %v", err)
	case <-attempt.Done():
		t.Fatal("push did not start its bulk PUT")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pace-bound push did not stop with its parent: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled push did not join")
	}
	status, err := f.a.replica.Status(t.Context())
	must(t, err)
	if status.LatestComplete != "" {
		t.Fatal("cancelled push published a generation")
	}
	completed, err := push.Push(t.Context(), op, generationID, f.b.replica)
	must(t, err)
	if completed.Receipt.Verification != "client-full-readback" {
		t.Fatal("retried push lost verified readback", completed)
	}
	pull, err := NewClient(server.URL, f.a.id, f.c.cert, f.ca.roots, f.policy(f.c, f.a), f.c.journal, f.trust, limits)
	must(t, err)
	defer pull.Close()
	start := time.Now()
	completed, err = pull.Pull(t.Context(), generation.Hash([]byte("paced pull")), generationID, f.c.replica)
	must(t, err)
	if completed.Receipt.Verification != "local-window-read" || completed.Receipt.Target != f.c.id {
		t.Fatal("paced pull lost the local verification receipt", completed)
	}
	if elapsed := time.Since(start); elapsed < 750*time.Millisecond {
		t.Fatalf("peer GET did not share the server send budget: %s", elapsed)
	}
}
