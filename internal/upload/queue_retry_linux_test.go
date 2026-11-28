package upload

import (
	"context"
	"errors"
	"github.com/nd4y/outpost/internal/storage"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestQueueCommandRetrySurvivesLostResultAndNeverRepeatsEffect(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var full atomic.Bool
	full.Store(true)
	s := f.server(t, "webdav", 0, func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
		if full.Load() {
			w.WriteHeader(507)
			return true
		}
		return false
	})
	q, dir := queueFor(t, f, queueLimits())
	raw := f.plan(t, s, 1, 1000)
	op := planOperation(t, raw, f.authority)
	must(t, q.Enqueue(ctx, f.replicas[0], raw))
	if e := q.Run(ctx, f.replicas[0], f.resolve(t, s), f.keys[0]); !errors.Is(e, ErrBlocked) {
		t.Fatal(e)
	}
	token := storage.Hash([]byte("retry-command"))
	cut := errors.New("lost result")
	q.Fault = func(point string) error {
		if point == "command-retry-durable" {
			return cut
		}
		return nil
	}
	if e := q.RetryCommand(ctx, op, token); !errors.Is(e, cut) {
		t.Fatal(e)
	}
	reopened, e := OpenQueue(dir, f.workers[0].ID, f.authority, queueLimits(), false)
	must(t, e)
	defer reopened.Close()
	state, e := reopened.Status(ctx)
	must(t, e)
	if state.Format != CommandQueueFormat || state.Jobs[op].Phase != "QUEUED" || state.Retries[token].Operation != op {
		t.Fatal("lost durable effect", state)
	}
	revision := state.Revision
	must(t, reopened.RetryCommand(ctx, op, token))
	state, e = reopened.Status(ctx)
	must(t, e)
	if state.Revision != revision {
		t.Fatal("replay rewrote queue")
	}
	if e = reopened.RetryCommand(ctx, storage.Hash([]byte("other job")), token); !errors.Is(e, ErrConflict) {
		t.Fatal("token rebound", e)
	}
	full.Store(false)
	must(t, reopened.Run(ctx, f.replicas[0], f.resolve(t, s), f.keys[0]))
	before, e := reopened.Status(ctx)
	must(t, e)
	must(t, reopened.RetryCommand(ctx, op, token))
	after, e := reopened.Status(ctx)
	must(t, e)
	if after.Revision != before.Revision || after.Jobs[op].Phase != "COMPLETE" || after.Jobs[op].Attempts != before.Jobs[op].Attempts {
		t.Fatal("replayed completed work")
	}
	if e = reopened.RetryCommand(ctx, op, storage.Hash([]byte("new retry"))); !errors.Is(e, ErrDenied) {
		t.Fatal("completed job retried", e)
	}
}
