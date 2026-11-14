package worker

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestChangedOperationIsRejectedWithoutStoppingIndependentJob(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, _ := f.jobs()
	cfg := f.config(t, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push})
	start(t, f.nodes[1])
	start(t, f.nodes[0])
	wait(t, func() bool { return complete(f.nodes[0], push.Operation) })
	original, _ := f.nodes[0].Status(context.Background())
	conflict := push
	conflict.Generation = storage.Hash([]byte("different generation"))
	fresh := push
	fresh.PeerRevision = 2
	fresh.Operation = storage.Hash([]byte("independent operation"))
	cfg.Revision = 2
	cfg.Jobs = []control.Job{conflict, fresh}
	raw, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, f.nodes[0].Accept(context.Background(), raw))
	receiving := f.cfg
	receiving.Node = f.nodes[1].node
	receiving.Revision = 2
	receiving.Domains = []control.Domain{f.domain}
	receiving.Jobs = []control.Job{fresh}
	raw, e = control.Sign(receiving, f.owner)
	must(t, e)
	must(t, f.nodes[1].Accept(context.Background(), raw))
	wait(t, func() bool { return complete(f.nodes[0], fresh.Operation) })
	s, e := f.nodes[0].Status(context.Background())
	must(t, e)
	if s.Rejected[push.Operation] != "OPERATION_CONFLICT" || s.Jobs[push.Operation].Binding != original.Jobs[push.Operation].Binding || s.Jobs[push.Operation].Phase != "COMPLETE" {
		t.Fatal("conflict overwrote an immutable receipt", s)
	}
}
func TestUnchangedJobRestartsAfterPolicyCancellationWithoutBackoff(t *testing.T) {
	f := newFixture(t)
	begun := make(chan struct{}, 1)
	restarted := make(chan int64, 1)
	var writes atomic.Int64
	push, _ := f.jobs()
	f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut && writes.Add(1) == 1 {
				_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, generation.MaxCatalog))
				begun <- struct{}{}
				select {
				case <-r.Context().Done():
				case <-time.After(6 * time.Second):
				}
				return
			}
			if r.Method == http.MethodPut {
				state, e := f.nodes[0].Status(r.Context())
				if e == nil {
					select {
					case restarted <- state.Jobs[push.Operation].NextMillis:
					default:
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	cfg := f.config(t, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push})
	start(t, f.nodes[1])
	start(t, f.nodes[0])
	select {
	case <-begun:
	case <-time.After(5 * time.Second):
		t.Fatal("attempt not started")
	}
	cfg.Revision++
	raw, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, f.nodes[0].Accept(context.Background(), raw))
	select {
	case next := <-restarted:
		if next != 0 {
			t.Fatal("policy cancellation imposed network failure backoff", next)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unchanged job did not restart")
	}
	wait(t, func() bool { return complete(f.nodes[0], push.Operation) })
}
func TestRunDeadlineIsAnOrderlyStop(t *testing.T) {
	f := newFixture(t)
	f.domain.Placement.Edges = nil
	f.config(t, 0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	must(t, f.nodes[0].Run(ctx))
}

func TestReceiverPolicyLagRetriesWithoutExpandingAuthority(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, _ := f.jobs()
	push.PeerRevision = 2
	f.config(t, 0, []control.Job{push})
	receiver := f.config(t, 1, nil)
	start(t, f.nodes[1])
	start(t, f.nodes[0])
	wait(t, func() bool {
		s, e := f.nodes[0].Status(context.Background())
		return e == nil && s.Jobs[push.Operation].Phase == "RETRY_WAIT"
	})
	receiver.Revision = 2
	receiver.Jobs = []control.Job{push}
	raw, e := control.Sign(receiver, f.owner)
	must(t, e)
	must(t, f.nodes[1].Accept(context.Background(), raw))
	wait(t, func() bool { return complete(f.nodes[0], push.Operation) })
}
