package upload

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func TestLongQueueAttemptKeepsPlanExpiryAndParentCancellation(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		name := "plan-expiry"
		if cancelParent {
			name = "parent-cancellation"
		}
		t.Run(name, func(t *testing.T) {
			f := fixtureBytes(t, 4096)
			limits := queueLimits()
			limits.AttemptMillis = MaxAttemptMillis
			q, _ := queueFor(t, f, limits)
			target := f.server(t, "webdav", 0, nil)
			expires := time.Now().Add(5 * time.Second).Unix()
			raw := changePlan(t, f, f.plan(t, target, 1, 1000), func(p *Plan) { p.ExpiresUnix = expires })
			must(t, q.Enqueue(t.Context(), f.replicas[0], raw))
			op := planOperation(t, raw, f.authority)
			parent, stop := context.WithCancel(t.Context())
			defer stop()
			deadline := make(chan time.Time, 1)
			joined := make(chan struct{})
			resolve := func(ctx context.Context, _ storage.Profile) (*storage.Backend, error) {
				end, ok := ctx.Deadline()
				if !ok {
					end = time.Time{}
				}
				deadline <- end
				<-ctx.Done()
				close(joined)
				return nil, ctx.Err()
			}
			done := make(chan error, 1)
			finished := make(chan struct{})
			go func() { defer close(finished); done <- q.Run(parent, f.replicas[0], resolve, f.keys[0]) }()
			t.Cleanup(func() {
				stop()
				select {
				case <-finished:
				case <-time.After(3 * time.Second):
					t.Error("queue goroutine did not join before fixture cleanup")
				}
			})
			select {
			case end := <-deadline:
				if !end.Equal(time.Unix(expires, 0)) {
					t.Fatal("resolver escaped the original signed plan expiry", end)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("long attempt did not reach its resolver")
			}
			if cancelParent {
				stop()
			}
			select {
			case <-joined:
			case <-time.After(6 * time.Second):
				t.Fatal("resolver survived parent cancellation or signed expiry")
			}
			select {
			case err := <-done:
				if err == nil || cancelParent && !errors.Is(err, context.Canceled) {
					t.Fatal("interrupted long attempt reported success", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("queue did not join its resolver")
			}
			state, err := q.Status(t.Context())
			must(t, err)
			if state.Jobs[op].Phase == "COMPLETE" || state.Jobs[op].Receipt != nil {
				t.Fatal("expiry/cancellation became successful generation evidence")
			}
			pins, err := f.replicas[0].Status(t.Context())
			must(t, err)
			if _, ok := pins.Pins[q.pin(op)]; !ok {
				t.Fatal("incomplete long operation released its source pin")
			}
			if !cancelParent {
				grant, err := q.PreviewAbandonment(t.Context(), op)
				must(t, err)
				signed, err := SignAbandonment(grant, f.maintenance)
				must(t, err)
				receipt, err := q.Abandon(t.Context(), f.replicas[0], op, signed)
				must(t, err)
				if receipt.Queue != state.Instance || receipt.ReleasedUnix == 0 {
					t.Fatal("long queue abandonment changed its instance or missed release")
				}
			}
		})
	}
}
