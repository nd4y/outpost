package upload

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestQueueAbandonmentFencesExpiredUploadAndPreservesOtherPins(t *testing.T) {
	f := fixtureBytes(t, 32<<10)
	target := f.server(t, "s3", 0, nil)
	q, dir := queueFor(t, f, queueLimits())
	other, _ := queueFor(t, f, queueLimits())
	raw := changePlan(t, f, f.plan(t, target, 1, 1000), func(p *Plan) {
		p.StartMillis = time.Now().Add(-time.Second).UnixMilli()
		p.ExpiresUnix = time.Now().Add(10 * time.Second).Unix()
	})
	p, e := Verify(raw, f.authority)
	must(t, e)
	ctx := context.Background()
	source := f.replicas[0]
	must(t, q.Enqueue(ctx, source, raw))
	must(t, other.Enqueue(ctx, source, raw))
	if _, e = q.PreviewAbandonment(ctx, p.Operation); !errors.Is(e, ErrDenied) {
		t.Fatal("live plan could be abandoned", e)
	}
	uploadPin := workerPin(storage.Hash(raw), q.worker)
	restorePin := storage.Hash([]byte("independent restore"))
	must(t, source.Pin(ctx, uploadPin, p.Generation, "generation"))
	must(t, source.Pin(ctx, restorePin, p.Generation, "restore"))
	time.Sleep(time.Until(time.Unix(p.ExpiresUnix, 0)))

	draft, e := q.PreviewAbandonment(ctx, p.Operation)
	must(t, e)
	signed, e := SignAbandonment(draft, f.maintenance)
	must(t, e)
	wrong, e := SignAbandonment(draft, f.planner)
	must(t, e)
	if _, e = q.Abandon(ctx, source, p.Operation, wrong); !errors.Is(e, ErrDenied) {
		t.Fatal("planner key could release maintenance pins", e)
	}
	if _, e = other.Abandon(ctx, source, p.Operation, signed); !errors.Is(e, ErrDenied) {
		t.Fatal("grant replayed on another queue instance", e)
	}
	state, e := other.Status(ctx)
	must(t, e)
	journal, e := other.journal(state.Jobs[p.Operation], false)
	must(t, e)
	must(t, journal.edit(ctx, func(s *State) error {
		s.Phase = "COMPLETE"
		s.Receipt = &Receipt{Target: p.Profile.ID(), Generation: p.Generation, Operation: p.Operation,
			Executor: other.worker, Verification: "full-target-readback", ObservedUnix: time.Now().Unix()}
		return nil
	}))
	must(t, journal.Close())
	if _, e = other.PreviewAbandonment(ctx, p.Operation); !errors.Is(e, ErrConflict) {
		t.Fatal("a worker's original completion was ignored", e)
	}
	otherGrant := draft
	otherGrant.Queue = other.instance
	otherSigned, e := SignAbandonment(otherGrant, f.maintenance)
	must(t, e)
	if _, e = other.Abandon(ctx, source, p.Operation, otherSigned); !errors.Is(e, ErrConflict) {
		t.Fatal("completed worker journal could be abandoned", e)
	}

	cut := errors.New("injected abandonment interruption")
	reopen := func() {
		t.Helper()
		must(t, q.Close())
		var e error
		q, e = OpenQueue(dir, f.workers[0].ID, f.authority, queueLimits(), false)
		must(t, e)
		current := q
		t.Cleanup(func() { current.Close() })
	}
	checkPins := func(wantUploadPins bool) {
		t.Helper()
		state, e := source.Status(ctx)
		must(t, e)
		want := generation.Pin{Generation: p.Generation, Kind: "generation"}
		if state.Pins[other.pin(p.Operation)] != want ||
			state.Pins[restorePin] != (generation.Pin{Generation: p.Generation, Kind: "restore"}) {
			t.Fatal("unrelated protections changed", state.Pins)
		}
		for _, id := range []string{q.pin(p.Operation), uploadPin} {
			pin, exists := state.Pins[id]
			if exists != wantUploadPins || exists && pin != want {
				t.Fatal("unexpected upload pin state", state.Pins)
			}
		}
	}
	for _, point := range []string{"abandonment-intent", "abandonment-pins"} {
		q.Fault = func(at string) error {
			if at == point {
				return cut
			}
			return nil
		}
		if _, e = q.Abandon(ctx, source, p.Operation, signed); !errors.Is(e, cut) {
			t.Fatal("interruption was not reached", point, e)
		}
		reopen()
		s, e := q.Status(ctx)
		must(t, e)
		job := s.Jobs[p.Operation]
		if job.Phase != "EXPIRED" || job.Receipt != nil || job.Abandonment == nil || job.Abandonment.ReleasedUnix != 0 {
			t.Fatal("unfinished abandonment claimed completion", job.Phase)
		}
		checkPins(point == "abandonment-intent")
	}

	receipt, e := q.Abandon(ctx, source, p.Operation, signed)
	must(t, e)
	if receipt.GrantDigest != storage.Hash(signed) || receipt.ReleasedUnix < p.ExpiresUnix {
		t.Fatal("invalid abandonment receipt", receipt)
	}
	reopen()
	again, e := q.Abandon(ctx, source, p.Operation, signed)
	must(t, e)
	if again != receipt {
		t.Fatal("replay changed the original receipt", again)
	}
	checkPins(false)
	must(t, source.VerifyComplete(ctx, p.Generation))
	if e = q.Retry(ctx, p.Operation); !errors.Is(e, ErrDenied) {
		t.Fatal("abandonment allowed retry", e)
	}
	if e = q.Run(ctx, source, f.resolve(t, target), f.keys[0]); !errors.Is(e, ErrBlocked) {
		t.Fatal("abandonment claimed a completed upload", e)
	}
	if target.Snapshot().Requests != 0 {
		t.Fatal("abandonment accessed the external target")
	}
}
