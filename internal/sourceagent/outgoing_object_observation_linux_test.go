package sourceagent

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/storage"
)

func TestSourceOutgoingObjectObservationIsTransientAndScoped(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	must(t, f.a.Prepare(ctx, f.intent(t, 1, "")))
	before, err := f.a.Status(ctx)
	must(t, err)
	if before.OutgoingIngressObjectBodies != nil {
		t.Fatal("an unobserved source route reported a count")
	}
	run, err := f.a.RunWithObjectBodyObservations(ctx, nil)
	must(t, err)
	bodies := run.OutgoingIngressObjectBodies
	if run.Phase != "COMPLETE" || bodies == nil || bodies.Retention != sourceObjectBodyRetention || len(bodies.Samples) != 1 {
		t.Fatal("normal capture did not return scoped direct evidence", bodies)
	}
	current := bodies.Samples[0]
	if current.Route != sourceObjectRoute(f.grant) || current.TransportReadPutBodyBytes <= 0 {
		t.Fatal("invalid direct-route evidence", current)
	}
	replay, err := f.a.RunWithObjectBodyObservations(ctx, nil)
	must(t, err)
	if replay.OutgoingIngressObjectBodies != nil {
		t.Fatal("a new invocation reused an earlier run's observation")
	}
	f.reopen(t)
	reopened, err := f.a.Status(ctx)
	must(t, err)
	if reopened.Generation != run.Generation || reopened.OutgoingIngressObjectBodies != nil {
		t.Fatal("reopen lost the backup or exposed a volatile sample")
	}

	s, err := f.a.load()
	must(t, err)
	intent, err := f.a.stateIntent(s)
	must(t, err)
	samples := new(sourceObjectSamples)
	observed := context.WithValue(ctx, sourceObjectScopeKey{}, samples)
	foreign := f.a.outgoingObjectObserver(observed, f.authority, storage.Hash([]byte("another operation")))
	if foreign == nil {
		t.Fatal("fixture could not bind a source route")
	}
	foreign(current.ObjectWriteObservation)
	if got := f.a.outgoingObjectStatus(ctx, s, intent, samples); got != nil {
		t.Fatal("a direct observation escaped its operation", got)
	}
	f.a.outgoingObjectObserver(observed, f.authority, intent.Operation)(current.ObjectWriteObservation)
	if got := f.a.outgoingObjectStatus(ctx, s, intent, samples); got == nil || got.Samples[0] != current {
		t.Fatal("exact live route failed to preserve the original sample", got)
	}
	f.a.b.ActiveFailover = true
	s.Route = []string{storage.Hash([]byte("a different receiver"))}
	if got := f.a.outgoingObjectStatus(ctx, s, intent, samples); got != nil {
		t.Fatal("a source observation survived route removal", got)
	}
}

func TestSourceOutgoingObjectObservationDoesNotAllocateTelemetryStorage(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	state, err := f.a.budget.Status(ctx)
	must(t, err)
	remaining := state.Limits.Telemetry - state.Used["telemetry"]
	const block = 4096
	if remaining < diskbudget.WriteCharge(1) || remaining > 8<<20 {
		t.Fatal("unexpected fixture telemetry allowance", remaining)
	}
	fill := (remaining-diskbudget.WriteCharge(1))/block*block + block
	release, err := f.a.budget.Reserve(ctx, "telemetry/fixture-reservation", int(fill))
	must(t, err)
	defer func() { must(t, release(false)) }()
	if err = f.a.budget.CheckWrite(ctx, "telemetry/fixture-empty", 1); !errors.Is(err, diskbudget.ErrCapacity) {
		t.Fatal("fixture did not exhaust the real telemetry allowance", err)
	}
	must(t, f.a.Prepare(ctx, f.intent(t, 1, "")))
	out, err := f.a.RunWithObjectBodyObservations(ctx, nil)
	must(t, err)
	if out.Phase != "COMPLETE" || out.OutgoingIngressObjectBodies == nil || len(out.OutgoingIngressObjectBodies.Samples) != 1 {
		t.Fatal("disk telemetry quota affected the capture or its in-memory sample", out)
	}
	if _, err = f.a.root.Lstat("telemetry/source-object-bodies"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("volatile observation created a telemetry storage path", err)
	}
	after, err := f.a.budget.Status(ctx)
	must(t, err)
	if after.Used["telemetry"] != state.Used["telemetry"] || len(after.Pending) != 1 {
		t.Fatal("volatile observation changed durable telemetry accounting", after.Used, after.Pending)
	}
}
