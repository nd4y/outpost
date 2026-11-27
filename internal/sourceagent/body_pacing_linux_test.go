package sourceagent

import (
	"errors"
	"testing"
)

func TestSourceIngressBodyLimitReopensOriginalBinding(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	binding := f.a.binding
	must(t, f.a.Prepare(ctx, f.intent(t, 1, "")))
	before, err := f.a.Status(ctx)
	must(t, err)
	if before.Phase != "PREPARING" || before.Operation == "" {
		t.Fatal("expected a prepared capture", before)
	}
	must(t, f.a.Close())
	f.a = nil
	for _, rate := range []int64{-1, 65536, 1<<30 + 1} {
		b := f.b
		b.IngressBodyBytesPerSecond = rate
		if a, err := Open(ctx, b, false); !errors.Is(err, ErrInvalid) {
			if a != nil {
				a.Close()
			}
			t.Fatalf("accepted invalid source body rate %d: %v", rate, err)
		}
	}
	for _, rate := range []int64{1 << 20, 1 << 30, 0} {
		b := f.b
		b.IngressBodyBytesPerSecond = rate
		a, err := Open(ctx, b, false)
		must(t, err)
		after, statusErr := a.Status(ctx)
		if statusErr != nil || a.binding != binding || (a.payloadBudget != nil) != (rate > 0) ||
			after.Phase != before.Phase || after.Operation != before.Operation {
			a.Close()
			t.Fatalf("rate %d affected the prepared capture or was ignored: %+v %v", rate, after, statusErr)
		}
		must(t, a.Close())
	}
}
