package sourceagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

func TestSourceBootstrapRejectsWorkerObjectObservers(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	binding := f.a.binding
	must(t, f.a.Prepare(ctx, f.intent(t, 1, "")))
	before, err := f.a.Status(ctx)
	must(t, err)
	must(t, f.a.Close())
	f.a = nil

	original, err := json.Marshal(f.b)
	must(t, err)
	if bytes.Contains(original, []byte("observeIngressObjectBodies")) || bytes.Contains(original, []byte("observePeerObjectBodies")) {
		t.Fatal("worker observation field was present in a default source bootstrap")
	}
	path := filepath.Join(f.base, "source-observer-bootstrap.json")
	opened := func(t *testing.T, raw []byte) {
		t.Helper()
		must(t, os.WriteFile(path, raw, 0600))
		config, err := Load(path)
		must(t, err)
		canonical, err := json.Marshal(config)
		must(t, err)
		if !bytes.Equal(canonical, original) {
			t.Fatal("disabled worker option altered source bootstrap JSON")
		}
		a, err := Open(ctx, config, false)
		must(t, err)
		defer func() { must(t, a.Close()) }()
		after, err := a.Status(ctx)
		must(t, err)
		if a.binding != binding || after.Phase != before.Phase || after.Operation != before.Operation {
			t.Fatal("worker option altered the persisted source binding")
		}
	}
	opened(t, original)
	const localPrefix = `"local":{`
	if bytes.Count(original, []byte(localPrefix)) != 1 {
		t.Fatal("expected one local bootstrap object")
	}
	for _, tc := range []struct {
		field  string
		enable func(*Bootstrap)
	}{
		{"observeIngressObjectBodies", func(b *Bootstrap) { b.Local.ObserveIngressObjectBodies = true }},
		{"observePeerObjectBodies", func(b *Bootstrap) { b.Local.ObservePeerObjectBodies = true }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			explicitFalse := bytes.Replace(original, []byte(localPrefix), []byte(localPrefix+`"`+tc.field+`":false,`), 1)
			opened(t, explicitFalse)

			enabled := f.b
			tc.enable(&enabled)
			raw, err := json.Marshal(enabled)
			must(t, err)
			must(t, os.WriteFile(path, raw, 0600))
			if _, err := Load(path); !errors.Is(err, ErrInvalid) {
				t.Fatalf("source bootstrap loader allowed a worker-only option: %v", err)
			}
			a, err := Open(ctx, enabled, false)
			if a != nil {
				must(t, a.Close())
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("source runtime accepted a worker-only option: %v", err)
			}
		})
	}
}
