package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/isolation"
)

func TestCLIIsolationObservationAndAdmissionPrecedePrivateState(t *testing.T) {
	ctx := context.Background()
	value, e := run(ctx, []string{"runtime-observe"})
	if e != nil {
		t.Fatal(e)
	}
	observed, ok := value.(isolation.Observation)
	if !ok || observed.RuntimeAcceptance || observed.Format != isolation.Format {
		t.Fatal("untyped isolation observation", value)
	}
	_, e = run(ctx, []string{"runtime-check"})
	if (e == nil) != (observed.Check() == nil) {
		t.Fatal("check disagrees", e)
	}
	if code, status := failure(isolation.ErrRequired); code != "CAPABILITY_UNAVAILABLE" || status != 5 {
		t.Fatal(code, status)
	}
	absent := filepath.Join(t.TempDir(), "private-state-must-not-open")
	_, e = run(ctx, []string{"worker-init", "--require-isolation", "--bootstrap", absent})
	if observed.Check() != nil && !errors.Is(e, isolation.ErrRequired) {
		t.Fatal("private state reached before isolation check", e)
	}
	if _, e = os.Stat(absent); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("admission created state", e)
	}
	if _, e = run(ctx, []string{"runtime-observe", "unexpected"}); !errors.Is(e, errUsage) {
		t.Fatal("extra argument accepted", e)
	}
}
