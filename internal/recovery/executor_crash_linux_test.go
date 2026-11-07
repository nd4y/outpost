package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
)

type executorChild struct {
	Profile Profile
	Request Request
	Trust   generation.Trust
	Replica string
}

func TestRecoveryExecutorSIGKILLBoundariesPreserveReceiptAndRetainedStages(t *testing.T) {
	for _, point := range []string{"recovery-intent-durable", "recovery-pin-durable", "recovery-data-durable", "recovery-prepared-durable", "recovery-bundle-durable", "recovery-result-durable", "recovery-before-pin-release"} {
		t.Run(point, func(t *testing.T) {
			f := newExecutorFixture(t)
			ctx := context.Background()
			params := executorChild{f.profile, f.request, f.source.Trust(), f.replicaDirectory}
			raw, e := json.Marshal(params)
			must(t, e)
			config := filepath.Join(filepath.Dir(f.profile.Volume.Root), "child.json")
			must(t, os.WriteFile(config, raw, 0600))
			child := exec.Command(os.Args[0], "-test.run=^TestRecoveryExecutorCrashChild$")
			child.Env = append(os.Environ(), "OUTPOST_EXECUTOR_CHILD="+config, "OUTPOST_EXECUTOR_POINT="+point)
			output, e := child.CombinedOutput()
			if e == nil {
				t.Fatalf("no crash: %s", output)
			}
			exit, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatal(e)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong termination %v: %s", e, output)
			}
			x, e := OpenExecutor(ctx, f.profile, false)
			must(t, e)
			defer x.Close()
			prior, e := x.Outcome(ctx, f.request)
			must(t, e)
			published := point == "recovery-bundle-durable" || point == "recovery-result-durable" || point == "recovery-before-pin-release"
			if (prior != nil) != published {
				t.Fatal("incorrect crash publication classification", point, prior)
			}
			result, e := x.Restore(ctx, f.request, f.source, allowed)
			must(t, e)
			if prior != nil && digest(result) != digest(prior) {
				t.Fatal("replay refreshed original verification")
			}
			body, e := os.ReadFile(filepath.Join(f.profile.Directory, "results", f.request.Operation, "data/private/data"))
			must(t, e)
			if !bytes.Equal(body, f.original) {
				t.Fatal("wrong plaintext after crash")
			}
			s, e := f.source.Status(ctx)
			must(t, e)
			if len(s.Pins) != 0 {
				t.Fatal("completed retry kept source pin", s.Pins)
			}
			quota, e := x.admission.Status(ctx)
			must(t, e)
			if len(quota.Pending) != 0 {
				t.Fatal("completed replay lost reservation cleanup", quota)
			}
			stages, e := os.ReadDir(filepath.Join(f.profile.Directory, "staging"))
			must(t, e)
			want := 0
			if point == "recovery-data-durable" || point == "recovery-prepared-durable" {
				want = 1
			}
			if len(stages) != want {
				t.Fatal("retained stages changed unexpectedly", point, len(stages), want)
			}
		})
	}
}

func TestRecoveryExecutorCrashChild(t *testing.T) {
	config := os.Getenv("OUTPOST_EXECUTOR_CHILD")
	if config == "" {
		return
	}
	raw, e := os.ReadFile(config)
	must(t, e)
	var p executorChild
	must(t, json.Unmarshal(raw, &p))
	ctx := context.Background()
	source, e := generation.Open(p.Replica, p.Trust, false)
	must(t, e)
	defer source.Close()
	x, e := OpenExecutor(ctx, p.Profile, false)
	must(t, e)
	defer x.Close()
	x.Fault = func(point string) error {
		if point == os.Getenv("OUTPOST_EXECUTOR_POINT") {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	_, e = x.Restore(ctx, p.Request, source, allowed)
	must(t, e)
}

func TestRecoveryExecutorPreparedReceiptTamperingCannotBeCompleted(t *testing.T) {
	f := newExecutorFixture(t)
	ctx := context.Background()
	interrupted := errors.New("after bundle rename")
	f.executor.Fault = func(point string) error {
		if point == "recovery-bundle-durable" {
			return interrupted
		}
		return nil
	}
	if _, e := f.executor.Restore(ctx, f.request, f.source, allowed); !errors.Is(e, interrupted) {
		t.Fatal(e)
	}
	name := filepath.Join(f.profile.Directory, "results", f.request.Operation, "receipt.json")
	raw, e := os.ReadFile(name)
	must(t, e)
	raw = append(raw, ' ')
	must(t, os.WriteFile(name, raw, 0600))
	f.executor.Fault = nil
	if result, e := f.executor.Outcome(ctx, f.request); !errors.Is(e, ErrConflict) || result != nil {
		t.Fatal("altered receipt accepted", result, e)
	}
	if _, e = f.executor.Restore(ctx, f.request, f.source, allowed); !errors.Is(e, ErrConflict) {
		t.Fatal("altered receipt overwritten", e)
	}
	saved, e := os.ReadFile(name)
	must(t, e)
	if !bytes.Equal(saved, raw) {
		t.Fatal("tampered evidence erased")
	}
	s, e := f.source.Status(ctx)
	must(t, e)
	if len(s.Pins) != 1 {
		t.Fatal("unconfirmed publication lost pin")
	}
}
