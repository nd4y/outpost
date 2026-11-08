package sourceagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

func TestSourceUnstartedRetirementSIGKILLAndNextGeneration(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var requests atomic.Int64
	f.registryMu.Lock()
	f.intercept = func(http.ResponseWriter, *http.Request) bool { requests.Add(1); return false }
	f.registryMu.Unlock()
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	first, err := f.a.Status(ctx)
	must(t, err)
	oldCheckpoint, err := f.a.Checkpoint(ctx)
	must(t, err)
	content, err := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, err)
	before := requests.Load()
	stop := errors.New("stop after the durable source intent")
	f.a.Fault = func(p string) error {
		if p == "source-agent-intent-durable" {
			return stop
		}
		return nil
	}
	expiry := time.Now().Add(12 * time.Second).Unix()
	intent := f.intentUntil(t, first.Sequence+1, first.Generation, expiry)
	if err = f.a.Prepare(ctx, intent); !errors.Is(err, stop) {
		t.Fatal("intent fence not reached", err)
	}
	if _, err = f.a.UnstartedRetirementPreview(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("current intent accepted for expiry", err)
	}
	f.waitForIntentExpiry(t, intent, expiry)
	f.reopen(t)
	preview, err := f.a.UnstartedRetirementPreview(ctx)
	must(t, err)
	if preview.Operation == first.Operation || preview.Checkpoint != storage.Hash(oldCheckpoint) {
		t.Fatal("incorrect retirement binding", preview)
	}
	wrong, err := SignUnstartedRetirement(preview, f.writer, time.Now())
	must(t, err)
	if err = f.a.RetireUnstarted(ctx, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("writer authorized owner retirement", err)
	}
	foreign := preview
	foreign.Operation = storage.Hash([]byte("different retired intent"))
	wrong, err = SignUnstartedRetirement(foreign, f.ownerSigner, time.Now())
	must(t, err)
	if err = f.a.RetireUnstarted(ctx, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("owner authorization accepted for a different operation", err)
	}
	grant, err := SignUnstartedRetirement(preview, f.ownerSigner, time.Now())
	must(t, err)
	cli := os.Getenv("OUTPOST_SETTLEMENT_CURRENT_CLI")
	if cli != "" {
		bootstrap, err := json.Marshal(f.b)
		must(t, err)
		owner, err := json.Marshal(map[string]any{"privateKey": f.ownerSigner})
		must(t, err)
		boot, ownerFile := filepath.Join(f.base, "bootstrap.json"), filepath.Join(f.base, "owner.json")
		unsigned, signed := filepath.Join(f.base, "retirement.json"), filepath.Join(f.base, "signed-retirement.json")
		must(t, os.WriteFile(boot, bootstrap, 0600))
		must(t, os.WriteFile(ownerFile, owner, 0600))
		runUnstartedCLI(t, cli, "source-unstarted-preview", "--bootstrap", boot, "--output", unsigned)
		runUnstartedCLI(t, cli, "source-unstarted-sign", "--key", ownerFile, "--input", unsigned, "--output", signed)
		grant, err = os.ReadFile(signed)
		must(t, err)
	}
	must(t, f.a.Close())
	f.a = nil
	payload, err := json.Marshal(struct {
		Bootstrap  Bootstrap
		Point      string
		Retirement []byte
	}{f.b, "source-unstarted-retirement-durable", grant})
	must(t, err)
	input := filepath.Join(f.base, "retire-crash.json")
	must(t, os.WriteFile(input, payload, 0600))
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestSourceAgentSIGKILLChild$")
	child.Env = append(os.Environ(), "OUTPOST_SOURCE_KILL_INPUT="+input)
	output, err := child.CombinedOutput()
	cancel()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("retirement child did not reach SIGKILL: %v %s", err, output)
	}
	wait, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !wait.Signaled() || wait.Signal() != syscall.SIGKILL {
		t.Fatalf("retirement child exited without the required signal: %v %s", err, output)
	}
	f.a, err = Open(ctx, f.b, false)
	must(t, err)
	unchanged, err := f.a.Status(ctx)
	must(t, err)
	if unchanged.Phase != "PREPARING" || unchanged.Sequence != first.Sequence || unchanged.Generation != first.Generation {
		t.Fatal("audit admission advanced the head before retirement", unchanged)
	}
	if cli != "" {
		runUnstartedCLI(t, cli, "source-unstarted-retire", "--bootstrap", filepath.Join(f.base, "bootstrap.json"),
			"--input", filepath.Join(f.base, "signed-retirement.json"))
		f.reopen(t)
	} else {
		hold, release := make(chan struct{}), make(chan struct{})
		attempt := make(chan error, 1)
		f.a.Fault = func(point string) error {
			if point == "source-unstarted-before-state" {
				close(hold)
				<-release
			}
			return nil
		}
		go func() { attempt <- f.a.RetireUnstarted(ctx, grant) }()
		select {
		case <-hold:
		case err = <-attempt:
			t.Fatal("retirement did not hold the execution lease", err)
		case <-time.After(time.Second):
			close(release)
			t.Fatal("retirement checkpoint was not reached")
		}
		run := make(chan error, 1)
		go func() { run <- f.a.Run(ctx) }()
		select {
		case err = <-run:
			close(release)
			<-attempt
			t.Fatal("normal run crossed the retirement lease", err)
		case <-time.After(25 * time.Millisecond):
		}
		close(release)
		must(t, <-attempt)
		if err = <-run; !errors.Is(err, ErrInvalid) {
			t.Fatal("concurrent run did not observe retired state", err)
		}
		f.a.Fault = nil
	}
	must(t, f.a.RetireUnstarted(ctx, grant))
	if err = f.a.Run(ctx); !errors.Is(err, ErrInvalid) || requests.Load() != before {
		t.Fatal("retired intent could reach the receiver", err, requests.Load(), before)
	}
	current, err := f.a.Status(ctx)
	must(t, err)
	checkpoint, err := f.a.Checkpoint(ctx)
	must(t, err)
	if current.Phase != "ABANDONED" || current.Operation != preview.Operation || current.Generation != first.Generation ||
		current.Sequence != first.Sequence || !bytes.Equal(checkpoint, oldCheckpoint) {
		t.Fatal("retirement altered completed history", current)
	}
	fresh := renewedAuthority(t, f, 2)
	_, err = f.a.Renew(ctx, fresh, nil)
	must(t, err)
	f.reopen(t)
	options := ingress.RegistryOptions{Directory: filepath.Join(f.base, "registry"), Authority: f.authority,
		Owner: f.b.Local.Owner, Replica: f.replica, Certificate: f.destination, Roots: f.roots,
		Limits: sourceFixtureLimits}
	f.registryMu.Lock()
	err = f.registry.Close()
	if err == nil {
		_, err = ingress.RenewRegistry(ctx, options, fresh, nil, nil)
	}
	if err == nil {
		options.Authority = fresh
		f.registry, err = ingress.OpenRegistry(ctx, options)
	}
	f.registryMu.Unlock()
	must(t, err)
	changed := bytes.Clone(content)
	changed[len(changed)/2] ^= 1
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), changed, 0640))
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	second, err := f.a.Status(ctx)
	must(t, err)
	if second.Phase != "COMPLETE" || second.Sequence != 2 || second.Operation == preview.Operation || second.Generation == first.Generation {
		t.Fatal("fresh operation did not retain the signed lineage", second)
	}
	must(t, os.Rename(f.tree, f.tree+"-unavailable"))
	for i, version := range []struct {
		generation string
		data       []byte
	}{{first.Generation, content}, {second.Generation, changed}} {
		dest := filepath.Join(f.base, "retired-restore-"+version.generation)
		_, err = generation.RecoverMaterialized(ctx, f.replicaPath, version.generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, dest)
		must(t, err)
		actual, err := os.ReadFile(filepath.Join(dest, "private.bin"))
		must(t, err)
		if !bytes.Equal(actual, version.data) {
			t.Fatal("retired intent damaged an independent restore", i)
		}
	}
	t.Log("actual SIGKILL, zero retirement requests, same receiver renewal and two independent restores")
}

func runUnstartedCLI(t *testing.T, binary string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v %s", args[0], err, output)
	}
}

func TestSourceUnstartedRetirementRefusesActiveWithoutReceiverReceipt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	expiry := time.Now().Add(12 * time.Second).Unix()
	intent := f.intentUntil(t, 1, "", expiry)
	must(t, f.a.Prepare(ctx, intent))
	f.waitForIntentExpiry(t, intent, expiry)
	if _, err := f.a.UnstartedRetirementPreview(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("ACTIVE intent can be classified as unstarted", err)
	}
	s, err := f.a.load()
	must(t, err)
	i, err := f.a.stateIntent(s)
	must(t, err)
	now := time.Now()
	grant, err := SignUnstartedRetirement(f.a.unstartedRetirement(s, i, now.Unix(), now.Add(time.Minute).Unix()), f.ownerSigner, now)
	must(t, err)
	if err = f.a.RetireUnstarted(ctx, grant); !errors.Is(err, ErrInvalid) {
		t.Fatal("no receiver receipt bypassed ACTIVE fence", err)
	}
}

func (f *fixture) waitForIntentExpiry(t *testing.T, raw []byte, expiry int64) {
	t.Helper()
	time.Sleep(time.Until(time.Unix(expiry, 0)))
	now := time.Now()
	_, err := ingress.VerifyAuthority(f.authority, f.b.Local.Owner, now)
	must(t, err)
	if _, _, err = ingress.VerifyIntent(raw, f.authority, f.b.Local.Owner, now); !errors.Is(err, ingress.ErrDenied) {
		t.Fatal("signed intent did not expire", err)
	}
}
