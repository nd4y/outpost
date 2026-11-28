package sourceagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
)

func TestSourceSettlementSIGKILLResumesReceiptCheckpointAndFinalHead(t *testing.T) {
	f := newFixtureLifetime(t, 5)
	ctx := context.Background()
	must(t, f.a.Next(ctx))
	f.a.Fault = func(p string) error {
		if p == "source-receipt-durable" {
			return errors.New("stop before checkpoint")
		}
		return nil
	}
	if f.a.Run(ctx) == nil {
		t.Fatal("receipt stop not reached")
	}
	f.expire(t)
	f.reopen(t)
	before, e := f.a.Status(ctx)
	must(t, e)
	original := *before.Job.Receipt
	item := f.settlement(t)
	f.provisionSettlement(t, item)
	for _, point := range []string{"source-settlement-receipt-observed", "source-checkpoint-durable", "source-agent-before-head"} {
		must(t, f.a.Close())
		f.a = nil
		raw, e := json.Marshal(struct {
			Bootstrap  Bootstrap
			Point      string
			Settlement *control.SettlementAdmission
		}{f.b, point, &item})
		must(t, e)
		input := filepath.Join(f.base, point+".json")
		must(t, os.WriteFile(input, raw, 0600))
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestSourceAgentSIGKILLChild$")
		cmd.Env = append(os.Environ(), "OUTPOST_SOURCE_KILL_INPUT="+input)
		output, err := cmd.CombinedOutput()
		if bounded.Err() != nil {
			cancel()
			t.Fatalf("settlement child timeout: %s", output)
		}
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("child not killed at %s: %v %s", point, err, output)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("wrong termination at %s: %v %s", point, err, output)
		}
		f.a, e = Open(ctx, f.b, false)
		must(t, e)
		current, e := f.a.Status(ctx)
		must(t, e)
		if current.Sequence != 0 || current.Job == nil || current.Job.Receipt == nil || *current.Job.Receipt != original {
			t.Fatal("interrupted head or receipt changed", point, current)
		}
		t.Log("actual SIGKILL", point)
	}
	must(t, f.a.Settle(ctx, item))
	raw, e := f.a.Checkpoint(ctx)
	must(t, e)
	cp, e := capture.VerifyCheckpoint(raw, f.grant.Trust)
	must(t, e)
	if cp.Sequence != 1 || cp.Receipt != original {
		t.Fatal("crash settlement duplicated generation or receipt")
	}
}

func TestSourceSettlementRechecksExpiryAfterExecutionLeaseWait(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.Next(ctx))
	f.a.Fault = func(p string) error {
		if p == "source-receipt-durable" {
			return errors.New("pause")
		}
		return nil
	}
	if f.a.Run(ctx) == nil {
		t.Fatal("pause not reached")
	}
	f.reopen(t)
	item := f.settlement(t)
	var g ingress.Settlement
	must(t, json.Unmarshal(item.Grant, &g))
	g.ExpiresUnix = time.Now().Unix() + 1
	var e error
	item.Grant, e = ingress.SignSettlement(g, item.Authority, item.Intent, f.ownerSigner, time.Now())
	must(t, e)
	done := make(chan error, 1)
	must(t, f.a.lease.WithLock(ctx, func() error {
		go func() { done <- f.a.Settle(ctx, item) }()
		time.Sleep(time.Until(time.Unix(g.ExpiresUnix, 0)) + 30*time.Millisecond)
		return nil
	}))
	select {
	case e := <-done:
		if !errors.Is(e, ingress.ErrDenied) {
			t.Fatal("expired queued grant was not denied", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lease waiter did not join")
	}
	s, e := f.a.Status(ctx)
	must(t, e)
	if s.Sequence != 0 || s.Job.Phase != "WAITING_COPIES" {
		t.Fatal("expired waiter changed checkpoint", s)
	}
}
