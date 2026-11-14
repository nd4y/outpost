package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/nd4y/outpost/internal/command"
)

func TestWorkerCommandPauseOvertakesPendingRetryWithoutDroppingWorkFence(t *testing.T) {
	f, _, job, makeCommand, _ := blockedUploadCommand(t)
	w := f.nodes[0]
	ctx := context.Background()
	retry := makeCommand("retry", job.Operation, 5)
	cut := errors.New("intent interrupted")
	w.Fault = func(point string) error {
		if point == "worker-command-intent-durable" {
			return cut
		}
		return nil
	}
	if _, e := w.ExecuteCommand(ctx, retry); !errors.Is(e, cut) {
		t.Fatal(e)
	}
	w.Fault = nil
	pause := makeCommand("pause", "", 9)
	ack, e := w.ExecuteCommand(ctx, pause)
	must(t, e)
	if verifyWorkerAck(t, w, pause, ack).State != "COMPLETE" {
		t.Fatal("pending retry blocked control")
	}
	ack, e = w.ExecuteCommand(ctx, retry)
	must(t, e)
	if verifyWorkerAck(t, w, retry, ack).State != "COMPLETE" {
		t.Fatal("later pause invalidated admitted work")
	}
	s, e := w.Status(ctx)
	must(t, e)
	if !s.Controls.Domains[job.Domain] || s.Jobs[job.Operation].Phase != "QUEUED" {
		t.Fatal("retry cleared hold")
	}
	env, _, e := command.VerifyEnvelope(retry, w.owner)
	must(t, e)
	if s.Controls.Sequences[env.Service] != 9 || s.Controls.Sequences[command.SequenceScope(env.Service, "retry")] != 5 {
		t.Fatal("fences conflated")
	}
	if _, e = w.ExecuteCommand(ctx, makeCommand("retry", job.Operation, 3)); !errors.Is(e, ErrDenied) {
		t.Fatal("stale work accepted", e)
	}
}

func TestWorkerCommandLaterPauseDoesNotInvalidateUndeliveredRetry(t *testing.T) {
	f, _, job, makeCommand, _ := blockedUploadCommand(t)
	w := f.nodes[0]
	ctx := context.Background()
	pause := makeCommand("pause", "", 9)
	_, e := w.ExecuteCommand(ctx, pause)
	must(t, e)
	retry := makeCommand("retry", job.Operation, 5)
	ack, e := w.ExecuteCommand(ctx, retry)
	must(t, e)
	if verifyWorkerAck(t, w, retry, ack).State != "COMPLETE" {
		t.Fatal("priority delivery lost older work")
	}
}
