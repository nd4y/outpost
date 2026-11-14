package worker

import (
	"context"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
)

func TestWorkerCommandExpiredQueuedActionReconcilesWithoutActivePolicy(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.cfg.ExpiresUnix = time.Now().Unix() + 3
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	raw := makeCommand("scrub", f.generation, 1)
	_, e := w.ExecuteCommand(context.Background(), raw)
	must(t, e)
	env, _, e := command.VerifyEnvelope(raw, w.owner)
	must(t, e)
	time.Sleep(time.Until(time.Unix(env.Request.ExpiresUnix, 0).Add(30 * time.Millisecond)))
	stop := start(t, w)
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		op := actionRecord(t, w, raw)
		if len(op.Ack) > 0 {
			ack := verifyWorkerAck(t, w, raw, op.Ack)
			if ack.State != "FAILED" || ack.ErrorCode != "COMMAND_EXPIRED" || op.Work.Attempts != 0 || len(op.Result) > 0 {
				t.Fatal("expired action executed or falsely completed", ack, op.Work)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expired queued action remains pending without an active policy")
}

func TestWorkerCommandExpiredActionPollingWithoutExecutionOwner(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.cfg.ExpiresUnix = time.Now().Unix() + 2
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	raw := makeCommand("scrub", f.generation, 1)
	_, e := w.ExecuteCommand(context.Background(), raw)
	must(t, e)
	env, _, e := command.VerifyEnvelope(raw, w.owner)
	must(t, e)
	time.Sleep(time.Until(time.Unix(env.Request.ExpiresUnix, 0).Add(30 * time.Millisecond)))
	ack, e := w.ExecuteCommand(context.Background(), raw)
	must(t, e)
	if result := verifyWorkerAck(t, w, raw, ack); result.State != "FAILED" || result.ErrorCode != "COMMAND_EXPIRED" {
		t.Fatal("polling left expired action pending", result)
	}
}
