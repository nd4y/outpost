package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func actionRecord(t *testing.T, w *Worker, raw []byte) CommandRecord {
	t.Helper()
	env, _, e := command.VerifyEnvelope(raw, w.owner)
	must(t, e)
	s, e := w.Status(context.Background())
	must(t, e)
	return s.Controls.Operations[env.Request.Operation]
}
func waitAction(t *testing.T, w *Worker, raw []byte) CommandRecord {
	t.Helper()
	var result CommandRecord
	wait(t, func() bool { result = actionRecord(t, w, raw); return len(result.Ack) > 0 })
	return result
}
func TestWorkerCommandScrubReadsFreshBytesAndKeepsHistoricalReceipt(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	raw := makeCommand("scrub", f.generation, 1)
	ack, e := w.ExecuteCommand(ctx, raw)
	must(t, e)
	if len(ack) > 0 {
		t.Fatal("admission claimed scrub completion")
	}
	stop := start(t, w)
	record := waitAction(t, w, raw)
	stop()
	receipt := verifyWorkerAck(t, w, raw, record.Ack)
	var scrub ScrubReceipt
	must(t, json.Unmarshal(record.Result, &scrub))
	if receipt.State != "COMPLETE" || receipt.ResultDigest != storage.Hash(record.Result) || scrub.Verification != "sha256-ciphertext" || scrub.Generation != f.generation || scrub.VerifiedObjects < 1 || scrub.VerifiedAt < record.StartedUnix {
		t.Fatal("missing actual scrub receipt", receipt, scrub)
	}
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	replica, e := generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	catalog, e := replica.Catalog(ctx, f.generation)
	must(t, e)
	replica.Close()
	c, e := generation.VerifyCatalog(catalog, f.domain.Trust)
	must(t, e)
	object := c.Kits[0].Objects[0]
	path := filepath.Join(dir, "objects", object.ID)
	data, e := os.ReadFile(path)
	must(t, e)
	data[len(data)/2] ^= 1
	must(t, os.WriteFile(path, data, 0600))
	replay, e := w.ExecuteCommand(ctx, raw)
	must(t, e)
	if !bytes.Equal(replay, record.Ack) {
		t.Fatal("historical receipt replaced by new observation")
	}
	fresh := makeCommand("scrub", f.generation, 2)
	_, e = w.ExecuteCommand(ctx, fresh)
	must(t, e)
	stop = start(t, w)
	damaged := waitAction(t, w, fresh)
	stop()
	if a := verifyWorkerAck(t, w, fresh, damaged.Ack); a.State != "FAILED" || a.ErrorCode != "DATA_INCOMPLETE" || len(damaged.Result) != 0 {
		t.Fatal("corrupt bytes certified", a)
	}
	preserved, e := os.ReadFile(path)
	must(t, e)
	if !bytes.Equal(data, preserved) {
		t.Fatal("scrub destroyed evidence")
	}
}

func TestWorkerCommandPauseJoinsScrubThenResumeKeepsOriginalReadAge(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	w.Fault = func(point string) error {
		if point == "worker-command-scrub-batch-durable" {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}
	raw := makeCommand("scrub", f.generation, 1)
	_, e := w.ExecuteCommand(ctx, raw)
	must(t, e)
	stop := start(t, w)
	defer stop()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scrub did not reach durable read")
	}
	type answer struct {
		ack []byte
		err error
	}
	done := make(chan answer, 1)
	pause := makeCommand("pause", "", 2)
	go func() { ack, e := w.ExecuteCommand(ctx, pause); done <- answer{ack, e} }()
	wait(t, func() bool { s, e := w.Status(ctx); return e == nil && s.Controls.Domains[f.domain.Trust.Domain] })
	select {
	case <-done:
		t.Fatal("pause acknowledged before scrub joined")
	case <-time.After(150 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case a := <-done:
		must(t, a.err)
		if verifyWorkerAck(t, w, pause, a.ack).State != "COMPLETE" {
			t.Fatal("pause failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pause did not join scrub")
	}
	pending := actionRecord(t, w, raw)
	if len(pending.Ack) > 0 || pending.Work.Phase != "QUEUED" {
		t.Fatal("cancelled scrub falsely terminal", pending.Work)
	}
	resume := makeCommand("resume", "", 3)
	_, e = w.ExecuteCommand(ctx, resume)
	must(t, e)
	record := waitAction(t, w, raw)
	if verifyWorkerAck(t, w, raw, record.Ack).State != "COMPLETE" || record.Work.Attempts < 2 {
		t.Fatal("paused work not resumed")
	}
	var result ScrubReceipt
	must(t, json.Unmarshal(record.Result, &result))
	if result.VerifiedAt < record.StartedUnix {
		t.Fatal("invalid read age")
	}
}

func TestWorkerCommandScrubSIGKILLResumesBatchAndOriginalResult(t *testing.T) {
	for _, point := range []string{"worker-command-scrub-batch-durable", "worker-command-work-result-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			f.endpoint(t, nil)
			_, makeCommand := workerCommandFixture(t, f, 0, nil)
			w := f.nodes[0]
			ctx := context.Background()
			envelope := makeCommand("scrub", f.generation, 1)
			in := commandChild{planningChild: planningChild{Directory: w.dir, Node: w.node, Point: point, Owner: w.owner, Certificate: w.cert.Certificate[0], CA: f.ca.cert.Raw, Key: w.cert.PrivateKey.(ed25519.PrivateKey)}, Envelope: envelope, Run: true}
			raw, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(f.base, "scrub-child.json")
			must(t, os.WriteFile(file, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestWorkerCommandSIGKILLChild$")
			child.Env = append(os.Environ(), "OUTPOST_WORKER_COMMAND_CHILD="+file)
			output, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("not killed %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong exit %v %s", e, output)
			}
			before := actionRecord(t, w, envelope)
			if (len(before.Ack) > 0) != (point == "worker-command-work-result-durable") {
				t.Fatal("wrong durable boundary")
			}
			other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
			must(t, e)
			defer other.Close()
			stop := start(t, other)
			after := waitAction(t, other, envelope)
			stop()
			ack, e := other.ExecuteCommand(ctx, envelope)
			must(t, e)
			if verifyWorkerAck(t, other, envelope, ack).State != "COMPLETE" || !bytes.Equal(ack, after.Ack) || len(before.Ack) > 0 && !bytes.Equal(before.Ack, ack) {
				t.Fatal("result not preserved")
			}
		})
	}
}
