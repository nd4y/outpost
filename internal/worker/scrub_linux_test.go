package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func scheduledState(t *testing.T, w *Worker, f *fixture) ScrubState {
	t.Helper()
	s, e := w.Status(context.Background())
	must(t, e)
	return s.Scrubs[scrubKey(f.domain.Trust.Domain, f.domain.Trust.Repository, f.domain.Trust.Epoch, f.generation)]
}

func TestScheduledScrubSharesSlotsAndPreservesTransferPriority(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.Parallel = 1
	f.domain.ScrubIntervalSeconds = 60
	entered, stopped := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var enterOnce, stopOnce sync.Once
	f.endpoint(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, generation.MaxCatalog+1))
			enterOnce.Do(func() { close(entered) })
			select {
			case <-r.Context().Done():
			case <-release:
			}
			stopOnce.Do(func() { close(stopped) })
		})
	})
	push, _ := f.jobs()
	c := f.config(t, 0, []control.Job{push})
	w := f.nodes[0]
	stop := start(t, w)
	defer stop()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("transfer did not occupy sole slot")
	}
	time.Sleep(150 * time.Millisecond)
	s, e := w.Status(context.Background())
	must(t, e)
	if len(s.Scrubs) != 0 || s.Jobs[push.Operation].Phase != "RUNNING" {
		t.Fatal("scrub bypassed shared slot/backup priority", s)
	}
	c.Revision++
	c.Jobs = nil
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, w.Accept(context.Background(), raw))
	wait(t, func() bool { return scheduledState(t, w, f).Phase == "COMPLETE" })
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("old HTTP request was not cancelled")
	}
	s, e = w.Status(context.Background())
	must(t, e)
	if s.Jobs[push.Operation].Phase != "WITHDRAWN" {
		t.Fatal("old transfer not withdrawn")
	}
}

func TestScheduledScrubWithdrawalJoinsAndRetainsPendingEvidence(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.domain.ScrubIntervalSeconds = 60
	c := f.config(t, 0, nil)
	w := f.nodes[0]
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	w.Fault = func(point string) error {
		if point == "worker-scrub-batch-durable" {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}
	stop := start(t, w)
	defer stop()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled batch missing")
	}
	before := scheduledState(t, w, f)
	c.Revision++
	c.Domains[0].ScrubIntervalSeconds = 0
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, w.Accept(context.Background(), raw))
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active == nil })
	if scheduledState(t, w, f).Phase != "RUNNING" {
		t.Fatal("replacement view started before old batch joined")
	}
	releaseOnce.Do(func() { close(release) })
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil && w.active.cfg.Revision == 2 })
	queued := scheduledState(t, w, f)
	if queued.Window != before.Window || queued.Phase != "QUEUED" {
		t.Fatal("withdrawal lost pending evidence", queued)
	}
	time.Sleep(1100 * time.Millisecond)
	after := scheduledState(t, w, f)
	a, _ := json.Marshal(queued)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Fatal("disabled schedule executed again")
	}
}

func TestScheduledScrubAutomaticallyDetectsAndRepairsBothOutboundRoutes(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, pull := f.rules()
	push.Repair = true
	pull.Repair = true
	f.replicationConfig(t, 0, 1, push)
	f.replicationConfig(t, 1, 1, push, pull)
	f.replicationConfig(t, 2, 1, pull)
	stopA := start(t, f.nodes[0])
	stopB := start(t, f.nodes[1])
	stopC := start(t, f.nodes[2])
	wait(t, func() bool {
		return complete(f.nodes[0], push.Job(f.domain.Trust, f.generation).Operation) && complete(f.nodes[2], pull.Job(f.domain.Trust, f.generation).Operation)
	})
	stopA()
	stopC()
	stopB()
	for _, index := range []int{1, 2} {
		dir := filepath.Join(DomainDirectory(f.nodes[index].dir, f.domain.Trust), "replica")
		r, e := generation.Open(dir, f.domain.Trust, false)
		must(t, e)
		raw, e := r.Catalog(context.Background(), f.generation)
		must(t, e)
		refs, e := generation.Dependencies(raw, f.domain.Trust)
		must(t, e)
		must(t, r.Close())
		name := filepath.Join(dir, "objects", refs[0].ID)
		bad, e := os.ReadFile(name)
		must(t, e)
		bad[0] ^= 1
		must(t, os.WriteFile(name, bad, 0600))
	}
	// No manual verification/damage marking occurs after the raw fault.
	f.domain.ScrubIntervalSeconds = 60
	f.replicationConfig(t, 1, 2, push, pull)
	f.replicationConfig(t, 2, 2, pull)
	stopA = start(t, f.nodes[0])
	defer stopA()
	stopB = start(t, f.nodes[1])
	defer stopB()
	stopC = start(t, f.nodes[2])
	defer stopC()
	wait(t, func() bool {
		b, c := scheduledState(t, f.nodes[1], f), scheduledState(t, f.nodes[2], f)
		return b.Phase == "COMPLETE" && c.Phase == "COMPLETE" && b.HealthToken != "" && c.HealthToken != ""
	})
	stopA()
	stopC()
	stopB()
	for _, index := range []int{1, 2} {
		w := f.nodes[index]
		dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
		r, e := generation.Open(dir, f.domain.Trust, false)
		must(t, e)
		must(t, r.VerifyComplete(context.Background(), f.generation))
		journal, e := r.Integrity(context.Background())
		must(t, e)
		must(t, r.Close())
		if len(journal.Repairs) != 1 || len(journal.Damage) != 0 {
			t.Fatal("scheduled detection did not repair", journal)
		}
		snapshot, e := w.ManagementSnapshot(context.Background(), workerEnrollment(t, f, index), f.domain.Trust.Domain)
		must(t, e)
		if len(snapshot.Generations) != 1 || snapshot.Generations[0].Verification != "CIPHERTEXT" || snapshot.Generations[0].VerifiedUnix != scheduledState(t, w, f).VerifiedUnix {
			t.Fatal("scheduled observation age absent", snapshot.Generations)
		}
	}
}

func TestScheduledScrubNewCyclesReadFreshAndRestartKeepsOriginalAge(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.domain.ScrubIntervalSeconds = 1
	f.config(t, 0, nil)
	w := f.nodes[0]
	stop := start(t, w)
	wait(t, func() bool { return scheduledState(t, w, f).Phase == "COMPLETE" })
	first := scheduledState(t, w, f)
	wait(t, func() bool { s := scheduledState(t, w, f); return s.Phase == "COMPLETE" && s.Window != first.Window })
	second := scheduledState(t, w, f)
	if second.VerifiedUnix <= first.VerifiedUnix {
		t.Fatal("new window did not actually read later", first, second)
	}
	stop()
	saved := scheduledState(t, w, f)
	other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer other.Close()
	after := scheduledState(t, other, f)
	a, _ := json.Marshal(saved)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Fatal("reopen changed successful age")
	}
	must(t, other.MigrateControls(context.Background(), false))
	s, e := other.Status(context.Background())
	must(t, e)
	if s.Format != ScheduledFormat {
		t.Fatal("control migration downgraded schedule")
	}
	if e = other.MigrateControls(context.Background(), true); !errors.Is(e, ErrDenied) {
		t.Fatal("rollback discarded scheduled evidence", e)
	}
	// Downgrading only the format cannot make older semantics accept the state.
	raw, e := other.state.Read("worker.json")
	must(t, e)
	s.Format = Format
	bad, e := json.Marshal(s)
	must(t, e)
	must(t, other.state.Write("worker.json", bad))
	if _, e = other.Status(context.Background()); !errors.Is(e, ErrDenied) {
		t.Fatal("schedule accepted under old format", e)
	}
	must(t, other.state.Write("worker.json", raw))
}

func TestScheduledScrubPauseJoinsAndResumePreservesReadWindow(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.domain.ScrubIntervalSeconds = 60
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	w.Fault = func(point string) error {
		if point == "worker-scrub-batch-durable" {
			once.Do(func() { close(entered); <-release })
		}
		return nil
	}
	stop := start(t, w)
	defer stop()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled batch not reached")
	}
	before := scheduledState(t, w, f)
	type reply struct {
		ack []byte
		e   error
	}
	done := make(chan reply, 1)
	pause := makeCommand("pause", "", 1)
	go func() { ack, e := w.ExecuteCommand(ctx, pause); done <- reply{ack, e} }()
	wait(t, func() bool { s, e := w.Status(ctx); return e == nil && s.Controls.Domains[f.domain.Trust.Domain] })
	select {
	case <-done:
		t.Fatal("pause acknowledged before scheduled scrub joined")
	case <-time.After(150 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case r := <-done:
		must(t, r.e)
		if verifyWorkerAck(t, w, pause, r.ack).State != "COMPLETE" {
			t.Fatal("pause failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pause did not join")
	}
	paused := scheduledState(t, w, f)
	if paused.Phase != "QUEUED" || paused.Window != before.Window {
		t.Fatal("pause discarded scrub window", paused)
	}
	_, e := w.ExecuteCommand(ctx, makeCommand("resume", "", 2))
	must(t, e)
	wait(t, func() bool { return scheduledState(t, w, f).Phase == "COMPLETE" })
	resumed := scheduledState(t, w, f)
	if resumed.Window != before.Window || resumed.Attempts < 2 || resumed.VerifiedUnix < before.StartedUnix {
		t.Fatal("resume relabelled/discarded verification", resumed)
	}
}

func TestScheduledScrubQuotaDenialPrecedesPayloadRead(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.domain.ScrubIntervalSeconds = 60
	c := f.config(t, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	r, e := generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	defer r.Close()
	s, e := w.Status(ctx)
	must(t, e)
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	v := &view{cfg: c, ctx: bounded, cancel: cancel, controls: s.Controls, domains: map[string]*domainState{f.domain.Trust.Domain: {replica: r}}}
	must(t, w.state.SetAdmission(ctx, func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }))
	running := map[string]bool{}
	if e = w.scheduleScrub(v, running, make(chan result, 1)); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("schedule bypassed journal quota", e)
	}
	if len(running) != 0 {
		t.Fatal("read started without durable admission")
	}
	s, e = w.Status(ctx)
	must(t, e)
	if len(s.Scrubs) != 0 || s.Format != Format {
		t.Fatal("quota denial committed schedule")
	}
	if _, e = os.Stat(filepath.Join(dir, "verification")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("payload verified before durable intent", e)
	}
}

func TestScheduledScrubSIGKILLRetainsWindowAndReceipt(t *testing.T) {
	for _, point := range []string{"worker-scrub-intent-durable", "worker-scrub-batch-durable", "worker-scrub-result-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			f.endpoint(t, nil)
			f.domain.ScrubIntervalSeconds = 60
			f.config(t, 0, nil)
			w := f.nodes[0]
			in := commandChild{planningChild: planningChild{Directory: w.dir, Node: w.node, Point: point, Owner: w.owner, Certificate: w.cert.Certificate[0], CA: f.ca.cert.Raw, Key: w.cert.PrivateKey.(ed25519.PrivateKey)}, Scheduled: true}
			raw, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(f.base, "scheduled-child.json")
			must(t, os.WriteFile(file, raw, 0600))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkerCommandSIGKILLChild$")
			child.Env = append(os.Environ(), "OUTPOST_WORKER_COMMAND_CHILD="+file)
			output, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || ctx.Err() != nil {
				t.Fatalf("child not killed: %v %s", e, output)
			}
			waited, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !waited.Signaled() || waited.Signal() != syscall.SIGKILL {
				t.Fatalf("not SIGKILL: %v %s", e, output)
			}
			before := scheduledState(t, w, f)
			if before.Window == "" {
				t.Fatal("durable schedule lost")
			}
			stop := start(t, w)
			wait(t, func() bool { return scheduledState(t, w, f).Phase == "COMPLETE" })
			stop()
			after := scheduledState(t, w, f)
			if after.Window != before.Window || point == "worker-scrub-result-durable" && after.VerifiedUnix != before.VerifiedUnix {
				t.Fatal("restart replaced historical result", before, after)
			}
		})
	}
}
