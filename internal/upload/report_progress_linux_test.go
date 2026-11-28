package upload

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func TestUploadObservedProgressRequiresMatchingDurableParts(t *testing.T) {
	f := newFixture(t)
	target := f.server(t, "webdav", 0, nil)
	raw := f.plan(t, target, 1, 1000)
	ctx := t.Context()
	plan, err := Verify(raw, f.authority)
	must(t, err)
	tasks, err := plan.Tasks()
	must(t, err)
	if len(tasks) < 2 {
		t.Fatal("fixture needs an uncompleted part")
	}
	bound := ProgressBinding{Operation: plan.Operation, Generation: plan.Generation,
		Target: plan.Profile.ID(), Plan: storage.Hash(raw)}
	limits := queueLimits()
	long := limits
	long.AttemptMillis = MaxAttemptMillis
	q, dir := queueFor(t, f, long)
	observe := func(ctx context.Context, b ProgressBinding) (JobProgress, error) {
		return ObserveProgressAt(ctx, nil, dir, f.workers[0].ID, f.authority, limits, b)
	}
	must(t, q.Enqueue(ctx, f.replicas[0], raw))
	must(t, q.edit(ctx, func(s *QueueState) error {
		job := s.Jobs[plan.Operation]
		job.Phase, job.Attempts = "RUNNING", 1
		s.Jobs[plan.Operation] = job
		return nil
	}))
	state, err := q.Status(ctx)
	must(t, err)
	journal, err := q.journal(state.Jobs[plan.Operation], false)
	must(t, err)
	defer journal.Close()
	if delay := time.Until(time.UnixMilli(plan.StartMillis)); delay > 0 {
		time.Sleep(delay)
	}
	inner := filepath.Join(dir, "jobs", plan.Operation)
	if _, err := observe(ctx, bound); err == nil {
		t.Fatal("old journal without an existing progress lock produced a sample")
	}
	if _, err := os.Stat(filepath.Join(inner, "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("observer created missing journal lock", err)
	}
	must(t, journal.beginParts(ctx, []string{tasks[0].Part.ID, tasks[1].Part.ID}, 0))
	intent, err := observe(ctx, bound)
	must(t, err)
	var total int64
	for _, task := range tasks {
		total += int64(task.Part.Bytes)
	}
	if intent != (JobProgress{PlanBytes: total}) {
		t.Fatal("prepared part intents counted as confirmation", intent)
	}
	must(t, journal.doneParts(ctx, []partAcknowledgement{{id: tasks[0].Part.ID, round: 0, submitted: 0}}))
	want := JobProgress{PlanBytes: total, ConfirmedBytes: int64(tasks[0].Part.Bytes)}
	before, err := os.ReadFile(filepath.Join(inner, "state.json"))
	must(t, err)
	got, err := observe(ctx, bound)
	must(t, err)
	if got != want {
		t.Fatal("reused target part not counted from its signed size", got, want)
	}
	// The reporting entrypoint starts from fresh handles and accepts the
	// existing long-window queue without creating or migrating state.
	got, err = observe(ctx, bound)
	must(t, err)
	if got != want {
		t.Fatal("restart lost measured progress", got, want)
	}
	for _, field := range []string{"plan", "target", "generation"} {
		bad := bound
		wrong := storage.Hash([]byte(field))
		switch field {
		case "plan":
			bad.Plan = wrong
		case "target":
			bad.Target = wrong
		case "generation":
			bad.Generation = wrong
		}
		if _, err := observe(ctx, bad); err == nil {
			t.Fatal("foreign scope admitted", field)
		}
	}
	for _, test := range []struct {
		root           *os.Root
		lock, document string
		maximum        int
	}{
		{q.root, "queue.lock", "queue.json", maxQueueBytes},
		{journal.root, "state.lock", "state.json", maxJournal},
		{journal.root, "state.lock", "plan.json", MaxPlan},
	} {
		func() {
			unlock, err := lock(ctx, test.root, test.lock)
			must(t, err)
			defer unlock()
			saved, err := regular(test.root, test.document, test.maximum)
			must(t, err)
			// A bad document would fail an eager read or parse before the
			// observer got to the busy lock. The lock must win.
			must(t, atomicFile(test.root, test.document, []byte("{")))
			defer func() { must(t, atomicFile(test.root, test.document, saved)) }()
			bounded, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			_, err = observe(bounded, bound)
			if !errors.Is(err, syscall.EWOULDBLOCK) || bounded.Err() != nil {
				t.Fatal("observer touched a document before rejecting its busy lock", test.document, err)
			}
		}()
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := observe(canceled, bound); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation proceeded", err)
	}
	after, err := os.ReadFile(filepath.Join(inner, "state.json"))
	must(t, err)
	if !bytes.Equal(after, before) {
		t.Fatal("observer mutated queued progress")
	}
}
