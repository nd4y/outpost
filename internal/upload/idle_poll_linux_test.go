package upload

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func waitUploadCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("upload condition did not settle")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func idleUploadWorker(t *testing.T, f *fixture, raw []byte) int {
	t.Helper()
	plan, err := Verify(raw, f.authority)
	must(t, err)
	for i, worker := range f.workers {
		if worker.ID != plan.owner("publication", 0) {
			return i
		}
	}
	t.Fatal("no worker distinct from the round-zero publisher")
	return -1
}

func ownUploadPartsComplete(t *testing.T, j *Journal) bool {
	t.Helper()
	state, err := j.Status(context.Background())
	must(t, err)
	if state.Phase != "TRANSFERRING" {
		return false
	}
	tasks, err := j.plan.Tasks()
	must(t, err)
	for _, task := range tasks {
		if j.plan.owner(task.Part.ID, 0) == j.worker && !state.Parts[task.Part.ID].Complete {
			return false
		}
	}
	return true
}

func requireIdleUploadPin(t *testing.T, f *fixture, j *Journal, worker int) {
	t.Helper()
	state, err := j.Status(context.Background())
	must(t, err)
	if state.Phase == "COMPLETE" || state.Receipt != nil {
		t.Fatal("waiting for peers created completion evidence")
	}
	status, err := f.replicas[worker].Status(context.Background())
	must(t, err)
	if status.Pins[workerPin(j.planID, j.worker)].Generation != f.id {
		t.Fatal("waiting for peers released the source generation pin")
	}
}

func TestWaitingUploadWorkerBoundsTargetPolling(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureBytes(t, 512<<10)
			f.childTimeout = 60 * time.Second
			var markerReads atomic.Int64
			target := f.server(t, kind, 0, func(_ http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
				if r.Method == http.MethodGet && key == "complete-"+f.id {
					markerReads.Add(1)
				}
				return false
			})
			raw := f.plan(t, target, 3, 180000)
			worker := idleUploadWorker(t, f, raw)
			workerProcess := f.prepare(t, target, raw, worker)
			journal, err := Open(workerProcess.config.Directory, raw, workerProcess.config.Worker, f.authority, false)
			must(t, err)
			defer journal.Close()
			workerProcess.start(t)
			waitUploadCondition(t, func() bool { return ownUploadPartsComplete(t, journal) })
			before := markerReads.Load()
			time.Sleep(2100 * time.Millisecond)
			polls := markerReads.Load() - before
			t.Logf("idle target marker GETs protocol=%s interval=2.1s count=%d", kind, polls)
			if polls > 12 {
				t.Errorf("waiting worker polled the target too often: %d GETs in2.1s", polls)
			}
			requireIdleUploadPin(t, f, journal, worker)
			must(t, workerProcess.cmd.Process.Kill())
			workerProcess.wait(t, false)
			// Restart the same journal, then let its missing peers complete.
			workerProcess.start(t)
			others := []*child{}
			for i := range f.workers {
				if i != worker {
					other := f.prepare(t, target, raw, i)
					other.start(t)
					others = append(others, other)
				}
			}
			workerProcess.wait(t, true)
			for _, other := range others {
				other.wait(t, true)
			}
			for key, count := range target.Snapshot().Writes {
				if count != 1 {
					t.Fatal("idle restart rewrote immutable bytes", key, count)
				}
			}
			recoverBytes(t, f, target, f.id, f.version, f.data)
		})
	}
}

func TestWaitingUploadBackoffCancellationKeepsPin(t *testing.T) {
	f := fixtureBytes(t, 128<<10)
	var markerReads atomic.Int64
	target := f.server(t, "webdav", 0, func(_ http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
		if r.Method == http.MethodGet && key == "complete-"+f.id {
			markerReads.Add(1)
		}
		return false
	})
	raw := f.plan(t, target, 3, 180000)
	worker := idleUploadWorker(t, f, raw)
	workerProcess := f.prepare(t, target, raw, worker)
	j, err := Open(workerProcess.config.Directory, raw, workerProcess.config.Worker, f.authority, false)
	must(t, err)
	defer j.Close()
	backend := f.backend(t, target, worker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := j.Run(ctx, f.replicas[worker], backend, f.keys[worker]); done <- err }()
	// Observe enough no-progress iterations to reach the idle cap.
	waitUploadCondition(t, func() bool { return ownUploadPartsComplete(t, j) && markerReads.Load() >= 6 })
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("idle cancellation result", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for an idle polling interval")
	}
	requireIdleUploadPin(t, f, j, worker)
	state, err := j.Status(context.Background())
	must(t, err)
	if state.Phase != "RETRYABLE" {
		t.Fatal("cancelled idle worker lost retryable state", state.Phase)
	}
	before := markerReads.Load()
	time.Sleep(100 * time.Millisecond)
	if markerReads.Load() != before {
		t.Fatal("idle polling continued after Run joined")
	}
	if _, err := backend.Catalog(context.Background(), f.id, f.authority.Generation); !storage.Missing(err) {
		t.Fatal("idle cancellation manufactured a complete marker", err)
	}
}
