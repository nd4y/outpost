package upload

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/teststore"
)

func TestWebDAVMoveProcessesResumeAndRestoreBothGenerations(t *testing.T) {
	f := newFixture(t)
	var interrupt atomic.Int32
	blocked := make(chan string, 1)
	stopReply := func(r *http.Request, key string) bool {
		blocked <- key
		<-r.Context().Done()
		return true
	}
	target := f.externalServer(t, teststore.Options{Kind: "webdav", MoveOnly: true, Delay: 25 * time.Millisecond,
		Before: func(_ http.ResponseWriter, r *http.Request, actor, key string, _ []byte) bool {
			if actor == f.workers[0].ID && r.Method == "MOVE" && strings.Contains(r.Header.Get("Destination"), "-part-") && interrupt.CompareAndSwap(1, 0) {
				return stopReply(r, key)
			}
			return false
		},
		AfterWrite: func(_ http.ResponseWriter, r *http.Request, actor, key string, _ []byte) bool {
			if actor == f.workers[0].ID && r.Method == "MOVE" && strings.HasPrefix(key, "part-") && interrupt.CompareAndSwap(2, 0) {
				return stopReply(r, key)
			}
			return false
		},
	})
	oldID, oldVersion, oldBytes := f.id, f.version, bytes.Clone(f.data)
	plan := f.plan(t, target, 3, 60000)
	workers := []*child{f.prepare(t, target, plan, 0), f.prepare(t, target, plan, 1), f.prepare(t, target, plan, 2)}
	killAt := func(phase int32) string {
		t.Helper()
		interrupt.Store(phase)
		workers[0].start(t)
		select {
		case key := <-blocked:
			must(t, workers[0].cmd.Process.Kill())
			workers[0].wait(t, false)
			return key
		case <-time.After(10 * time.Second):
			t.Fatal("worker did not reach requested MOVE boundary", phase)
			return ""
		}
	}
	staged := killAt(1)
	if _, err := os.Stat(target.Path(staged)); err != nil {
		t.Fatal("staged ciphertext not retained across SIGKILL", err)
	}
	if _, err := os.Stat(target.Path("complete-" + oldID)); !os.IsNotExist(err) {
		t.Fatal("generation published before parts arrived", err)
	}
	part := killAt(2)
	if _, err := os.Stat(target.Path(part)); err != nil {
		t.Fatal("MOVE was not durable before second SIGKILL", err)
	}
	for _, worker := range workers {
		worker.start(t)
	}
	for _, worker := range workers {
		worker.wait(t, true)
	}
	initial := target.Snapshot()
	actors := map[string]bool{}
	for _, event := range initial.Events {
		actors[event.Actor] = true
	}
	if len(actors) != 3 || initial.PeakWorkers < 2 || initial.Writes[staged] != 1 || initial.Writes[part] != 1 {
		t.Fatal("missing parallel payload transfer or replayed durable stage", len(actors), initial.PeakWorkers, initial.Writes[staged], initial.Writes[part])
	}
	// Removing the local journal from this synthetic worker must halt before
	// any target request, even when another worker completed the generation.
	book := filepath.Join(workers[0].config.Directory, "move-attempts")
	must(t, os.Rename(book, book+"-held"))
	workers[0].start(t)
	workers[0].wait(t, false)
	if target.Snapshot().Requests != initial.Requests {
		t.Fatal("worker contacted target after losing its attempt book")
	}
	must(t, os.Rename(book+"-held", book))

	changed := bytes.Clone(oldBytes)
	changed[len(changed)/2] ^= 1
	must(t, os.WriteFile(f.input, changed, 0640))
	f.id, f.version = f.capture(t, 2, oldID)
	plan = f.plan(t, target, 3, 60000)
	for i := range workers {
		workers[i] = f.prepare(t, target, plan, i)
		workers[i].start(t)
	}
	for _, worker := range workers {
		worker.wait(t, true)
	}
	for key, count := range target.Snapshot().Writes {
		if !strings.HasPrefix(key, "attempt-") && !strings.HasPrefix(key, "probe-stage-") && count != 1 {
			t.Fatal("canonical object rewritten", key, count)
		}
	}
	for i, replica := range f.replicas {
		must(t, replica.Close())
		must(t, os.Rename(f.dirs[i], f.dirs[i]+"-held"))
	}
	must(t, f.store.Close())
	must(t, os.Rename(filepath.Join(f.base, "source-store"), filepath.Join(f.base, "source-store-held")))
	must(t, os.Rename(f.input, f.input+"-held"))
	recoverBytes(t, f, target, oldID, oldVersion, oldBytes)
	recoverBytes(t, f, target, f.id, f.version, changed)
	t.Log("three distinct processes, two actual SIGKILL boundaries around MOVE, retained attempt restored without a repeated PUT, and both generations independently restored")
}

func TestWebDAVMoveQueueReopensWithDurableAttemptBook(t *testing.T) {
	f := fixtureBytes(t, 192<<10)
	target := f.externalServer(t, teststore.Options{Kind: "webdav", MoveOnly: true})
	plan := f.plan(t, target, 1, 60000)
	q, dir := queueFor(t, f, queueLimits())
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	must(t, q.Enqueue(ctx, f.replicas[0], plan))
	must(t, q.Run(ctx, f.replicas[0], f.resolve(t, target), f.keys[0]))
	must(t, q.Close())
	q, err := OpenQueue(dir, f.workers[0].ID, f.authority, queueLimits(), false)
	must(t, err)
	defer q.Close()
	state, err := q.Status(ctx)
	must(t, err)
	op := planOperation(t, plan, f.authority)
	if state.Jobs[op].Phase != "COMPLETE" || state.Jobs[op].Receipt == nil {
		t.Fatal("queue lost completion on reopen")
	}
	journal, err := q.journal(state.Jobs[op], false)
	must(t, err)
	defer journal.Close()
	inner, err := journal.Status(ctx)
	must(t, err)
	if inner.Format != moveJournalFormat || !inner.MoveBookReady || inner.Phase != "COMPLETE" {
		t.Fatal("queue did not use durable MOVE journal", inner.Format, inner.Phase)
	}
}
