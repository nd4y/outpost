package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func TestJournalBatchesAreBoundedAtomicAndAdmitted(t *testing.T) {
	f := fixtureBytes(t, 2<<20)
	target := f.server(t, "s3", 0, nil)
	raw := f.plan(t, target, 1, 10000)
	dir := filepath.Join(f.base, "progress-batches")
	must(t, os.Mkdir(dir, 0700))
	j, err := Open(dir, raw, f.workers[0].ID, f.authority, true)
	must(t, err)
	defer func() { j.Close() }()
	tasks, err := j.plan.Tasks()
	must(t, err)
	if len(tasks) <= maxProgressBatch {
		t.Fatal("bound control needs 33 genuine plan members")
	}
	ids := make([]string, maxProgressBatch)
	for i := range ids {
		ids[i] = tasks[i].Part.ID
	}
	ctx := t.Context()
	snapshot := func() []byte {
		t.Helper()
		s, err := j.Status(ctx)
		must(t, err)
		encoded, err := json.Marshal(s)
		must(t, err)
		return encoded
	}
	reject := func(operation func() error) {
		t.Helper()
		before := snapshot()
		if operation() == nil || !bytes.Equal(before, snapshot()) {
			t.Fatal("rejected transaction changed durable progress")
		}
	}
	reject(func() error { return j.beginParts(ctx, nil, 0) })
	reject(func() error { return j.beginParts(ctx, append(append([]string{}, ids...), tasks[32].Part.ID), 0) })
	reject(func() error { return j.beginParts(ctx, []string{ids[0], ids[0]}, 0) })
	reject(func() error { return j.beginParts(ctx, []string{ids[0], storage.Hash([]byte("outside plan"))}, 0) })
	reject(func() error { return j.beginParts(ctx, ids, -1) })
	j.Guard = func(context.Context) error { return storage.ErrUnavailable }
	reject(func() error { return j.beginParts(ctx, ids, 0) })
	j.Guard = nil
	j.Admit = func(string, int) (func(bool) error, error) { return nil, storage.ErrDenied }
	reject(func() error { return j.beginParts(ctx, ids, 0) })
	j.Admit = nil
	commits := 0
	j.Admit = func(string, int) (func(bool) error, error) {
		return func(committed bool) error {
			if committed {
				commits++
			}
			return nil
		}, nil
	}
	must(t, j.beginParts(ctx, ids, 0))
	if commits != 1 {
		t.Fatal("intent batch was not one admitted durable transaction", commits)
	}
	must(t, j.Close())
	j, err = Open(dir, raw, f.workers[0].ID, f.authority, false)
	must(t, err)
	state, err := j.Status(ctx)
	must(t, err)
	if state.Phase != "TRANSFERRING" || state.Receipt != nil || len(state.Parts) != maxProgressBatch {
		t.Fatal("pending intents became completion evidence after reopen")
	}
	for _, p := range state.Parts {
		if p.Complete || p.Attempts != 1 {
			t.Fatal("preparation has a fabricated acknowledgement")
		}
	}
	acks := []partAcknowledgement{{id: ids[0], round: 1, submitted: 1}, {id: ids[1], round: 2, submitted: 0}}
	reject(func() error { return j.doneParts(ctx, nil) })
	reject(func() error { return j.doneParts(ctx, append(append([]partAcknowledgement{}, acks...), acks[0])) })
	reject(func() error { return j.doneParts(ctx, []partAcknowledgement{acks[0], {id: tasks[32].Part.ID}}) })
	reject(func() error { return j.doneParts(ctx, []partAcknowledgement{{id: ids[0], round: -1}}) })
	reject(func() error { return j.doneParts(ctx, []partAcknowledgement{{id: ids[0], submitted: -1}}) })
	reject(func() error { return j.doneParts(ctx, make([]partAcknowledgement, maxProgressBatch+1)) })
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	reject(func() error { return j.doneParts(stopped, acks) })
	j.Guard = func(context.Context) error { return storage.ErrUnavailable }
	reject(func() error { return j.doneParts(ctx, acks) })
	j.Guard = nil
	j.Admit = func(string, int) (func(bool) error, error) { return nil, storage.ErrDenied }
	reject(func() error { return j.doneParts(ctx, acks) })
	j.Admit = nil
	must(t, j.doneParts(ctx, acks))
	reject(func() error { return j.doneParts(ctx, acks) })
	must(t, j.Close())
	j, err = Open(dir, raw, f.workers[0].ID, f.authority, false)
	must(t, err)
	state, err = j.Status(ctx)
	must(t, err)
	if !state.Parts[ids[0]].Complete || state.Parts[ids[0]].Round != 1 || state.Parts[ids[0]].SubmittedBytes != 1 || !state.Parts[ids[1]].Complete || state.Parts[ids[1]].Round != 2 || state.Parts[ids[2]].Complete || state.Receipt != nil {
		t.Fatal("acknowledgement transaction changed scope or publication state")
	}
	if err := j.edit(ctx, func(s *State) error {
		p := s.Parts[ids[2]]
		p.SubmittedBytes = int64(^uint64(0) >> 1)
		s.Parts[ids[2]] = p
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reject(func() error { return j.doneParts(ctx, []partAcknowledgement{{id: ids[2], submitted: 1}}) })
}

func TestJournalBatchSIGKILLRechecksUncommittedAcknowledgement(t *testing.T) {
	f := fixtureBytes(t, 128<<10)
	var blocking atomic.Bool
	blocking.Store(true)
	var mu sync.Mutex
	var first string
	var firstReads int
	reached := make(chan struct{})
	var once sync.Once
	target := f.server(t, "webdav", 0, nil)
	target.Options.Before = func(_ http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
		if !strings.HasPrefix(key, "part-") {
			return false
		}
		mu.Lock()
		if first == "" && r.Method == http.MethodPut {
			first = key
		}
		isFirst := first == key
		if isFirst && r.Method == http.MethodGet && target.Snapshot().Writes[key] == 1 {
			firstReads++
		}
		mu.Unlock()
		if r.Method == http.MethodPut && !isFirst && blocking.Load() {
			once.Do(func() { close(reached) })
			<-r.Context().Done()
			return true
		}
		return false
	}
	raw := f.plan(t, target, 1, 30000)
	worker := f.prepare(t, target, raw, 0)
	worker.start(t)
	select {
	case <-reached:
	case <-time.After(7 * time.Second):
		t.Fatal("worker did not reach a pending verified acknowledgement")
	}
	j, err := Open(worker.config.Directory, raw, worker.config.Worker, f.authority, false)
	must(t, err)
	defer j.Close()
	state, err := j.Status(t.Context())
	must(t, err)
	mu.Lock()
	key, reads := first, firstReads
	mu.Unlock()
	if key == "" || reads < 1 || state.Parts[strings.TrimPrefix(key, "part-")].Complete || state.Receipt != nil {
		t.Fatal("volatile acknowledgement was exposed as durable completion")
	}
	pins, err := f.replicas[0].Status(t.Context())
	must(t, err)
	if _, ok := pins.Pins[workerPin(j.planID, worker.config.Worker)]; !ok {
		t.Fatal("pending upload lost its source pin")
	}
	must(t, worker.cmd.Process.Kill())
	worker.wait(t, false)
	blocking.Store(false)
	worker.start(t)
	worker.wait(t, true)
	mu.Lock()
	afterReads := firstReads
	mu.Unlock()
	if afterReads <= reads || target.Snapshot().Writes[key] != 1 {
		t.Fatal("restart did not recheck immutable bytes before acknowledging them")
	}
	state, err = j.Status(t.Context())
	must(t, err)
	if state.Phase != "COMPLETE" || state.Receipt == nil {
		t.Fatal("recovered batch failed final publication")
	}
	for _, part := range state.Parts {
		if !part.Complete {
			t.Fatal("publication preceded the durable acknowledgement flush")
		}
	}
	recoverBytes(t, f, target, f.id, f.version, f.data)
	if _, err := os.Stat(worker.config.Result); errors.Is(err, os.ErrNotExist) {
		t.Fatal("worker did not write its accepted receipt")
	}
}
