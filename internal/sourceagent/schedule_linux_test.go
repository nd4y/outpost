package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/statefile"
)

func testSchedule() Schedule {
	return Schedule{Format: ScheduleFormat, Revision: 1, Enabled: true, IntervalSeconds: 3600, RetrySeconds: 1, AttemptSeconds: 10, StartUnix: time.Now().Unix()}
}
func TestSourceScheduleReconcilesAcceptedHeadAndRestoresSuccessiveGenerations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := testSchedule()
	// The acknowledgement/replay contract does not depend on HDD latency.
	c.AttemptSeconds = 150
	must(t, f.a.ConfigureSchedule(ctx, c))
	started := time.Now()
	f.a.Fault = func(point string) error {
		if point == "source-schedule-head-observed" {
			return errors.New("lost scheduling acknowledgement")
		}
		return nil
	}
	must(t, f.a.scheduleStep(ctx))
	state, e := f.a.ScheduleStatus(ctx)
	must(t, e)
	if state.LastSequence != 0 || state.Phase != "RETRY_WAIT" {
		t.Fatal("fault not exercised", state)
	}
	first, e := f.a.Status(ctx)
	must(t, e)
	if first.Sequence != 1 || first.Phase != "COMPLETE" {
		t.Fatalf("head not durable after %s, schedule error=%s, source phase=%s, capture=%+v", time.Since(started), state.ErrorCode, first.Phase, first.Job)
	}
	t.Logf("first scheduled checkpoint durable after %s", time.Since(started))
	initial, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	f.reopen(t)
	must(t, f.a.scheduleStep(ctx))
	state, e = f.a.ScheduleStatus(ctx)
	must(t, e)
	if state.LastSequence != 1 || state.Attempts != 1 || state.NextUnix <= time.Now().Unix() {
		t.Fatal("accepted generation repeated", state)
	}
	must(t, f.a.scheduleStep(ctx))
	same, e := f.a.Status(ctx)
	must(t, e)
	if same.Generation != first.Generation || same.Sequence != 1 {
		t.Fatal("not-yet-due source recaptured")
	}
	changed := bytes.Repeat([]byte("scheduled new data"), 20000)
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), changed, 0640))
	c.Revision = 2
	must(t, f.a.ConfigureSchedule(ctx, c))
	must(t, f.a.scheduleStep(ctx))
	second, e := f.a.Status(ctx)
	must(t, e)
	if second.Sequence != 2 || second.Generation == first.Generation {
		t.Fatal("next due generation absent")
	}
	must(t, os.RemoveAll(f.tree))
	for i, item := range []struct {
		id   string
		data []byte
	}{{first.Generation, initial}, {second.Generation, changed}} {
		destination := filepath.Join(f.base, []string{"restore-first", "restore-second"}[i])
		_, e = generation.RecoverMaterialized(ctx, f.replicaPath, item.id, f.grant.Trust, f.owner, generation.RecoverySelection{}, destination)
		must(t, e)
		restored, e := os.ReadFile(filepath.Join(destination, "private.bin"))
		must(t, e)
		if !bytes.Equal(restored, item.data) {
			t.Fatal("scheduled version differs")
		}
	}
}

func TestSourceSchedulePauseAndStatusRemainResponsiveDuringNetworkRead(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	joined := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once, joinedOnce sync.Once
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/objects/") {
			// Consume the request before waiting for disconnect. An unread HTTP/1
			// body can prevent the server from observing the client's cancellation.
			_, _ = io.Copy(io.Discard, r.Body)
			once.Do(func() { close(started) })
			select {
			case <-r.Context().Done():
				joinedOnce.Do(func() { close(joined) })
			case <-release:
			}
			return true
		}
		return false
	}
	c := testSchedule()
	must(t, f.a.ConfigureSchedule(ctx, c))
	done := make(chan error, 1)
	go func() { done <- f.a.RunSchedule(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("source did not reach blocked object transfer")
	}
	bounded, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer stop()
	status, e := f.a.ScheduleStatus(bounded)
	must(t, e)
	if status.Phase != "RUNNING" {
		t.Fatal("running schedule not visible", status)
	}
	duplicate, stopDuplicate := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stopDuplicate()
	if e = f.a.RunSchedule(duplicate); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("second scheduler acquired active execution lease", e)
	}
	c.Revision++
	c.Enabled = false
	// Use another OS process, as the CLI does. Opening the ordinary Agent
	// here would wait for capture and prevent the cancellation it is requesting.
	input, e := json.Marshal(struct {
		Bootstrap Bootstrap
		Schedule  Schedule
	}{f.b, c})
	must(t, e)
	file := filepath.Join(f.base, "schedule-control.json")
	must(t, os.WriteFile(file, input, 0600))
	childCtx, stopChild := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopChild()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestSourceScheduleControlChild$")
	cmd.Env = append(os.Environ(), "OUTPOST_SCHEDULE_CONTROL_INPUT="+file, "GORACE=atexit_sleep_ms=0")
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("independent control blocked: %v %s", e, output)
	}
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("pause did not cancel network request")
	}
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("source scheduler did not join")
	}
	status, e = f.a.ScheduleStatus(context.Background())
	must(t, e)
	if status.Config.Enabled || status.Phase != "PAUSED" {
		t.Fatal("pause overwritten", status)
	}
	pending, e := f.a.Status(context.Background())
	must(t, e)
	if pending.Operation == "" || pending.Phase == "COMPLETE" {
		t.Fatal("pending source not preserved", pending)
	}
	f.intercept = nil
	c.Revision++
	c.Enabled = true
	must(t, f.a.ConfigureSchedule(context.Background(), c))
	must(t, f.a.scheduleStep(context.Background()))
	resumed, e := f.a.Status(context.Background())
	must(t, e)
	if resumed.Operation != pending.Operation || resumed.Sequence != 1 || resumed.Phase != "COMPLETE" {
		t.Fatal("resume replaced source intent", resumed)
	}
}

func TestSourceScheduleControlChild(t *testing.T) {
	file := os.Getenv("OUTPOST_SCHEDULE_CONTROL_INPUT")
	if file == "" {
		t.Skip("child only")
	}
	var input struct {
		Bootstrap Bootstrap
		Schedule  Schedule
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	must(t, json.Unmarshal(raw, &input))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	c, e := OpenScheduleControl(ctx, input.Bootstrap)
	must(t, e)
	defer c.Close()
	s, e := c.Status(ctx)
	must(t, e)
	if s.Phase != "RUNNING" {
		t.Fatal("active source not observed")
	}
	must(t, c.Configure(ctx, input.Schedule))
}

func TestSourceScheduleInitialPendingHeadKeepsOriginalCopyAge(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	first, e := f.a.load()
	must(t, e)
	checkpoint, e := capture.VerifyCheckpoint(first.Checkpoint, f.grant.Trust)
	must(t, e)
	must(t, f.a.Next(ctx))
	pending, e := f.a.load()
	must(t, e)
	if pending.Phase == "COMPLETE" {
		t.Fatal("pending fixture absent")
	}
	must(t, f.a.ConfigureSchedule(ctx, testSchedule()))
	s, e := f.a.ScheduleStatus(ctx)
	must(t, e)
	if s.LastSequence != first.Sequence || s.LastGeneration != first.Generation || s.LastCompletedUnix != checkpoint.Receipt.VerifiedAt {
		t.Fatal("initial schedule lost retained evidence", s)
	}
}

func TestSourceScheduleRejectsRevisionTamperingClockRollbackAndQuota(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := testSchedule()
	must(t, f.a.ConfigureSchedule(ctx, c))
	must(t, f.a.ConfigureSchedule(ctx, c))
	changed := c
	changed.IntervalSeconds++
	if e := f.a.ConfigureSchedule(ctx, changed); !errors.Is(e, ingress.ErrConflict) {
		t.Fatal("same revision changed", e)
	}
	changed = c
	changed.Revision++
	changed.Enabled = false
	must(t, f.a.ConfigureSchedule(ctx, changed))
	if e := f.a.ConfigureSchedule(ctx, c); !errors.Is(e, ingress.ErrConflict) {
		t.Fatal("old schedule replayed", e)
	}
	original, e := f.a.store.Read("schedule.json")
	must(t, e)
	s, e := f.a.loadSchedule()
	must(t, e)
	s.UpdatedUnix = time.Now().Add(time.Hour).Unix()
	s.Signature = nil
	payload, e := json.Marshal(s)
	must(t, e)
	s.Signature = ed25519.Sign(f.a.writer, append([]byte(scheduleStateFormat+"\x00"), payload...))
	raw, e := json.Marshal(s)
	must(t, e)
	must(t, f.a.store.Write("schedule.json", raw))
	if _, e = f.a.ScheduleStatus(ctx); !errors.Is(e, ErrInvalid) {
		t.Fatal("clock rollback ignored", e)
	}
	must(t, f.a.store.Write("schedule.json", []byte("{}")))
	changed.Revision++
	if e = f.a.ConfigureSchedule(ctx, changed); !errors.Is(e, ErrInvalid) {
		t.Fatal("corrupt schedule reset", e)
	}
	kept, e := f.a.store.Read("schedule.json")
	must(t, e)
	if string(kept) != "{}" {
		t.Fatal("corrupt state overwritten")
	}
	must(t, f.a.store.Write("schedule.json", original))
	admit := f.a.store.Admit
	defer func() { f.a.store.Admit = admit }()
	f.a.store.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if e = f.a.ConfigureSchedule(ctx, changed); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("schedule bypassed quota", e)
	}
	kept, e = f.a.store.Read("schedule.json")
	must(t, e)
	if !bytes.Equal(kept, original) {
		t.Fatal("failed update changed accepted schedule")
	}
}
