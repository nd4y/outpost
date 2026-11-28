package worker

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

func TestExternalTransferStatusRequiresExactCompletedAttempt(t *testing.T) {
	j := control.Job{Kind: "upload", Executor: "worker", Domain: "domain", Target: "target", Operation: "operation", Generation: "generation"}
	receipt := upload.Receipt{Executor: j.Executor, Target: j.Target, Operation: j.Operation,
		Generation: j.Generation, Verification: "cached-target-readback", ObservedUnix: 6}
	raw, err := json.Marshal(receipt)
	must(t, err)
	job := JobState{Job: j, Receipt: raw, Phase: "COMPLETE", UpdatedUnix: 10}
	queue := upload.QueueJob{Plan: json.RawMessage(`{"opaque":"plan"}`), Attempts: 2, Phase: "COMPLETE", Receipt: &receipt}
	counts := storage.HTTPBodyCounts{Requests: 3, RequestBytes: 250, ResponseBytes: 0, RepeatedRequestBytes: 50}
	attempt := upload.HTTPAttempt{Node: j.Executor, Domain: j.Domain, Target: j.Target, Operation: j.Operation,
		Plan: storage.Hash(queue.Plan), Attempt: 2, StartedMillis: 9500, FinishedMillis: 10000, Outcome: "SUCCEEDED", Counts: &counts}

	got := completedExternalTransfer(job, queue, attempt)
	if got == nil || got.RequestBodyBytesPerSecond == nil || *got.RequestBodyBytesPerSecond != 500 ||
		got.ResponseBodyBytesPerSecond == nil || *got.ResponseBodyBytesPerSecond != 0 ||
		got.FinishedMillis != 10000 || got.ReplayedRequestBodyBytes != 50 {
		t.Fatalf("completed attempt projection differs: %+v", got)
	}
	instant := attempt
	instant.StartedMillis = instant.FinishedMillis
	got = completedExternalTransfer(job, queue, instant)
	if got == nil || got.RequestBodyBytes != 250 || got.RequestBodyBytesPerSecond != nil || got.ResponseBodyBytesPerSecond != nil {
		t.Fatalf("zero-duration evidence lost counts or invented a rate: %+v", got)
	}
	if bodyBytesPerSecond(math.MaxInt64, 1) != nil {
		t.Fatal("overflow produced a rate")
	}
	if rate := bodyBytesPerSecond(math.MaxInt64, 1000); rate == nil || *rate != math.MaxInt64 {
		t.Fatal("intermediate overflow discarded a representable rate")
	}

	for _, tc := range []struct {
		name   string
		change func(*JobState, *upload.QueueJob, *upload.HTTPAttempt)
	}{
		{"job still active", func(j *JobState, _ *upload.QueueJob, _ *upload.HTTPAttempt) { j.Phase = "RUNNING" }},
		{"queue still active", func(_ *JobState, q *upload.QueueJob, _ *upload.HTTPAttempt) { q.Phase = "RUNNING" }},
		{"receipt missing", func(j *JobState, _ *upload.QueueJob, _ *upload.HTTPAttempt) { j.Receipt = nil }},
		{"failed attempt", func(_ *JobState, _ *upload.QueueJob, a *upload.HTTPAttempt) { a.Outcome = "FAILED" }},
		{"newer attempt", func(_ *JobState, q *upload.QueueJob, _ *upload.HTTPAttempt) { q.Attempts++ }},
		{"another plan", func(_ *JobState, _ *upload.QueueJob, a *upload.HTTPAttempt) { a.Plan = "wrong" }},
		{"another target", func(_ *JobState, _ *upload.QueueJob, a *upload.HTTPAttempt) { a.Target = "wrong" }},
		{"incomplete bodies", func(_ *JobState, _ *upload.QueueJob, a *upload.HTTPAttempt) { a.Counts.Incomplete = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			localJob, localQueue, localAttempt, localCounts := job, queue, attempt, counts
			localAttempt.Counts = &localCounts
			tc.change(&localJob, &localQueue, &localAttempt)
			if got := completedExternalTransfer(localJob, localQueue, localAttempt); got != nil {
				t.Fatalf("unproven attempt supplied a sample: %+v", got)
			}
		})
	}
}
