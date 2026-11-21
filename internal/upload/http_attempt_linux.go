package upload

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

// HTTPAttempt is a local observation of one queue attempt. It is separate
// from the upload receipt and cannot certify a backup or release a pin.
type HTTPAttempt struct {
	Node           string                  `json:"node"`
	Domain         string                  `json:"domain"`
	Target         string                  `json:"target"`
	Operation      string                  `json:"operation"`
	Plan           string                  `json:"plan"`
	Attempt        uint64                  `json:"attempt"`
	StartedMillis  int64                   `json:"startedMillis"`
	FinishedMillis int64                   `json:"finishedMillis,omitempty"`
	Outcome        string                  `json:"outcome"`
	Counts         *storage.HTTPBodyCounts `json:"counts,omitempty"`
}

func (a HTTPAttempt) Valid(now time.Time) bool {
	if !storage.ID(a.Node) || !storage.ID(a.Domain) || !storage.ID(a.Target) || !storage.ID(a.Operation) || !storage.ID(a.Plan) || a.Attempt == 0 || a.StartedMillis < 1 || a.StartedMillis > now.UnixMilli() {
		return false
	}
	if a.Outcome == "STARTED" {
		return a.FinishedMillis == 0 && a.Counts == nil
	}
	return (a.Outcome == "SUCCEEDED" || a.Outcome == "FAILED") && a.FinishedMillis >= a.StartedMillis && a.FinishedMillis <= now.UnixMilli() && a.Counts != nil && a.Counts.Valid()
}

func (q *Queue) startHTTPAttempt(ctx context.Context, op string, job QueueJob, profile storage.Profile) (context.Context, func(error)) {
	if q.ObserveHTTPAttempt == nil {
		return ctx, func(error) {}
	}
	ctx, meter := storage.WithHTTPMeter(ctx, profile)
	observation := HTTPAttempt{
		Node: q.worker, Domain: q.authority.Generation.Domain, Target: profile.ID(), Operation: op,
		Plan: storage.Hash(job.Plan), Attempt: job.Attempts + 1, StartedMillis: time.Now().UnixMilli(), Outcome: "STARTED",
	}
	write := func() {
		// A cancelled transfer may still have a meaningful local observation.
		// The observer receives no credentials and uses a separate local budget.
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 150*time.Millisecond)
		defer cancel()
		q.ObserveHTTPAttempt(bounded, observation)
	}
	write()
	return ctx, func(result error) {
		counts := meter.Snapshot()
		observation.Counts = &counts
		observation.FinishedMillis = time.Now().UnixMilli()
		observation.Outcome = "SUCCEEDED"
		if result != nil {
			observation.Outcome = "FAILED"
		}
		write()
	}
}
