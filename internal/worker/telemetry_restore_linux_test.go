package worker

import (
	"testing"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/telemetry"
)

func TestWorkerRestoreFailureMetricsRequireObservedTerminalCommands(t *testing.T) {
	const observed = 1800000000
	oldFailure := int64(observed - 20)
	lastFailure := int64(observed - 10)
	snapshot := management.Snapshot{ObservedUnix: observed}
	check := func(wantCount, wantFinished *int64) {
		t.Helper()
		var record telemetry.Record
		appendRestoreFailureMetrics(&record, snapshot)
		if len(record.Metrics) != 2 {
			t.Fatalf("unexpected restore failure metrics: %+v", record.Metrics)
		}
		for i, want := range []struct {
			name  string
			value *int64
		}{
			{"restore_command_failures_retained", wantCount},
			{"restore_last_failure_timestamp_seconds", wantFinished},
		} {
			got := record.Metrics[i]
			if got.Name != want.name || got.Target != "" || (got.Value == nil) != (want.value == nil) ||
				got.Value != nil && *got.Value != *want.value {
				t.Fatalf("wrong restore failure metric at %d: %+v", i, got)
			}
		}
	}
	check(nil, nil)
	snapshot.RestoreCommandsObserved = true
	check(nil, nil)
	snapshot.Commands = []management.CommandObservation{
		{Kind: "restore", Phase: "RETRY_WAIT"},
		{Kind: "restore", Phase: "COMPLETE", FinishedUnix: observed},
		{Kind: "scrub", Phase: "FAILED", FinishedUnix: observed},
	}
	zero := int64(0)
	check(&zero, nil)

	snapshot.Commands = append(snapshot.Commands,
		management.CommandObservation{Kind: "restore", Phase: "FAILED", FinishedUnix: lastFailure},
		management.CommandObservation{Kind: "restore", Phase: "FAILED", FinishedUnix: oldFailure},
	)
	two := int64(2)
	check(&two, &lastFailure)
	snapshot.ObservedUnix++
	check(&two, &lastFailure)
}
