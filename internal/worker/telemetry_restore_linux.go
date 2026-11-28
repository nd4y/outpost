package worker

import (
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/telemetry"
)

func appendRestoreFailureMetrics(record *telemetry.Record, snapshot management.Snapshot) {
	var retained, latest int64
	var count, finished *int64
	if snapshot.RestoreCommandsObserved && snapshot.Commands != nil {
		for _, op := range snapshot.Commands {
			if op.Kind == "restore" && op.Phase == "FAILED" {
				retained++
				latest = max(latest, op.FinishedUnix)
			}
		}
		count = &retained
		if retained > 0 {
			finished = &latest
		}
	}
	record.Metrics = append(record.Metrics,
		telemetry.Metric{Name: "restore_command_failures_retained", Value: count},
		telemetry.Metric{Name: "restore_last_failure_timestamp_seconds", Value: finished},
	)
}
