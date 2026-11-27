package management

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/storage"
)

type VerifiedRestore struct {
	Operation          string              `json:"operationId"`
	Generation         string              `json:"generation"`
	Target             string              `json:"target"`
	VerifiedUnix       int64               `json:"verifiedUnix"`
	Scope              string              `json:"scope"`
	LogicalMeasurement *LogicalMeasurement `json:"logicalMeasurement,omitempty"`
}

type LogicalMeasurement struct {
	Operation    string `json:"operationId"`
	LogicalBytes int64  `json:"logicalBytes,string"`
	MeasuredUnix int64  `json:"measuredUnix"`
}

func updateVerifiedRestore(previous, current VerifiedRestore, restoredBytes int64) VerifiedRestore {
	measurement := previous.LogicalMeasurement
	if current.Scope == "WHOLE_GENERATION" && (measurement == nil || current.VerifiedUnix >= measurement.MeasuredUnix) {
		measurement = &LogicalMeasurement{Operation: current.Operation, LogicalBytes: restoredBytes, MeasuredUnix: current.VerifiedUnix}
	}
	if current.VerifiedUnix < previous.VerifiedUnix ||
		current.VerifiedUnix == previous.VerifiedUnix && previous.Scope == "WHOLE_GENERATION" && current.Scope != "WHOLE_GENERATION" {
		current = previous
	}
	current.LogicalMeasurement = measurement
	return current
}

// verifiedRestores projects original evidence from the same locked report view.
// Selection comes from the verified command, never from restored file counts.
func (r *Registry) verifiedRestores(ctx context.Context, state registryState, report Report) []VerifiedRestore {
	verified := make([]VerifiedRestore, 0)
	if len(report.Commands) == 0 || len(report.Generations) == 0 {
		return verified
	}
	local := make(map[string]uint64, len(report.Generations))
	for _, generation := range report.Generations {
		if generation.Target == report.Node && generation.MetadataState != "UNAVAILABLE" {
			local[generation.Generation] = generation.Sequence
		}
	}
	now := time.Now()
	latest := make(map[string]VerifiedRestore, len(local))
	for _, observation := range report.Commands {
		if ctx.Err() != nil {
			return nil
		}
		result := observation.Restore
		sequence, found := local[observation.Generation]
		previous := latest[observation.Generation]
		if !found || observation.Kind != "restore" || observation.Phase != "COMPLETE" ||
			result == nil || result.Restored.Sequence != sequence {
			continue
		}
		if measurement := previous.LogicalMeasurement; measurement != nil &&
			observation.VerifiedUnix < previous.VerifiedUnix && observation.VerifiedUnix < measurement.MeasuredUnix {
			continue
		}
		operation, found := state.CommandOperations[observation.Operation]
		if !found || operation.Receipt.State != "COMPLETE" || operation.Node != report.Node ||
			operation.Audit.Tenant != report.Tenant || operation.Audit.Domain != report.Domain ||
			operation.Envelope != observation.EnvelopeDigest {
			continue
		}
		raw, envelope, err := r.readCommand(operation)
		if err != nil || envelope.Request.Kind != "restore" ||
			envelope.Request.Generation != observation.Generation || envelope.Request.Preset != result.Preset {
			continue
		}
		ack, err := command.VerifyAck(operation.Acknowledgement, raw, r.owner, operation.NodeKey, now)
		if err != nil || ack.State != "COMPLETE" || ack.StartedUnix != observation.StartedUnix ||
			ack.ObservedUnix != observation.FinishedUnix || ack.ResultDigest != observation.ResultDigest {
			continue
		}
		payload, err := json.Marshal(result)
		if err != nil || storage.Hash(payload) != ack.ResultDigest {
			continue
		}
		scope := "WHOLE_GENERATION"
		if len(envelope.Request.Versions) != 0 {
			scope = "SELECTED_VERSIONS"
		}
		current := VerifiedRestore{
			Operation: observation.Operation, Generation: observation.Generation, Target: report.Node,
			VerifiedUnix: result.VerifiedUnix, Scope: scope,
		}
		latest[observation.Generation] = updateVerifiedRestore(previous, current, result.Restored.Restored.Bytes)
	}
	for _, generation := range report.Generations {
		if result, ok := latest[generation.Generation]; ok && generation.Target == result.Target {
			verified = append(verified, result)
		}
	}
	return verified
}
