package worker

import (
	"context"
	"encoding/json"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
)

type MaintenanceReceipt struct {
	Kind   string                        `json:"kind"`
	Result generation.MaintenanceReceipt `json:"result"`
}

func (w *Worker) executeMaintenance(ctx context.Context, v *view, env command.Envelope) ([]byte, error) {
	local := v.domains[env.Request.Domain]
	if local == nil {
		return nil, ErrDenied
	}
	if _, e := v.cfg.MaintenancePermit(env.Request); e != nil {
		return nil, e
	}
	admit := func() error { return w.actionPolicy(ctx, v, env) }
	if _, e := local.replica.MaintainAdmitted(ctx, env.Request.MaintenancePermit, admit); e != nil {
		return nil, e
	}
	if e := w.point("worker-command-maintenance-result-durable"); e != nil {
		return nil, e
	}
	if e := admit(); e != nil {
		return nil, e
	}
	result, e := local.replica.MaintenanceResult(ctx, env.Request.Operation)
	if e != nil {
		return nil, e
	}
	return json.Marshal(MaintenanceReceipt{Kind: "maintenance", Result: result})
}
