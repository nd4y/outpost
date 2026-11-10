package worker

import (
	"context"
	"encoding/json"
	"time"

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
	p, e := v.cfg.MaintenancePermit(env.Request)
	if e != nil {
		return nil, e
	}
	if p.Window != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Unix(p.Window.ExpiresUnix, 0))
		defer cancel()
	}
	admit := func() error { return w.actionPolicy(ctx, v, env) }
	if _, e := local.replica.MaintainOnNode(ctx, env.Request.MaintenancePermit, w.node, admit); e != nil {
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
