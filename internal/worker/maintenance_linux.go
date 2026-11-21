package worker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
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
	admit := func() error {
		// The envelope pins the exact signed configuration. Recheck that
		// configuration and command authority without rehashing every
		// survivor's signature for each removed object.
		return w.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, raw []byte) error {
			if cfg.Revision != v.cfg.Revision {
				return ErrDenied
			}
			now := time.Now()
			if e := w.commandAdmission(cfg, raw, env, now); e != nil {
				return e
			}
			if p.Window != nil && now.Unix() >= p.Window.ExpiresUnix {
				return generation.ErrMaintenanceWindow
			}
			return nil
		})
	}
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
