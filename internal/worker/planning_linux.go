package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

func planningPin(j control.Job) string {
	return storage.Hash([]byte("outpost-upload-planning-1/" + j.Operation + "/" + j.Executor))
}
func (w *Worker) planUpload(ctx context.Context, v *view, j control.Job, source *generation.Replica) ([]byte, error) {
	if !v.autonomy.Permits(j) {
		return nil, ErrDenied
	}
	grant, _, ok := v.cfg.UploadDelegation(j.Delegation)
	d, domain := v.cfg.DomainByID(j.Domain)
	if !ok || !domain {
		return nil, ErrDenied
	}
	a := upload.Authority{Generation: d.Trust, Planner: d.Planner}
	// This pin survives a crash before queue admission. The queue takes its own
	// independent durable pin before this planning pin can be released.
	if e := source.Pin(ctx, planningPin(j), j.Generation, "generation"); e != nil {
		return nil, e
	}
	if e := w.point("upload-planning-pin-durable"); e != nil {
		return nil, e
	}
	name := "upload-plan-" + j.Operation + ".json"
	var raw []byte
	e := w.state.WithLock(ctx, func() error { var e error; raw, e = w.state.Read(name); return e })
	if errors.Is(e, os.ErrNotExist) {
		if j.MissingRepair == nil {
			raw, e = upload.BuildDerivedCached(ctx, source, j.Generation, grant, a, &upload.PlanningCache{Store: w.state, Fault: w.point})
		} else {
			original := "upload-plan-" + upload.DelegatedOperation(grant, j.Generation) + ".json"
			var retained []byte
			e = w.state.WithLock(ctx, func() error { var e error; retained, e = w.state.Read(original); return e })
			if errors.Is(e, os.ErrNotExist) {
				return nil, ErrDenied
			}
			if e == nil {
				raw, e = upload.DeriveMissingRepair(retained, a, *j.MissingRepair)
			}
		}
		if e != nil {
			return nil, e
		}
		e = w.state.WithLock(ctx, func() error {
			old, e := w.state.Read(name)
			if e == nil {
				if !bytes.Equal(old, raw) {
					return upload.ErrConflict
				}
				return nil
			}
			if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			return w.state.Write(name, raw)
		})
	}
	if e != nil {
		return nil, e
	}
	p, e := upload.Verify(raw, a)
	if e != nil || p.Format != upload.DerivedFormat || p.Operation != j.Operation || p.Generation != j.Generation || p.Profile.ID() != j.Target || !bytes.Equal(p.Delegation, grant) {
		return nil, upload.ErrDenied
	}
	if e = w.point("upload-plan-durable"); e != nil {
		return nil, e
	}
	return raw, ctx.Err()
}

func (w *Worker) discoverUploads(v *view) error {
	for _, grant := range v.cfg.Uploads {
		if v.ctx.Err() != nil {
			return nil
		}
		id := storage.Hash(grant)
		raw, g, ok := v.cfg.UploadDelegation(id)
		if !ok {
			v.cancel()
			return ErrDenied
		}
		if v.paused(g.Trust.Domain, "") {
			continue
		}
		ctx, cancel := context.WithTimeout(v.ctx, time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond)
		local := v.domains[g.Trust.Domain]
		var entries []generation.InventoryEntry
		var e error
		if local == nil {
			e = ErrDenied
		} else {
			entries, e = local.replica.Inventory(ctx)
		}
		if e == nil {
			jobs := make([]control.Job, 0, len(entries))
			for _, entry := range entries {
				jobs = append(jobs, control.UploadJob(raw, g, entry.Generation, w.node))
			}
			e = w.admitDerived(ctx, v, jobs)
		}
		cancel()
		if v.ctx.Err() != nil {
			return nil
		}
		if e = w.recordDiscoveryID(v.ctx, v, id, len(entries), e); e != nil {
			v.cancel()
			return e
		}
	}
	return nil
}
