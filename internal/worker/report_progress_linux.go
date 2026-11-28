package worker

import (
	"context"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

const uploadProgressReadWindow = 200 * time.Millisecond

func uploadProgressBinding(cfg control.Config, job JobState) (upload.ProgressBinding, bool) {
	j := job.Job
	_, target := cfg.TargetByID(j.Target)
	domain, admitted := cfg.DomainByID(j.Domain)
	if job.Phase != "RUNNING" || j.Kind != "upload" || j.Executor != cfg.Node || !admitted || !target ||
		!domain.Placement.PermitsCloud(cfg.Node, j.Target) || j.MissingRepair != nil {
		return upload.ProgressBinding{}, false
	}
	out := upload.ProgressBinding{Operation: j.Operation, Generation: j.Generation, Target: j.Target}
	if j.Delegation != "" {
		if job.Binding != binding(j) || !cfg.AutonomousUpload(j) {
			return upload.ProgressBinding{}, false
		}
		out.Delegation = j.Delegation
		return out, true
	}
	for _, declared := range cfg.Jobs {
		if declared.Operation == j.Operation && binding(declared) == job.Binding &&
			declared.Kind == "upload" && declared.Domain == j.Domain && declared.Executor == j.Executor &&
			declared.Generation == j.Generation && declared.Target == j.Target {
			out.Plan = storage.Hash(declared.Plan)
			return out, true
		}
	}
	return upload.ProgressBinding{}, false
}

func (w *Worker) observeUploadProgress(ctx context.Context, cfg control.Config, domain control.Domain, status Status, reports []management.Job) {
	if cfg.Active(time.Now()) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, uploadProgressReadWindow)
	defer cancel()
	authority := upload.Authority{Generation: domain.Trust, Planner: domain.Planner}
	probes := 0
	for i := range reports {
		if probes >= cfg.Limits.Parallel || ctx.Err() != nil {
			return
		}
		if reports[i].Kind != "UPLOAD" || reports[i].Phase != "RUNNING" {
			continue
		}
		j := status.Jobs[reports[i].Operation]
		selected, ok := uploadProgressBinding(cfg, j)
		if !ok {
			continue
		}
		probes++
		if w.check(ctx) != nil {
			return
		}
		dir := w.relative(filepath.Join(DomainDirectory(w.dir, domain.Trust), "uploads", selected.Operation))
		progress, err := upload.ObserveProgressAt(ctx, w.root, dir, w.node, authority, externalQueueLimits, selected)
		if err != nil || w.check(ctx) != nil {
			continue
		}
		reports[i].CompletedBytes, reports[i].TotalBytes = &progress.ConfirmedBytes, &progress.PlanBytes
	}
}
