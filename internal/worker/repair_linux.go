package worker

import (
	"context"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

const repairNeedsFormat = "outpost-repair-needs-1"

type repairNeedsReply struct {
	Format     string                  `json:"format"`
	Domain     string                  `json:"domain"`
	Repository string                  `json:"repository"`
	Epoch      uint64                  `json:"epoch"`
	Rule       string                  `json:"rule"`
	Needs      []generation.RepairNeed `json:"needs"`
}

func validRepairNeeds(needs []generation.RepairNeed) bool {
	if len(needs) > generation.MaxGenerations {
		return false
	}
	seen := map[string]bool{}
	var previous uint64
	for _, need := range needs {
		if !storage.ID(need.Generation) || !storage.ID(need.Token) || need.Sequence <= previous || seen[need.Generation] {
			return false
		}
		seen[need.Generation] = true
		previous = need.Sequence
	}
	return true
}
func (w *Worker) repairNeeds(ctx context.Context, v *view, rule control.Replication) ([]generation.RepairNeed, error) {
	d, ok := v.cfg.DomainByID(rule.Domain)
	local := v.domains[rule.Domain]
	if !ok || local == nil || !rule.Repair || rule.Executor() != w.node {
		return nil, ErrDenied
	}
	if rule.Mode == "pull" {
		return local.replica.RepairNeeds(ctx)
	}
	raw, e := w.discoveryRequest(ctx, v, rule, "repair-needs")
	if e != nil {
		return nil, e
	}
	var reply repairNeedsReply
	if storage.Decode(raw, &reply, maxInventory) != nil || reply.Format != repairNeedsFormat || reply.Domain != rule.Domain || reply.Repository != d.Trust.Repository || reply.Epoch != d.Trust.Epoch || reply.Rule != rule.ID(d.Trust) || !validRepairNeeds(reply.Needs) {
		return nil, peer.ErrProtocol
	}
	return reply.Needs, nil
}
