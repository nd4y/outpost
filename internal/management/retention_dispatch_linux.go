package management

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const RetentionStepRequestFormat = "outpost-retention-step-request-1"
const maxRetentionStepsPerPlan = 128
const maxRetentionStepBytes = 96 << 10

var errRetentionStepWaiting = errors.New("retention step awaits prerequisite")

type RetentionStepRequest struct {
	Format  string          `json:"format"`
	Node    string          `json:"node"`
	Command command.Request `json:"command"`
}

type RetentionStepReceipt struct {
	Format          string `json:"format"`
	Plan            string `json:"planOperationId"`
	Operation       string `json:"operationId"`
	Actor           string `json:"actor"`
	RequestDigest   string `json:"requestDigest"`
	StagedUnix      int64  `json:"stagedUnix"`
	StagingRevision uint64 `json:"stagingRevision"`
}

type retentionStepRecord struct {
	Receipt RetentionStepReceipt `json:"receipt"`
	Input   RetentionStepRequest `json:"input"`
}

func validRetentionStepInput(input RetentionStepRequest) bool {
	if input.Format != RetentionStepRequestFormat || !storage.ID(input.Node) || !storage.ID(input.Command.Operation) ||
		!oneOf(input.Command.Kind, "maintenance", "retention") {
		return false
	}
	raw, e := json.Marshal(input)
	return e == nil && len(raw) <= maxRetentionStepBytes
}

func validateRetentionSteps(s registryState) error {
	if len(s.RetentionSteps) > maxOperations {
		return ErrInvalid
	}
	counts, revisions := map[string]int{}, map[uint64]bool{}
	for id, step := range s.RetentionSteps {
		receipt, input := step.Receipt, step.Input
		plan, exists := s.RetentionPlans[receipt.Plan]
		if !exists || !validRetentionStepInput(input) || receipt.Format != "outpost-retention-step-1" ||
			receipt.Operation != id || input.Command.Operation != id || input.Command.Tenant != plan.Plan.Tenant ||
			input.Command.Domain != plan.Trust.Domain || !storage.ID(receipt.Actor) ||
			receipt.RequestDigest != commandRequestDigest(Principal{Actor: receipt.Actor}, input.Node, input.Command) ||
			!validTime(receipt.StagedUnix) || receipt.StagedUnix > s.ObservedUnix ||
			receipt.StagingRevision <= plan.Plan.RegistrationRevision || receipt.StagingRevision > s.Revision ||
			revisions[receipt.StagingRevision] {
			return ErrInvalid
		}
		counts[receipt.Plan]++
		revisions[receipt.StagingRevision] = true
		if counts[receipt.Plan] > maxRetentionStepsPerPlan {
			return ErrInvalid
		}
		if o, exists := s.CommandOperations[id]; exists && (o.Node != input.Node || o.Receipt.RequestDigest != receipt.RequestDigest) {
			return ErrInvalid
		}
	}
	return nil
}

// StageRetentionStep records an exact owner-authorized request for the existing
// reconciler. It does not publish an envelope or report a worker effect.
func (r *Registry) StageRetentionStep(ctx context.Context, p Principal, tenant, domain, operation string, input RetentionStepRequest) (RetentionStepReceipt, error) {
	var out RetentionStepReceipt
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, domain) {
		return out, ErrDenied
	}
	req := input.Command
	if !storage.ID(tenant) || !storage.ID(domain) || !storage.ID(operation) || !validRetentionStepInput(input) ||
		req.Tenant != tenant || req.Domain != domain {
		return out, ErrInvalid
	}
	digest := commandRequestDigest(p, input.Node, req)
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		plan, ok := s.RetentionPlans[operation]
		if !ok || plan.Plan.Tenant != tenant || plan.Trust.Domain != domain {
			return ErrUnavailable
		}
		if old, exists := s.RetentionSteps[req.Operation]; exists {
			if old.Receipt.Plan != operation || old.Receipt.RequestDigest != digest {
				return ErrConflict
			}
			out = old.Receipt
			return nil
		}
		_, cmdUsed := s.CommandOperations[req.Operation]
		_, enrollUsed := s.Operations[req.Operation]
		_, configUsed := s.ConfigOperations[req.Operation]
		if cmdUsed || enrollUsed || configUsed || resolutionID(s, req.Operation) {
			return ErrConflict
		}
		if _, e = retentionStepBinding(plan, input); e != nil {
			return e
		}
		if _, _, e = r.admitCommandPolicy(ctx, s, p, tenant, input.Node, req); e != nil {
			return e
		}
		count := 0
		for _, step := range s.RetentionSteps {
			if step.Receipt.Plan == operation {
				count++
			}
		}
		if len(s.RetentionSteps) >= maxOperations || count >= maxRetentionStepsPerPlan {
			return ErrCapacity
		}
		out = RetentionStepReceipt{Format: "outpost-retention-step-1", Plan: operation, Operation: req.Operation,
			Actor: p.Actor, RequestDigest: digest, StagedUnix: time.Now().Unix(), StagingRevision: s.Revision + 1}
		if s.RetentionSteps == nil {
			s.RetentionSteps = make(map[string]retentionStepRecord)
		}
		s.RetentionSteps[req.Operation] = retentionStepRecord{Receipt: out, Input: input}
		if e = r.save(s); e != nil {
			return e
		}
		return r.point("management-retention-step-durable")
	})
	if e != nil {
		return RetentionStepReceipt{}, e
	}
	return out, nil
}

func retentionStepBinding(plan retentionPlanRecord, input RetentionStepRequest) (generation.RetentionProtection, error) {
	req, p := input.Command, plan.Plan.Request.Preview
	if req.Kind == "maintenance" {
		permit, e := generation.VerifyPermit(req.MaintenancePermit, plan.Trust)
		if e != nil || !plan.matches(req.Tenant, input.Node, req, permit) {
			return generation.RetentionProtection{}, ErrConflict
		}
		return generation.RetentionProtection{}, nil
	}
	grant, e := generation.VerifyRetentionProtection(req.RetentionGrant, plan.Trust, input.Node)
	if e != nil {
		return grant, ErrDenied
	}
	link := linkRetentionGrant(grant, req.RetentionGrant)
	if link == nil || link.Retirement != p.Operation || link.RetiringNode != p.Window.Node ||
		grant.Action != "CLOSE" && !slices.Contains(p.Retire, grant.Generation) ||
		grant.Action == "HOLD" && !slices.Contains(plan.Plan.Request.HoldCommands, req.Operation) {
		return grant, ErrConflict
	}
	return grant, nil
}

func (r *Registry) admitStagedRetentionStep(ctx context.Context, s registryState, step retentionStepRecord) error {
	plan, ok := s.RetentionPlans[step.Receipt.Plan]
	if !ok {
		return ErrInvalid
	}
	grant, e := retentionStepBinding(plan, step.Input)
	if e != nil {
		return e
	}
	p := plan.Plan.Request.Preview
	switch grant.Action {
	case "HOLD":
		now := time.Now()
		if p.Window.ExpiresUnix <= now.Unix() {
			return ErrConflict
		}
		f := s.Domains[p.Domain]
		_, cfg, domain, ok := r.retentionHolder(ctx, s, p.Window.Node, p.Domain, f, now)
		n, found := cfg.NodeByID(step.Input.Node)
		if !ok || !found || n.Class != "trusted" || !slices.Contains(domain.Placement.Holders, step.Input.Node) {
			return ErrDenied
		}
	case "CLOSE":
		if p.Window.ExpiresUnix <= time.Now().Unix() {
			return nil
		}
		var status RetentionPlanStatus
		if o, ok := s.CommandOperations[p.Operation]; ok {
			if e := r.readPlannedRetirement(s, plan, o, &status); e != nil {
				return e
			}
		}
		if !status.CloseRequired {
			return errRetentionStepWaiting
		}
	case "RELEASE":
		return r.admitStagedRetentionRelease(s, plan, step.Input.Node, grant)
	}
	return nil
}

func (r *Registry) admitStagedRetentionRelease(s registryState, plan retentionPlanRecord, node string, grant generation.RetentionProtection) error {
	actions, e := r.planActions(s, plan)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(grant.Closure)
	digest := storage.Hash(raw)
	held, closed := false, false
	for _, a := range actions {
		held = held || a.link.Action == "HOLD" && a.op.Node == node && a.link.HoldDigest == grant.HoldDigest
		if a.link.Action != "CLOSE" || a.op.Receipt.State != "COMPLETE" {
			continue
		}
		envelope, _, e := r.readCommand(a.op)
		if e != nil {
			return e
		}
		ack, e := command.VerifyAck(a.op.Acknowledgement, envelope, r.owner, a.op.NodeKey, time.Now())
		if e != nil {
			return e
		}
		closed = closed || ack.State == "COMPLETE" && ack.ResultDigest == digest
	}
	if !held || !closed {
		return errRetentionStepWaiting
	}
	return nil
}
