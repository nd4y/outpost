package management

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const maxRetentionPlanHoldCommands = 128

type retentionCommandLink struct {
	Action       string `json:"action"`
	Retirement   string `json:"retirement"`
	RetiringNode string `json:"retiringNode"`
	Repository   string `json:"repository"`
	Epoch        uint64 `json:"epoch"`
	GrantDigest  string `json:"grantDigest"`
	HoldDigest   string `json:"holdDigest,omitempty"`
}

func linkRetentionGrant(g generation.RetentionProtection, raw []byte) *retentionCommandLink {
	l := retentionCommandLink{Action: g.Action, Repository: g.Repository, Epoch: g.Epoch, GrantDigest: storage.Hash(raw)}
	if g.Action == "CLOSE" {
		l.Retirement, l.RetiringNode = g.Operation, g.Node
		return &l
	}
	if g.Retirement == nil {
		return nil
	}
	l.Retirement, l.RetiringNode = g.Retirement.Operation, g.Retirement.Node
	l.HoldDigest = g.HoldDigest
	if g.Action == "HOLD" {
		l.HoldDigest = l.GrantDigest
	}
	return &l
}

func (l retentionCommandLink) valid(o commandOperation) bool {
	if o.Audit.Action != "COMMAND_RETENTION" || !storage.ID(l.Retirement) || !storage.ID(l.RetiringNode) ||
		!storage.ID(l.Repository) || l.Epoch == 0 || !storage.ID(l.GrantDigest) {
		return false
	}
	switch l.Action {
	case "CLOSE":
		return o.Node == l.RetiringNode && l.HoldDigest == ""
	case "HOLD":
		return o.Node != l.RetiringNode && l.HoldDigest == l.GrantDigest
	case "RELEASE":
		return o.Node != l.RetiringNode && storage.ID(l.HoldDigest)
	default:
		return false
	}
}

func (l retentionCommandLink) matches(o commandOperation, tenant string, p generation.Permit) bool {
	return o.Audit.Tenant == tenant && o.Audit.Domain == p.Domain && l.Retirement == p.Operation &&
		l.RetiringNode == p.Window.Node && l.Repository == p.Repository && l.Epoch == p.Epoch
}

func hasPlannedClose(s registryState, tenant string, p generation.Permit) bool {
	for _, o := range s.CommandOperations {
		l := o.Retention
		if l != nil && l.Action == "CLOSE" && l.matches(o, tenant, p) {
			return true
		}
	}
	return false
}

func admitRetentionLink(s registryState, node string, input command.Request, grant generation.RetentionProtection) error {
	l := linkRetentionGrant(grant, input.RetentionGrant)
	if l == nil {
		return nil
	}
	plan, exists := s.RetentionPlans[l.Retirement]
	if !exists {
		return nil
	}
	p := plan.Plan.Request.Preview
	if input.Tenant != plan.Plan.Tenant || input.Domain != p.Domain || l.RetiringNode != p.Window.Node {
		return ErrConflict
	}
	if _, e := generation.VerifyRetentionProtection(input.RetentionGrant, plan.Trust, node); e != nil {
		return ErrConflict
	}
	_, known := s.CommandOperations[input.Operation]
	if known || l.Action != "HOLD" {
		return nil
	}
	count, closing, sameHold := 0, false, false
	for _, o := range s.CommandOperations {
		old := o.Retention
		if old == nil || !old.matches(o, input.Tenant, p) {
			continue
		}
		if old.Action == "HOLD" {
			count++
		}
		closing = closing || old.Action == "CLOSE"
		sameHold = sameHold || old.Action == "HOLD" && old.HoldDigest == l.HoldDigest && o.Node == node
	}
	if closing && !sameHold {
		return ErrConflict
	}
	if count >= maxRetentionPlanHoldCommands {
		return ErrCapacity
	}
	return nil
}

type RetentionActionProof struct {
	Command      string `json:"commandOperationId"`
	Node         string `json:"node"`
	Digest       string `json:"digest"`
	ObservedUnix int64  `json:"observedUnix"`
	Proof        []byte `json:"proof"`
}

type RetentionHoldStatus struct {
	Node       string                `json:"node"`
	HoldDigest string                `json:"holdDigest"`
	State      string                `json:"state"`
	Release    *RetentionActionProof `json:"release,omitempty"`
}

type plannedRetentionAction struct {
	op   commandOperation
	link retentionCommandLink
}

func (r *Registry) planActions(s registryState, record retentionPlanRecord) ([]plannedRetentionAction, error) {
	plan, p := record.Plan, record.Plan.Request.Preview
	actions := []plannedRetentionAction{}
	for _, o := range s.CommandOperations {
		if l := o.Retention; l != nil && l.matches(o, plan.Tenant, p) {
			actions = append(actions, plannedRetentionAction{o, *l})
		}
	}
	// Plans created by older binaries named their holds without an index.
	for _, id := range plan.Request.HoldCommands {
		o, ok := s.CommandOperations[id]
		if !ok || o.Retention != nil || o.Audit.Action != "COMMAND_RETENTION" || o.Audit.Tenant != plan.Tenant || o.Audit.Domain != p.Domain {
			continue
		}
		req, _, e := r.commandRequest(o)
		if e != nil {
			return nil, e
		}
		var grant generation.RetentionProtection
		if json.Unmarshal(req.RetentionGrant, &grant) != nil {
			return nil, ErrInvalid
		}
		if l := linkRetentionGrant(grant, req.RetentionGrant); l != nil && l.Action == "HOLD" && l.matches(o, plan.Tenant, p) {
			actions = append(actions, plannedRetentionAction{o, *l})
		}
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].op.Receipt.Operation < actions[j].op.Receipt.Operation })
	return actions, nil
}

func (r *Registry) reconcileRetentionSettlement(ctx context.Context, s registryState, record retentionPlanRecord, out *RetentionPlanStatus) (bool, error) {
	actions, e := r.planActions(s, record)
	if e != nil {
		return false, e
	}
	reports := map[string]map[string]CommandObservation{}
	requested := map[string]bool{}
	for _, a := range actions {
		requested[a.op.Receipt.Operation] = true
	}
	proof := func(a plannedRetentionAction) (generation.RetentionProtection, RetentionActionProof, bool) {
		o := a.op
		if o.Receipt.State != "COMPLETE" || ctx.Err() != nil {
			return generation.RetentionProtection{}, RetentionActionProof{}, false
		}
		items, seen := reports[o.Node]
		if !seen {
			items = map[string]CommandObservation{}
			report, _, e := r.readReport(s, o.Node, record.Trust.Domain)
			if e == nil && report.Tenant == record.Plan.Tenant {
				for _, c := range report.Commands {
					if c.Kind == "retention" && c.Phase == "COMPLETE" && requested[c.Operation] {
						items[c.Operation] = c
					}
				}
			}
			reports[o.Node] = items
		}
		c, found := items[o.Receipt.Operation]
		if !found {
			return generation.RetentionProtection{}, RetentionActionProof{}, false
		}
		grant, receipt, valid := r.confirmedRetentionProof(o, c, record.Trust, time.Now())
		if !valid || grant.Action != a.link.Action || receipt.GrantDigest != a.link.GrantDigest || receipt.HoldDigest != a.link.HoldDigest {
			return grant, RetentionActionProof{}, false
		}
		return grant, RetentionActionProof{Command: c.Operation, Node: o.Node, Digest: c.ResultDigest, ObservedUnix: receipt.ObservedUnix, Proof: c.RetentionProof}, true
	}
	closing := false
	for _, a := range actions {
		if a.link.Action != "CLOSE" {
			continue
		}
		closing = true
		_, p, ok := proof(a)
		if !ok {
			continue
		}
		if out.Closure != nil && out.Closure.Digest != p.Digest {
			return false, ErrConflict
		}
		out.Closure = &p
	}
	if e = ctx.Err(); e != nil {
		return false, e
	}
	if out.Closure == nil {
		if closing {
			out.State, out.CloseRequired = "CLOSURE_PENDING", true
		}
		return closing, nil
	}
	holds := map[string]RetentionHoldStatus{}
	for _, a := range actions {
		if a.link.Action != "HOLD" {
			continue
		}
		h, seen := holds[a.link.HoldDigest]
		if !seen {
			h = RetentionHoldStatus{Node: a.op.Node, HoldDigest: a.link.HoldDigest, State: "HOLD_UNCONFIRMED"}
		}
		if h.State == "HOLD_UNCONFIRMED" {
			if _, _, ok := proof(a); ok {
				h.State = "HELD"
			}
		}
		holds[h.HoldDigest] = h
	}
	for _, a := range actions {
		if a.link.Action != "RELEASE" {
			continue
		}
		h, found := holds[a.link.HoldDigest]
		if !found || h.Node != a.op.Node || h.Release != nil {
			continue
		}
		g, p, ok := proof(a)
		if !ok {
			continue
		}
		raw, _ := json.Marshal(g.Closure)
		if storage.Hash(raw) != out.Closure.Digest {
			continue
		}
		h.State, h.Release = "RELEASED", &p
		holds[h.HoldDigest] = h
	}
	if e = ctx.Err(); e != nil {
		return false, e
	}
	out.State, out.CloseRequired = "SETTLED", false
	for _, hold := range holds {
		if hold.Release == nil {
			out.State = "CLOSED_AWAITING_RELEASES"
		}
		out.Holds = append(out.Holds, hold)
	}
	sort.Slice(out.Holds, func(i, j int) bool { return out.Holds[i].HoldDigest < out.Holds[j].HoldDigest })
	return true, nil
}
