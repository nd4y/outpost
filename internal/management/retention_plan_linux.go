package management

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const RetentionPlanRequestFormat = "outpost-retention-plan-request-1"
const maxRetentionPlans = 128

type RetentionPlan struct {
	Format               string                `json:"format"`
	Tenant               string                `json:"tenant"`
	Actor                string                `json:"actor"`
	RegisteredUnix       int64                 `json:"registeredUnix"`
	RegistrationRevision uint64                `json:"registrationRevision"`
	Request              RetentionDraftRequest `json:"request"`
}

type retentionPlanRecord struct {
	Plan  RetentionPlan    `json:"plan"`
	Trust generation.Trust `json:"trust"`
}

type RetentionPlanStatus struct {
	Format           string          `json:"format"`
	State            string          `json:"state"`
	Authorization    string          `json:"authorization"`
	RegistryRevision uint64          `json:"registryRevision"`
	Plan             RetentionPlan   `json:"plan"`
	Draft            *RetentionDraft `json:"draft,omitempty"`
	Retirement       *Receipt        `json:"retirement,omitempty"`
	CloseRequired    bool            `json:"closeRequired"`
}

func validateRetentionPlans(s registryState) error {
	if len(s.RetentionPlans) > maxRetentionPlans {
		return ErrInvalid
	}
	for id, record := range s.RetentionPlans {
		p, t := record.Plan, record.Trust
		d := p.Request.Preview
		if _, used := s.Operations[id]; used {
			return ErrInvalid
		}
		if _, used := s.ConfigOperations[id]; used {
			return ErrInvalid
		}
		if p.Format != "outpost-retention-plan-1" || id != d.Operation || !storage.ID(p.Tenant) || !storage.ID(p.Actor) ||
			p.RegistrationRevision == 0 || p.RegistrationRevision > s.Revision || !validTime(p.RegisteredUnix) || p.RegisteredUnix > s.ObservedUnix ||
			t.Domain != d.Domain || t.Repository != d.Repository || t.Epoch != d.Epoch ||
			len(t.Writer) != ed25519.PublicKeySize || len(t.Maintenance) != ed25519.PublicKeySize ||
			!validRetentionDraftInput(p.Request, t.Domain, RetentionPlanRequestFormat) {
			return ErrInvalid
		}
	}
	return nil
}

// RegisterRetentionPlan saves the immutable intended operation. No commands
// are sent by registration or by the status endpoint.
func (r *Registry) RegisterRetentionPlan(ctx context.Context, p Principal, tenant, domain string, input RetentionDraftRequest) (RetentionPlan, error) {
	var out RetentionPlan
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, domain) {
		return out, ErrDenied
	}
	if !storage.ID(tenant) || !storage.ID(domain) || !validRetentionDraftInput(input, domain, RetentionPlanRequestFormat) {
		return out, ErrInvalid
	}
	permit := input.Preview
	raw, _ := json.Marshal(input)
	digest := storage.Hash(raw)
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		if saved, exists := s.RetentionPlans[permit.Operation]; exists {
			prior, _ := json.Marshal(saved.Plan.Request)
			if saved.Plan.Tenant != tenant || saved.Trust.Domain != domain || storage.Hash(prior) != digest {
				return ErrConflict
			}
			out = saved.Plan
			return nil
		}
		_, commandUsed := s.CommandOperations[permit.Operation]
		_, enrollmentUsed := s.Operations[permit.Operation]
		_, configurationUsed := s.ConfigOperations[permit.Operation]
		now := time.Now()
		if commandUsed || enrollmentUsed || configurationUsed || resolutionID(s, permit.Operation) || permit.Window.ExpiresUnix <= now.Unix() {
			return ErrConflict
		}
		f, ok := s.Domains[domain]
		if !ok || f.Tenant != tenant {
			return ErrUnavailable
		}
		_, cfg, target, ok := r.retentionHolder(ctx, s, permit.Window.Node, domain, f, now)
		if !ok || target.RetirementMinimumCopies == 0 || permit.Repository != f.Repository || permit.Epoch != f.Epoch ||
			permit.Window.StartUnix >= cfg.ExpiresUnix || len(permit.Retire)*target.RetirementMinimumCopies > 64 {
			return ErrDenied
		}
		if len(s.RetentionPlans) >= maxRetentionPlans {
			return ErrCapacity
		}
		out = RetentionPlan{Format: "outpost-retention-plan-1", Tenant: tenant, Actor: p.Actor,
			RegisteredUnix: now.Unix(), RegistrationRevision: s.Revision + 1, Request: input}
		if s.RetentionPlans == nil {
			s.RetentionPlans = make(map[string]retentionPlanRecord)
		}
		s.RetentionPlans[permit.Operation] = retentionPlanRecord{Plan: out, Trust: target.Trust}
		if e = r.save(s); e != nil {
			return e
		}
		return r.point("management-retention-plan-durable")
	})
	if e != nil {
		return RetentionPlan{}, e
	}
	return out, nil
}

func (r *Registry) RetentionPlanStatus(ctx context.Context, p Principal, tenant, domain, operation string, maxAge time.Duration) (RetentionPlanStatus, error) {
	var out RetentionPlanStatus
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, domain) {
		return out, ErrDenied
	}
	if !storage.ID(tenant) || !storage.ID(domain) || !storage.ID(operation) || maxAge < time.Second || maxAge > 24*time.Hour {
		return out, ErrInvalid
	}
	s, e := r.retentionState(ctx)
	if e != nil {
		return out, e
	}
	record, ok := s.RetentionPlans[operation]
	if !ok || record.Plan.Tenant != tenant || record.Trust.Domain != domain {
		return out, ErrUnavailable
	}
	out = RetentionPlanStatus{Format: "outpost-retention-plan-status-1", Authorization: "NONE", RegistryRevision: s.Revision, Plan: record.Plan}
	if o, found := s.CommandOperations[operation]; found {
		e = r.readPlannedRetirement(s, record, o, &out)
		if e != nil {
			return RetentionPlanStatus{}, e
		}
	} else if record.Plan.Request.Preview.Window.ExpiresUnix <= time.Now().Unix() {
		out.State, out.CloseRequired = "WINDOW_EXPIRED", true
	} else {
		draft, e := r.prepareRetentionDraft(ctx, s, tenant, domain, record.Plan.Request, &record.Trust, maxAge)
		switch {
		case e == nil:
			out.State = "WAITING_FOR_HOLDS"
			if draft.Permit != nil {
				out.State = "READY_TO_SIGN"
			}
			out.Draft = &draft
			return out, nil
		case errors.Is(e, ErrDenied), errors.Is(e, ErrUnavailable):
			out.State = "POLICY_BLOCKED"
		default:
			return RetentionPlanStatus{}, e
		}
	}
	if e = r.checkRetentionRevision(ctx, s.Revision); e != nil {
		return RetentionPlanStatus{}, e
	}
	return out, nil
}

func (record retentionPlanRecord) matches(tenant, node string, req command.Request, permit generation.Permit) bool {
	p := record.Plan.Request.Preview
	return tenant == record.Plan.Tenant && node == p.Window.Node && req.Domain == p.Domain && req.Operation == p.Operation &&
		req.Kind == "maintenance" && permit.Format == generation.RetentionPermitFormat && permit.Domain == p.Domain &&
		permit.Repository == p.Repository && permit.Epoch == p.Epoch && permit.Operation == p.Operation && permit.Revision == p.Revision &&
		permit.Window != nil && *permit.Window == *p.Window && slices.Equal(permit.Retire, p.Retire)
}

func (r *Registry) readPlannedRetirement(s registryState, plan retentionPlanRecord, o commandOperation, out *RetentionPlanStatus) error {
	req, _, e := r.commandRequest(o)
	if e != nil {
		return e
	}
	permit, e := generation.VerifyPermit(req.MaintenancePermit, plan.Trust)
	if e != nil || !plan.matches(o.Audit.Tenant, o.Node, req, permit) {
		out.State = "COMMAND_CONFLICT"
		return nil
	}
	out.Retirement = &o.Receipt
	if resolved(s, req.Operation) {
		out.State, out.CloseRequired = "RETIREMENT_EFFECT_UNCONFIRMED", true
		return nil
	}
	expired := min(req.ExpiresUnix, permit.Window.ExpiresUnix) <= time.Now().Unix()
	if o.Envelope == "" {
		out.State, out.CloseRequired = "RETIREMENT_INTENT_RECORDED", expired
		return nil
	}
	raw, _, e := r.readCommand(o)
	if e != nil {
		return e
	}
	if o.Receipt.State == "ADMITTED" {
		out.State = "RETIREMENT_QUEUED"
		if expired {
			out.State, out.CloseRequired = "RETIREMENT_EFFECT_UNCONFIRMED", true
		}
		return nil
	}
	ack, e := command.VerifyAck(o.Acknowledgement, raw, r.owner, o.NodeKey, time.Now())
	if e != nil || ack.State != o.Receipt.State || ack.ObservedUnix != o.Receipt.ObservedUnix {
		return ErrInvalid
	}
	out.State, out.CloseRequired = "RETIREMENT_EFFECT_UNCONFIRMED", true
	if ack.State == "COMPLETE" {
		out.State = "RETIREMENT_REPORTED_COMPLETE"
	}
	return nil
}
