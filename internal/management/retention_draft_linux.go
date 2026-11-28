package management

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const RetentionDraftRequestFormat = "outpost-retention-draft-request-1"

type RetentionDraftRequest struct {
	Format       string            `json:"format"`
	Preview      generation.Permit `json:"preview"`
	HoldCommands []string          `json:"holdCommands"`
}

type RetentionDraftSource struct {
	Generation   string `json:"generation"`
	Node         string `json:"node"`
	Command      string `json:"commandOperationId"`
	ReportDigest string `json:"reportDigest"`
	ProofDigest  string `json:"proofDigest"`
	ObservedUnix int64  `json:"observedUnix"`
}

type RetentionDraft struct {
	Format                      string                 `json:"format"`
	State                       string                 `json:"state"`
	Authorization               string                 `json:"authorization"`
	RegistryRevision            uint64                 `json:"registryRevision"`
	TargetConfigurationRevision uint64                 `json:"targetConfigurationRevision"`
	EvaluatedUnix               int64                  `json:"evaluatedUnix"`
	MinimumCopies               int                    `json:"minimumCopies"`
	MissingGenerations          []string               `json:"missingGenerations"`
	Sources                     []RetentionDraftSource `json:"sources"`
	Permit                      *generation.Permit     `json:"permit,omitempty"`
}

type draftWitness struct {
	proof  generation.RetentionProtectionReceipt
	source RetentionDraftSource
}

// PrepareRetentionDraft assembles an unsigned permit from completed HOLD
// commands and current reports. The retiring replica still decides admission.
func (r *Registry) PrepareRetentionDraft(ctx context.Context, p Principal, tenant, domain string, input RetentionDraftRequest, maxAge time.Duration) (RetentionDraft, error) {
	var out RetentionDraft
	if p.Validate() != nil || !p.Allows(tenant, domain) || !p.Role("owner") {
		return out, ErrDenied
	}
	if !storage.ID(tenant) || !storage.ID(domain) || !validRetentionDraftInput(input, domain, RetentionDraftRequestFormat) ||
		maxAge < time.Second || maxAge > 24*time.Hour {
		return out, ErrInvalid
	}
	s, e := r.retentionState(ctx)
	if e != nil {
		return out, e
	}
	return r.prepareRetentionDraft(ctx, s, tenant, domain, input, nil, maxAge)
}

func validRetentionDraftInput(input RetentionDraftRequest, domain, format string) bool {
	p := input.Preview
	return input.Format == format && p.Format == generation.PermitWindowFormat && p.Domain == domain &&
		p.Revision != 0 && validRetentionIDs(p.Retire, 64) && validRetentionIDs(input.HoldCommands, 64) &&
		!slices.Contains(input.HoldCommands, p.Operation) && generation.ValidatePermitDraft(p) == nil
}

func (r *Registry) prepareRetentionDraft(ctx context.Context, s registryState, tenant, domain string, input RetentionDraftRequest, expected *generation.Trust, maxAge time.Duration) (RetentionDraft, error) {
	var out RetentionDraft
	permit := input.Preview
	fence, found := s.Domains[domain]
	if !found || fence.Tenant != tenant {
		return out, ErrUnavailable
	}
	now := time.Now()
	if permit.Window.ExpiresUnix <= now.Unix() || resolutionID(s, permit.Operation) {
		return out, ErrConflict
	}
	_, commandUsed := s.CommandOperations[permit.Operation]
	_, enrollmentUsed := s.Operations[permit.Operation]
	_, configurationUsed := s.ConfigOperations[permit.Operation]
	if commandUsed || enrollmentUsed || configurationUsed || hasPlannedClose(s, tenant, permit) {
		return out, ErrConflict
	}
	_, cfg, target, ok := r.retentionHolder(ctx, s, permit.Window.Node, domain, fence, now)
	if !ok || target.RetirementMinimumCopies == 0 || permit.Window.StartUnix >= cfg.ExpiresUnix ||
		permit.Repository != fence.Repository || permit.Epoch != fence.Epoch ||
		expected != nil && (!bytes.Equal(target.Trust.Writer, expected.Writer) || !bytes.Equal(target.Trust.Maintenance, expected.Maintenance)) {
		return out, ErrDenied
	}
	minimum := target.RetirementMinimumCopies
	if len(permit.Retire)*minimum > 64 {
		return out, ErrInvalid
	}
	groups := map[string][]commandOperation{}
	for _, id := range input.HoldCommands {
		o, exists := s.CommandOperations[id]
		n, known := cfg.NodeByID(o.Node)
		if exists && !resolved(s, id) && o.Receipt.State == "COMPLETE" && o.Audit.Action == "COMMAND_RETENTION" &&
			o.Audit.Tenant == tenant && o.Audit.Domain == domain && o.Node != permit.Window.Node &&
			known && n.Class == "trusted" && slices.Contains(target.Placement.Holders, o.Node) {
			groups[o.Node] = append(groups[o.Node], o)
		}
	}
	if len(groups) > generation.MaxRetirementMinimumCopies {
		return out, ErrInvalid
	}
	nodes := make([]string, 0, len(groups))
	for node := range groups {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	chosen := make(map[string][]draftWitness, len(permit.Retire))
	binding := generation.RetirementBinding{Node: permit.Window.Node, Operation: permit.Operation}
	for _, node := range nodes {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		report, pointer, cutoff, ok := r.retentionReport(ctx, s, node, domain, fence, now, maxAge)
		if !ok || report.ObservedUnix < cutoff {
			continue
		}
		observations := make(map[string]CommandObservation, len(report.Commands))
		for _, c := range report.Commands {
			if c.Kind == "retention" && c.Phase == "COMPLETE" {
				observations[c.Operation] = c
			}
		}
		complete := map[string]bool{}
		for _, g := range report.Generations {
			if g.Target == node && g.Status == "COMPLETE" && g.MetadataState == "" && g.Pinned {
				complete[g.Generation] = true
			}
		}
		seen := map[string]bool{}
		for _, o := range groups[node] {
			c, ok := observations[o.Receipt.Operation]
			if !ok {
				continue
			}
			proof, ok := r.retentionDraftProof(o, c, target.Trust, binding, now)
			if !ok || seen[proof.Generation] || !complete[proof.Generation] ||
				len(chosen[proof.Generation]) >= minimum || !slices.Contains(permit.Retire, proof.Generation) {
				continue
			}
			seen[proof.Generation] = true
			chosen[proof.Generation] = append(chosen[proof.Generation], draftWitness{proof, RetentionDraftSource{
				Generation: proof.Generation, Node: node, Command: c.Operation, ReportDigest: pointer.Digest,
				ProofDigest: c.ResultDigest, ObservedUnix: proof.ObservedUnix,
			}})
		}
	}
	if e := r.checkRetentionRevision(ctx, s.Revision); e != nil {
		return out, e
	}
	if permit.Window.ExpiresUnix <= time.Now().Unix() || cfg.Active(time.Now()) != nil {
		return out, ErrConflict
	}
	out = RetentionDraft{
		Format: "outpost-retention-draft-1", State: "INSUFFICIENT_EVIDENCE", Authorization: "NONE",
		RegistryRevision: s.Revision, TargetConfigurationRevision: cfg.Revision, EvaluatedUnix: now.Unix(), MinimumCopies: minimum,
		MissingGenerations: []string{}, Sources: []RetentionDraftSource{},
	}
	coverage := &generation.RetentionCoverage{MinimumCopies: minimum}
	for _, id := range permit.Retire {
		if len(chosen[id]) < minimum {
			out.MissingGenerations = append(out.MissingGenerations, id)
		}
		for _, w := range chosen[id] {
			out.Sources = append(out.Sources, w.source)
			coverage.Witnesses = append(coverage.Witnesses, w.proof)
		}
	}
	if len(out.MissingGenerations) == 0 {
		permit.Format, permit.Coverage = generation.RetentionPermitFormat, coverage
		if generation.ValidatePermitDraft(permit) != nil {
			return RetentionDraft{}, ErrInvalid
		}
		out.State, out.Permit = "READY_TO_SIGN", &permit
	}
	return out, nil
}

func (r *Registry) retentionDraftProof(o commandOperation, c CommandObservation, trust generation.Trust, binding generation.RetirementBinding, now time.Time) (generation.RetentionProtectionReceipt, bool) {
	grant, proof, ok := r.confirmedRetentionProof(o, c, trust, now)
	return proof, ok && grant.Action == "HOLD" && grant.Retirement != nil && *grant.Retirement == binding
}

func (r *Registry) confirmedRetentionProof(o commandOperation, c CommandObservation, trust generation.Trust, now time.Time) (generation.RetentionProtection, generation.RetentionProtectionReceipt, bool) {
	var grant generation.RetentionProtection
	var proof generation.RetentionProtectionReceipt
	raw, env, e := r.readCommand(o)
	if e != nil || env.Request.Kind != "retention" || c.EnvelopeDigest != o.Envelope {
		return grant, proof, false
	}
	ack, e := command.VerifyAck(o.Acknowledgement, raw, r.owner, o.NodeKey, now)
	if e != nil || ack.State != "COMPLETE" || ack.ResultDigest != c.ResultDigest || ack.ObservedUnix != c.FinishedUnix {
		return grant, proof, false
	}
	grant, e = generation.VerifyRetentionProtection(env.Request.RetentionGrant, trust, o.Node)
	if e != nil {
		return grant, proof, false
	}
	proof, e = generation.VerifyRetentionProtectionReceipt(c.RetentionProof, o.Node)
	digest := storage.Hash(env.Request.RetentionGrant)
	state, hold := "CLOSED", ""
	switch grant.Action {
	case "HOLD":
		state, hold = "HELD", digest
	case "RELEASE":
		state, hold = "RELEASED", grant.HoldDigest
	}
	bound := grant.Retirement == nil && proof.Retirement == nil ||
		grant.Retirement != nil && proof.Retirement != nil && *grant.Retirement == *proof.Retirement
	ok := e == nil && proof.State == state && proof.GrantDigest == digest && proof.HoldDigest == hold &&
		proof.Domain == grant.Domain && proof.Repository == grant.Repository && proof.Epoch == grant.Epoch &&
		proof.Generation == grant.Generation && proof.Operation == grant.Operation &&
		proof.ObservedUnix >= grant.NotBefore && proof.ObservedUnix < grant.ExpiresUnix && bound
	return grant, proof, ok
}
