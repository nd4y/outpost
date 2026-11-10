package management

import (
	"context"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

const RetentionCoverageRequestFormat = "outpost-retention-coverage-request-1"

type RetentionCoverageRequest struct {
	Format        string   `json:"format"`
	Nodes         []string `json:"nodes"`
	RetiringNodes []string `json:"retiringNodes"`
	Generations   []string `json:"generations"`
	MinimumCopies int      `json:"minimumCopies"`
}

type RetentionWitness struct {
	Node           string `json:"node"`
	ReportDigest   string `json:"reportDigest"`
	ReportSequence uint64 `json:"reportSequence"`
	ObservedUnix   int64  `json:"observedUnix"`
	VerifiedUnix   int64  `json:"verifiedUnix"`
	ConfigRevision uint64 `json:"configurationRevision"`
}

type RetentionGenerationCoverage struct {
	Generation string             `json:"generation"`
	State      string             `json:"state"`
	Witnesses  []RetentionWitness `json:"witnesses"`
}

type RetentionCoverage struct {
	Format           string                        `json:"format"`
	Tenant           string                        `json:"tenant"`
	Domain           string                        `json:"domain"`
	Repository       string                        `json:"repository"`
	Epoch            uint64                        `json:"epoch"`
	RegistryRevision uint64                        `json:"registryRevision"`
	EvaluatedUnix    int64                         `json:"evaluatedUnix"`
	MinimumCopies    int                           `json:"minimumCopies"`
	Authorization    string                        `json:"authorization"`
	Generations      []RetentionGenerationCoverage `json:"generations"`
}

func validRetentionIDs(ids []string, max int) bool {
	if len(ids) == 0 || len(ids) > max {
		return false
	}
	for i, id := range ids {
		if !storage.ID(id) || i > 0 && ids[i-1] >= id {
			return false
		}
	}
	return true
}

// PreviewRetentionCoverage evaluates signed observations. Durable survivor pins
// and deletion authorization remain separate from this read-only result.
func (r *Registry) PreviewRetentionCoverage(ctx context.Context, p Principal, tenant, domain string, input RetentionCoverageRequest, maxAge time.Duration) (RetentionCoverage, error) {
	var out RetentionCoverage
	if p.Validate() != nil || !p.Allows(tenant, domain) || !oneOfRole(p, "owner", "operator") {
		return out, ErrDenied
	}
	if !storage.ID(tenant) || !storage.ID(domain) || maxAge < time.Second || maxAge > 24*time.Hour || input.Format != RetentionCoverageRequestFormat || input.MinimumCopies < 1 || input.MinimumCopies > 8 || !validRetentionIDs(input.Nodes, 8) || !validRetentionIDs(input.RetiringNodes, 8) || !validRetentionIDs(input.Generations, 64) {
		return out, ErrInvalid
	}
	for _, node := range input.RetiringNodes {
		if !slices.Contains(input.Nodes, node) {
			return out, ErrInvalid
		}
	}
	var state registryState
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		var e error
		state, e = r.load()
		return e
	})
	if e != nil {
		return out, e
	}
	fence, ok := state.Domains[domain]
	if !ok || fence.Tenant != tenant {
		return out, ErrUnavailable
	}
	now := time.Now()
	out = RetentionCoverage{Format: "outpost-retention-coverage-1", Tenant: tenant, Domain: domain, Repository: fence.Repository, Epoch: fence.Epoch, RegistryRevision: state.Revision, EvaluatedUnix: now.Unix(), MinimumCopies: input.MinimumCopies, Authorization: "NONE", Generations: make([]RetentionGenerationCoverage, len(input.Generations))}
	positions := make(map[string]int, len(input.Generations))
	seen := make(map[string]Generation, len(input.Generations))
	for i, gen := range input.Generations {
		positions[gen] = i
		out.Generations[i] = RetentionGenerationCoverage{Generation: gen, State: "INSUFFICIENT_EVIDENCE", Witnesses: []RetentionWitness{}}
	}
	for _, node := range input.Nodes {
		if e = ctx.Err(); e != nil {
			return RetentionCoverage{}, e
		}
		if slices.Contains(input.RetiringNodes, node) {
			continue
		}
		report, pointer, minimumVerified, ok := r.retentionReport(ctx, state, node, domain, fence, now, maxAge)
		if !ok {
			continue
		}
		for _, gen := range report.Generations {
			pos, wanted := positions[gen.Generation]
			if !wanted || gen.Target != node || gen.Status != "COMPLETE" || gen.MetadataState != "" || !gen.Pinned || gen.Verification != "CIPHERTEXT" || gen.VerifiedUnix < max(minimumVerified, gen.CreatedUnix) {
				continue
			}
			result := &out.Generations[pos]
			if previous, exists := seen[gen.Generation]; exists && (previous.Sequence != gen.Sequence || previous.CreatedUnix != gen.CreatedUnix || previous.Objects != gen.Objects) {
				result.State = "CONFLICTING_EVIDENCE"
			}
			seen[gen.Generation] = gen
			result.Witnesses = append(result.Witnesses, RetentionWitness{Node: node, ReportDigest: pointer.Digest, ReportSequence: report.Sequence, ObservedUnix: report.ObservedUnix, VerifiedUnix: gen.VerifiedUnix, ConfigRevision: report.ConfigurationRevision})
			if result.State != "CONFLICTING_EVIDENCE" && len(result.Witnesses) >= input.MinimumCopies {
				result.State = "OBSERVED_MINIMUM_MET"
			}
		}
	}
	// The expensive report and policy reads run outside the registry lock.
	// Check the revision before returning a coherent observation.
	e = r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		current, e := r.load()
		if e != nil {
			return e
		}
		if current.Revision != state.Revision {
			return ErrConflict
		}
		return nil
	})
	if e != nil {
		return RetentionCoverage{}, e
	}
	return out, nil
}

func (r *Registry) retentionReport(ctx context.Context, s registryState, node, domain string, fence domainFence, now time.Time, maxAge time.Duration) (Report, reportPointer, int64, bool) {
	enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
	admission, allowed := enrollment.Domain(domain)
	if e != nil || !allowed || enrollment.Class != "trusted" || !enrollment.Active(now) || enrollment.Tenant != fence.Tenant || admission.Repository != fence.Repository || admission.Epoch != fence.Epoch {
		return Report{}, reportPointer{}, 0, false
	}
	report, pointer, e := r.readReport(s, node, domain)
	cutoff := now.Unix() - int64(maxAge/time.Second)
	if e != nil || report.Tenant != fence.Tenant || report.EnrollmentRevision != enrollment.Revision || report.ObservedUnix < cutoff || report.ObservedUnix > now.Unix() || report.InventoryState != "OBSERVED" {
		return Report{}, reportPointer{}, 0, false
	}
	cfg, _, e := r.configuration(ctx, s, node)
	d, present := cfg.DomainByID(domain)
	configuredNode, known := cfg.NodeByID(node)
	if e != nil || !present || !known || configuredNode.Class != "trusted" || cfg.Revision != report.ConfigurationRevision || report.ObservedUnix < cfg.NotBefore || now.Unix() >= cfg.ExpiresUnix || d.Trust.Repository != fence.Repository || d.Trust.Epoch != fence.Epoch || !slices.Contains(d.Placement.Holders, node) {
		return Report{}, reportPointer{}, 0, false
	}
	if d.PeerReadbackMaxAgeSeconds > 0 {
		cutoff = max(cutoff, now.Unix()-d.PeerReadbackMaxAgeSeconds)
	}
	return report, pointer, max(cutoff, cfg.NotBefore), true
}
