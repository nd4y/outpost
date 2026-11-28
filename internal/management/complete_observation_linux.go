package management

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

const CompleteObservationFormat = "outpost-management-complete-observation-1"

// CompleteObservation describes the retained signed report for one assigned
// trusted holder. ObservedUnix is the original report time.
type CompleteObservation struct {
	Format                string `json:"format"`
	Tenant                string `json:"tenant"`
	Node                  string `json:"node"`
	Domain                string `json:"domain"`
	Repository            string `json:"repository"`
	WriterEpoch           uint64 `json:"writerEpoch"`
	Generation            string `json:"generation"`
	GenerationSequence    uint64 `json:"generationSequence"`
	EnrollmentRevision    uint64 `json:"enrollmentRevision"`
	ConfigurationRevision uint64 `json:"configurationRevision"`
	ConfigurationDigest   string `json:"configurationDigest"`
	ReportDigest          string `json:"reportDigest"`
	ReportSequence        uint64 `json:"reportSequence"`
	ObservedUnix          int64  `json:"observedUnix"`
}

func (r *Registry) ObserveComplete(ctx context.Context, p Principal, tenant, node, domain, generation string, maxAge time.Duration) (CompleteObservation, error) {
	if !storage.ID(tenant) || !storage.ID(node) || !storage.ID(domain) || !storage.ID(generation) || maxAge < time.Second || maxAge > 24*time.Hour {
		return CompleteObservation{}, ErrInvalid
	}
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, domain) {
		return CompleteObservation{}, ErrDenied
	}
	state, err := r.retentionState(ctx)
	if err != nil {
		return CompleteObservation{}, err
	}
	fence := state.Domains[domain]
	if fence.Tenant != tenant {
		return CompleteObservation{}, ErrUnavailable
	}
	now := time.Now()
	enrollment, cfg, placement, ok := r.retentionHolder(ctx, state, node, domain, fence, now)
	if !ok {
		return CompleteObservation{}, ErrUnavailable
	}
	pending, err := r.pendingEnrollment(ctx, state, node)
	if err != nil {
		return CompleteObservation{}, err
	}
	if pending {
		return CompleteObservation{}, ErrConflict
	}
	report, pointer, cutoff, ok := r.retainedHolderReport(state, enrollment, cfg, placement, now, maxAge)
	if !ok || report.ObservedUnix < cutoff {
		return CompleteObservation{}, ErrUnavailable
	}
	for _, item := range report.Generations {
		if item.Generation != generation || item.Target != node || item.Status != "COMPLETE" || item.MetadataState != "" {
			continue
		}
		if err := r.checkRetentionRevision(ctx, state.Revision); err != nil {
			return CompleteObservation{}, err
		}
		return CompleteObservation{
			Format:                CompleteObservationFormat,
			Tenant:                tenant,
			Node:                  node,
			Domain:                domain,
			Repository:            fence.Repository,
			WriterEpoch:           fence.Epoch,
			Generation:            generation,
			GenerationSequence:    item.Sequence,
			EnrollmentRevision:    report.EnrollmentRevision,
			ConfigurationRevision: report.ConfigurationRevision,
			ConfigurationDigest:   state.Configurations[node].Digest,
			ReportDigest:          pointer.Digest,
			ReportSequence:        report.Sequence,
			ObservedUnix:          report.ObservedUnix,
		}, nil
	}
	return CompleteObservation{}, ErrUnavailable
}
