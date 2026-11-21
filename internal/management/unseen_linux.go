package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
)

const unseenFormat = "outpost-management-registry-3"

// UnseenRequest supplies the retained request, not permission to execute it.
type UnseenRequest struct {
	Node          string           `json:"node"`
	Command       *command.Request `json:"command,omitempty"`
	Configuration *SignedMutation  `json:"configuration,omitempty"`
}
type UnseenResolutionRequest struct {
	Resolution ResolveRequest `json:"resolution"`
	Original   UnseenRequest  `json:"original"`
}
type registryPredecessor struct {
	Format string `json:"format"`
	Digest string `json:"digest"`
}
type unseenRefusal struct {
	Kind     string   `json:"kind"`
	Node     string   `json:"node"`
	Request  string   `json:"request"`
	Expected uint64   `json:"expectedRevision"`
	Domains  []string `json:"domains"`
	Target   Receipt  `json:"targetReceipt"`
	Receipt  Receipt  `json:"receipt"`
	Audit    Audit    `json:"audit"`
}
type unseenProof struct {
	kind, node, request, digest string
	expected                    uint64
	domains                     []string
	repositories                map[string]string
	raw                         []byte
}

func registryIntentCount(s registryState) int {
	return len(s.Operations) + len(s.ConfigOperations) + len(s.CommandOperations) + len(s.UnseenRefusals)
}
func managementIDUsed(s registryState, id string) bool {
	_, a := s.Operations[id]
	_, b := s.ConfigOperations[id]
	_, c := s.CommandOperations[id]
	_, d := s.RetentionPlans[id]
	_, e := s.RetentionSteps[id]
	return a || b || c || d || e || resolutionID(s, id)
}
func unseenTargetReceipt(s registryState, p Principal, tenant, node, kind, id, digest string) (Receipt, bool, error) {
	v, ok := s.UnseenRefusals[id]
	if !ok {
		return Receipt{}, false, nil
	}
	if v.Audit.Tenant != tenant || !allowsDomains(p, tenant, v.Domains) {
		return Receipt{}, true, ErrDenied
	}
	if v.Kind != kind || v.Node != node || v.Target.RequestDigest != digest {
		return Receipt{}, true, ErrConflict
	}
	return v.Target, true, nil
}
func unseenResolutionReplay(s registryState, p Principal, tenant, target string, input ResolveRequest) (Receipt, bool, error) {
	v, ok := s.UnseenRefusals[target]
	if !ok {
		return Receipt{}, false, nil
	}
	if v.Audit.Tenant != tenant || !allowsDomains(p, tenant, v.Domains) {
		return Receipt{}, true, ErrUnavailable
	}
	if v.Target.RequestDigest != input.TargetDigest || v.Receipt.RequestDigest != resolveDigest(p.Actor, tenant, target, input) {
		return Receipt{}, true, ErrConflict
	}
	return v.Receipt, true, nil
}

func (r *Registry) unseenProof(p Principal, tenant, target string, in UnseenRequest) (unseenProof, error) {
	var out unseenProof
	if !storage.ID(in.Node) || !storage.ID(target) || (in.Command == nil) == (in.Configuration == nil) {
		return out, ErrInvalid
	}
	out.node = in.Node
	out.repositories = map[string]string{}
	if in.Command != nil {
		req := *in.Command
		a, e := command.VerifyAuthority(req.Authority, r.owner)
		if e != nil || req.Validate(a) != nil || req.Operation != target || req.Tenant != tenant || a.Node != in.Node || !bytes.Equal(a.Service, r.signer.Public().(ed25519.PublicKey)) {
			return out, ErrDenied
		}
		raw, e := json.Marshal(req)
		if e != nil || len(raw) > command.MaxRequest {
			return out, ErrInvalid
		}
		out.kind = "command"
		out.raw = raw
		out.domains = []string{req.Domain}
		out.digest = commandRequestDigest(p, in.Node, req)
		out.repositories[req.Domain] = a.Repository
	} else {
		req := *in.Configuration
		if req.Operation != target || req.Reason != "POLICY_CHANGE" || !safe(req.Expected) || req.PreviewDigest != storage.Hash(req.Document) {
			return out, ErrInvalid
		}
		cfg, e := control.Verify(req.Document, r.owner, in.Node)
		if e != nil {
			return out, e
		}
		out.kind = "configuration"
		out.expected = req.Expected
		out.raw = append([]byte(nil), req.Document...)
		out.digest = configurationRequestDigest(p, tenant, in.Node, req)
		for _, d := range cfg.Domains {
			out.domains = append(out.domains, d.Trust.Domain)
			out.repositories[d.Trust.Domain] = d.Trust.Repository
		}
	}
	out.request = storage.Hash(out.raw)
	return out, nil
}
func (r *Registry) unseenOwnerDomains(s registryState, p Principal, tenant string, proof unseenProof) ([]string, error) {
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, "") {
		return nil, ErrDenied
	}
	enrollment, e := VerifyEnrollment(s.Enrollments[proof.node], r.owner)
	if e != nil || enrollment.Tenant != tenant || !enrollment.Active(time.Now()) {
		return nil, ErrDenied
	}
	domains := append([]string(nil), proof.domains...)
	if proof.kind == "configuration" {
		for _, d := range enrollment.Domains {
			domains = append(domains, d.Domain)
		}
	}
	selected := map[string]bool{}
	for _, domain := range domains {
		d, ok := enrollment.Domain(domain)
		f := s.Domains[domain]
		if !ok || !p.Allows(tenant, domain) || f.Tenant != tenant || f.Repository != d.Repository || f.Epoch != d.Epoch {
			return nil, ErrDenied
		}
		if repository, supplied := proof.repositories[domain]; supplied && repository != d.Repository {
			return nil, ErrDenied
		}
		selected[domain] = true
	}
	out := []string{}
	for domain := range selected {
		out = append(out, domain)
	}
	sort.Strings(out)
	if len(out) == 0 || len(out) > 128 {
		return nil, ErrInvalid
	}
	return out, nil
}

func (r *Registry) UnseenRefusalPreview(ctx context.Context, p Principal, tenant, target string, in UnseenRequest) (ResolutionPreview, error) {
	var out ResolutionPreview
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, "") {
		return out, ErrDenied
	}
	proof, e := r.unseenProof(p, tenant, target, in)
	if e != nil {
		return out, e
	}
	e = r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		if !r.journalCopy {
			return ErrRegistryJournal
		}
		if v, ok := s.UnseenRefusals[target]; ok {
			if v.Target.RequestDigest != proof.digest || v.Node != proof.node || v.Kind != proof.kind {
				return ErrConflict
			}
			if v.Audit.Tenant != tenant || !allowsDomains(p, tenant, v.Domains) {
				return ErrUnavailable
			}
			out = ResolutionPreview{"outpost-management-resolution-preview-1", target, v.Target.RequestDigest, v.Node, append([]string(nil), v.Domains...), "ABANDONED", false, "ALREADY_ABANDONED"}
			return nil
		}
		domains, e := r.unseenOwnerDomains(s, p, tenant, proof)
		if e != nil {
			return e
		}
		if managementIDUsed(s, target) {
			return ErrConflict
		}
		if registryIntentCount(s) >= maxOperations {
			return ErrCapacity
		}
		out = ResolutionPreview{"outpost-management-resolution-preview-1", target, proof.digest, proof.node, domains, "UNCONFIRMED", true, "UNSEEN_UNPUBLISHED"}
		return nil
	})
	return out, e
}

// RefuseUnseen commits one terminal fence, never a runnable admitted intent.
func (r *Registry) RefuseUnseen(ctx context.Context, p Principal, tenant, target string, in UnseenResolutionRequest) (Receipt, error) {
	var out Receipt
	input := in.Resolution
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, "") || !storage.ID(target) || !storage.ID(input.Operation) || input.Operation == target || !storage.ID(input.TargetDigest) || input.Reason != "ABANDON_UNPUBLISHED" {
		return out, ErrDenied
	}
	proof, e := r.unseenProof(p, tenant, target, in.Original)
	if e != nil {
		return out, e
	}
	if proof.digest != input.TargetDigest {
		return out, ErrConflict
	}
	e = r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		if !r.journalCopy {
			return ErrRegistryJournal
		}
		if receipt, ok, e := unseenResolutionReplay(s, p, tenant, target, input); ok {
			out = receipt
			return e
		}
		domains, e := r.unseenOwnerDomains(s, p, tenant, proof)
		if e != nil {
			return e
		}
		if managementIDUsed(s, target) || managementIDUsed(s, input.Operation) {
			return ErrConflict
		}
		if registryIntentCount(s) >= maxOperations {
			return ErrCapacity
		}
		prefix := "candidate-"
		if proof.kind == "command" {
			prefix = "command-request-"
		}
		name := prefix + proof.request + ".json"
		saved, e := r.blobs.Read(name)
		if errors.Is(e, os.ErrNotExist) {
			e = r.blobs.Write(name, proof.raw)
		} else if e == nil && !bytes.Equal(saved, proof.raw) {
			e = ErrInvalid
		}
		if e != nil {
			return e
		}
		if e = r.point("management-unseen-request-durable"); e != nil {
			return e
		}
		if s.Format != unseenFormat {
			prior, e := r.store.Read("registry.json")
			if e != nil {
				return e
			}
			digest := storage.Hash(prior)
			prefix := "registry-v1-"
			if s.Format == resolutionFormat {
				prefix = "registry-v2-"
			}
			name := prefix + digest + ".json"
			saved, e := r.store.Read(name)
			if errors.Is(e, os.ErrNotExist) {
				e = r.store.Write(name, prior)
			} else if e == nil && !bytes.Equal(saved, prior) {
				e = ErrInvalid
			}
			if e != nil {
				return e
			}
			if e = r.point("management-unseen-predecessor-durable"); e != nil {
				return e
			}
			s.RefusalPredecessor = &registryPredecessor{s.Format, digest}
			if s.Format == registryFormat {
				s.LegacyCheckpoint = digest
			}
			s.Format = unseenFormat
		}
		if e = r.check(ctx); e != nil {
			return e
		}
		if _, e = r.unseenOwnerDomains(s, p, tenant, proof); e != nil {
			return e
		}
		now := time.Now().Unix()
		result := resolutionResult(target, proof.digest, domains)
		digest := resolveDigest(p.Actor, tenant, target, input)
		original := Receipt{Format: "outpost-management-receipt-1", Operation: target, RequestDigest: proof.digest, State: "ABANDONED", ObservedUnix: now, ResultDigest: result, ErrorCode: "OWNER_ABANDONED"}
		receipt := Receipt{Format: "outpost-management-receipt-1", Operation: input.Operation, RequestDigest: digest, State: "COMPLETE", ObservedUnix: now, ResultDigest: result}
		audit := Audit{Sequence: s.Revision + 1, Actor: p.Actor, Tenant: tenant, Operation: input.Operation, Reason: input.Reason, Action: "ABANDON_UNSEEN", State: "COMPLETE", ObservedUnix: now, RequestDigest: digest, ResultDigest: result}
		if s.UnseenRefusals == nil {
			s.UnseenRefusals = map[string]unseenRefusal{}
		}
		s.UnseenRefusals[target] = unseenRefusal{proof.kind, proof.node, proof.request, proof.expected, domains, original, receipt, audit}
		if e = r.save(s); e != nil {
			return e
		}
		if e = r.point("management-unseen-result-durable"); e != nil {
			return e
		}
		out = receipt
		return nil
	})
	return out, e
}

func (r *Registry) validateUnseen(s registryState) error {
	if s.Format != unseenFormat {
		if len(s.UnseenRefusals) != 0 || s.RefusalPredecessor != nil {
			return ErrInvalid
		}
		return nil
	}
	prior := s.RefusalPredecessor
	if !s.JournalCopy || len(s.UnseenRefusals) == 0 || len(s.UnseenRefusals) > maxOperations || prior == nil || !oneOf(prior.Format, registryFormat, resolutionFormat) || !storage.ID(prior.Digest) || !storage.ID(s.LegacyCheckpoint) || prior.Format == registryFormat && prior.Digest != s.LegacyCheckpoint {
		return ErrInvalid
	}
	used := map[string]bool{}
	for id := range s.Operations {
		used[id] = true
	}
	for id := range s.ConfigOperations {
		used[id] = true
	}
	for id := range s.CommandOperations {
		used[id] = true
	}
	for id := range s.RetentionPlans {
		used[id] = true
	}
	for id := range s.RetentionSteps {
		used[id] = true
	}
	for _, v := range s.Resolutions {
		used[v.Receipt.Operation] = true
	}
	for target, v := range s.UnseenRefusals {
		if !storage.ID(target) || used[target] || !storage.ID(v.Receipt.Operation) || target == v.Receipt.Operation || used[v.Receipt.Operation] {
			return ErrInvalid
		}
		used[target] = true
		used[v.Receipt.Operation] = true
		if !oneOf(v.Kind, "command", "configuration") || !storage.ID(v.Node) || !storage.ID(v.Request) || !safe(v.Expected) || v.Kind == "command" && v.Expected != 0 || len(v.Domains) == 0 || len(v.Domains) > 128 || !sort.StringsAreSorted(v.Domains) || v.Kind == "command" && len(v.Domains) != 1 {
			return ErrInvalid
		}
		for i, d := range v.Domains {
			if !storage.ID(d) || i > 0 && v.Domains[i-1] == d || s.Domains[d].Tenant != v.Audit.Tenant {
				return ErrInvalid
			}
		}
		if !storage.ID(v.Audit.Actor) || !storage.ID(v.Audit.Tenant) || v.Audit.Domain != "" || v.Audit.Sequence == 0 || v.Audit.Sequence > s.Revision || v.Audit.Operation != v.Receipt.Operation || v.Audit.Action != "ABANDON_UNSEEN" || v.Audit.Reason != "ABANDON_UNPUBLISHED" || v.Audit.State != "COMPLETE" || !validTime(v.Audit.ObservedUnix) || v.Audit.ObservedUnix > s.ObservedUnix {
			return ErrInvalid
		}
		input := ResolveRequest{v.Receipt.Operation, v.Target.RequestDigest, "ABANDON_UNPUBLISHED"}
		digest := resolveDigest(v.Audit.Actor, v.Audit.Tenant, target, input)
		result := resolutionResult(target, v.Target.RequestDigest, v.Domains)
		if v.Target.Format != "outpost-management-receipt-1" || v.Target.Operation != target || !storage.ID(v.Target.RequestDigest) || v.Target.State != "ABANDONED" || v.Target.ErrorCode != "OWNER_ABANDONED" || v.Target.ObservedUnix != v.Audit.ObservedUnix || v.Target.ResultDigest != result || v.Receipt.Format != "outpost-management-receipt-1" || v.Receipt.State != "COMPLETE" || v.Receipt.ErrorCode != "" || v.Receipt.RequestDigest != digest || v.Receipt.ResultDigest != result || v.Receipt.ObservedUnix != v.Audit.ObservedUnix || v.Audit.RequestDigest != digest || v.Audit.ResultDigest != result {
			return ErrInvalid
		}
	}
	return nil
}

func unseenSnapshotRefs(s registryState) []snapshotRef {
	refs := []snapshotRef{}
	if p := s.RefusalPredecessor; p != nil {
		prefix := "registry-v1-"
		if p.Format == resolutionFormat {
			prefix = "registry-v2-"
		}
		refs = append(refs, snapshotRef{prefix + p.Digest + ".json", p.Digest, "unseen-checkpoint", "", false})
	}
	for _, v := range s.UnseenRefusals {
		prefix, kind := "candidate-", "candidate"
		if v.Kind == "command" {
			prefix, kind = "command-request-", "unseen-request"
		}
		refs = append(refs, snapshotRef{"blobs/" + prefix + v.Request + ".json", v.Request, kind, v.Node, false})
	}
	return refs
}
func checkUnseenDependency(s registryState, ref snapshotRef, raw []byte) error {
	if ref.kind == "unseen-checkpoint" {
		old, e := validateRegistry(raw, s.Owner, s.Signer)
		p := s.RefusalPredecessor
		if e != nil || p == nil || old.Format != p.Format || old.Revision >= s.Revision || !old.JournalCopy || old.Format == resolutionFormat && old.LegacyCheckpoint != s.LegacyCheckpoint {
			return ErrInvalid
		}
		return nil
	}
	for target, v := range s.UnseenRefusals {
		if v.Node != ref.node || v.Request != storage.Hash(raw) {
			continue
		}
		var digest string
		if v.Kind == "command" {
			var req command.Request
			if canonical(raw, &req, command.MaxRequest) != nil {
				return ErrInvalid
			}
			a, e := command.VerifyAuthority(req.Authority, s.Owner)
			if e != nil || req.Validate(a) != nil || req.Operation != target || req.Tenant != v.Audit.Tenant || a.Node != v.Node || !bytes.Equal(a.Service, s.Signer) || len(v.Domains) != 1 || req.Domain != v.Domains[0] {
				return ErrInvalid
			}
			digest = commandRequestDigest(Principal{Actor: v.Audit.Actor}, v.Node, req)
		} else {
			cfg, e := control.Verify(raw, s.Owner, v.Node)
			if e != nil {
				return e
			}
			for _, d := range cfg.Domains {
				found := false
				for _, allowed := range v.Domains {
					if allowed == d.Trust.Domain {
						found = true
					}
				}
				if !found {
					return ErrInvalid
				}
			}
			req := SignedMutation{Operation: target, Reason: "POLICY_CHANGE", Document: raw, Expected: v.Expected, PreviewDigest: v.Request}
			digest = configurationRequestDigest(Principal{Actor: v.Audit.Actor}, v.Audit.Tenant, v.Node, req)
		}
		if digest != v.Target.RequestDigest {
			return ErrInvalid
		}
	}
	return nil
}
