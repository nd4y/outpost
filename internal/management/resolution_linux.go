package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
)

const resolutionFormat = "outpost-management-registry-2"

type ResolveRequest struct {
	Operation    string `json:"operationId"`
	TargetDigest string `json:"targetRequestDigest"`
	Reason       string `json:"reason"`
}
type ResolutionPreview struct {
	Format       string   `json:"format"`
	Operation    string   `json:"operationId"`
	TargetDigest string   `json:"targetRequestDigest"`
	Node         string   `json:"node"`
	Domains      []string `json:"domains"`
	State        string   `json:"state"`
	CanAbandon   bool     `json:"canAbandon"`
	Reason       string   `json:"reason"`
}
type intentResolution struct {
	Target       string   `json:"target"`
	TargetDigest string   `json:"targetRequestDigest"`
	Domains      []string `json:"domains"`
	Receipt      Receipt  `json:"receipt"`
	Audit        Audit    `json:"audit"`
}
type resolutionTarget struct {
	node, tenant string
	domains      []string
	receipt      Receipt
	action       string
	sequence     uint64
}

func (r *Registry) resolutionTarget(s registryState, operation string) (resolutionTarget, error) {
	var out resolutionTarget
	if v, ok := s.Operations[operation]; ok {
		enrollment, e := VerifyEnrollment(v.Document, r.owner)
		if e != nil {
			return out, e
		}
		out = resolutionTarget{node: enrollment.Node, tenant: enrollment.Tenant, receipt: v.Receipt, action: v.Audit.Action, sequence: v.Audit.Sequence}
		for _, d := range enrollment.Domains {
			out.domains = append(out.domains, d.Domain)
		}
	} else if v, ok := s.ConfigOperations[operation]; ok {
		out = resolutionTarget{v.Node, v.Audit.Tenant, append([]string(nil), v.Domains...), v.Receipt, v.Audit.Action, v.Audit.Sequence}
	} else if v, ok := s.CommandOperations[operation]; ok {
		out = resolutionTarget{v.Node, v.Audit.Tenant, []string{v.Audit.Domain}, v.Receipt, v.Audit.Action, v.Audit.Sequence}
	} else {
		return out, ErrUnavailable
	}
	sort.Strings(out.domains)
	return out, nil
}
func allowsDomains(p Principal, tenant string, domains []string) bool {
	if len(domains) == 0 {
		return false
	}
	for _, d := range domains {
		if !p.Allows(tenant, d) {
			return false
		}
	}
	return true
}
func resolved(s registryState, operation string) bool { _, ok := s.Resolutions[operation]; return ok }
func resolutionReceipt(s registryState, receipt Receipt) Receipt {
	if v, ok := s.Resolutions[receipt.Operation]; ok {
		receipt.State = "ABANDONED"
		receipt.ObservedUnix = v.Receipt.ObservedUnix
		receipt.ResultDigest = v.Receipt.ResultDigest
		receipt.ErrorCode = "OWNER_ABANDONED"
	}
	return receipt
}
func resolutionID(s registryState, operation string) bool {
	for _, v := range s.Resolutions {
		if v.Receipt.Operation == operation {
			return true
		}
	}
	return false
}
func resolveDigest(actor, tenant, target string, input ResolveRequest) string {
	raw, _ := json.Marshal(struct {
		Actor, Tenant, Target string
		Request               ResolveRequest
	}{actor, tenant, target, input})
	return storage.Hash(raw)
}
func resolutionResult(target, digest string, domains []string) string {
	raw, _ := json.Marshal(struct {
		Target, RequestDigest, State string
		Domains                      []string
	}{target, digest, "ABANDONED", domains})
	return storage.Hash(raw)
}
func (r *Registry) validateResolutions(s registryState) error {
	if s.Format == registryFormat {
		if len(s.Resolutions) != 0 || s.LegacyCheckpoint != "" {
			return ErrInvalid
		}
		return nil
	}
	if s.Format != resolutionFormat || !storage.ID(s.LegacyCheckpoint) || len(s.Resolutions) == 0 || len(s.Resolutions) > maxOperations {
		return ErrInvalid
	}
	ids := map[string]bool{}
	for id, v := range s.Resolutions {
		t, e := r.resolutionTarget(s, id)
		if e != nil || id != v.Target || t.receipt.State != "ADMITTED" || t.receipt.RequestDigest != v.TargetDigest || v.Audit.Tenant != t.tenant {
			return ErrInvalid
		}
		if !storage.ID(v.Receipt.Operation) || ids[v.Receipt.Operation] || v.Receipt.Operation == id || v.Receipt.Format != "outpost-management-receipt-1" || v.Receipt.State != "COMPLETE" || v.Receipt.ErrorCode != "" || v.Audit.Operation != v.Receipt.Operation || v.Audit.Action != "ABANDON_INTENT" || v.Audit.Reason != "ABANDON_UNPUBLISHED" || v.Audit.State != "COMPLETE" || !storage.ID(v.Audit.Actor) || v.Audit.Domain != "" || v.Audit.Sequence <= t.sequence || v.Audit.Sequence > s.Revision || !validTime(v.Receipt.ObservedUnix) || v.Receipt.ObservedUnix > s.ObservedUnix || v.Receipt.ObservedUnix < t.receipt.ObservedUnix || v.Audit.ObservedUnix != v.Receipt.ObservedUnix {
			return ErrInvalid
		}
		if _, e := r.resolutionTarget(s, v.Receipt.Operation); !errors.Is(e, ErrUnavailable) {
			return ErrInvalid
		}
		ids[v.Receipt.Operation] = true
		if len(v.Domains) == 0 || len(v.Domains) > 128 || !sort.StringsAreSorted(v.Domains) {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, d := range v.Domains {
			if !storage.ID(d) || seen[d] {
				return ErrInvalid
			}
			seen[d] = true
		}
		for _, d := range t.domains {
			if !seen[d] {
				return ErrInvalid
			}
		}
		input := ResolveRequest{v.Receipt.Operation, v.TargetDigest, "ABANDON_UNPUBLISHED"}
		digest := resolveDigest(v.Audit.Actor, t.tenant, id, input)
		if v.Receipt.RequestDigest != digest || v.Audit.RequestDigest != digest || v.Receipt.ResultDigest != resolutionResult(id, v.TargetDigest, v.Domains) || v.Audit.ResultDigest != v.Receipt.ResultDigest {
			return ErrInvalid
		}
		if cmd, ok := s.CommandOperations[id]; ok && (cmd.Envelope != "" || len(cmd.Acknowledgement) != 0) {
			return ErrInvalid
		}
	}
	return nil
}

// Effect eligibility is checked under the same registry lock as publication.
// Unknown cache state is never interpreted as proof of no effect.
func (r *Registry) canResolve(ctx context.Context, s registryState, t resolutionTarget) (bool, string, error) {
	if resolved(s, t.receipt.Operation) {
		return false, "ALREADY_ABANDONED", nil
	}
	if t.receipt.State != "ADMITTED" {
		return false, "TERMINAL", nil
	}
	if v, ok := s.CommandOperations[t.receipt.Operation]; ok {
		if v.Envelope != "" {
			return false, "COMMAND_PUBLISHED", nil
		}
		return true, "UNPUBLISHED", nil
	}
	if v, ok := s.ConfigOperations[t.receipt.Operation]; ok {
		pointer, known := s.Configurations[v.Node]
		raw, e := r.cacheRaw(ctx, v.Node)
		if errors.Is(e, os.ErrNotExist) && !known && v.Expected == 0 {
			return true, "UNPUBLISHED", nil
		}
		if e != nil {
			return false, "STATE_UNAVAILABLE", e
		}
		if len(raw) == 0 {
			if !known && v.Expected == 0 {
				return true, "UNPUBLISHED", nil
			}
			return false, "STATE_UNAVAILABLE", nil
		}
		if storage.Hash(raw) == v.Candidate {
			return false, "CONFIGURATION_PUBLISHED", nil
		}
		current, e := control.Verify(raw, r.owner, v.Node)
		if e != nil {
			return false, "STATE_UNAVAILABLE", e
		}
		if !known || pointer.Digest != storage.Hash(raw) || pointer.Revision != current.Revision || current.Revision != v.Expected {
			return false, "STATE_CONFLICT", nil
		}
	}
	return true, "UNPUBLISHED", nil
}
func (r *Registry) ResolutionPreview(ctx context.Context, p Principal, tenant, operation string) (ResolutionPreview, error) {
	var out ResolutionPreview
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, "") || !storage.ID(operation) {
		return out, ErrDenied
	}
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		t, e := r.resolutionTarget(s, operation)
		if e != nil {
			return e
		}
		if t.tenant != tenant || !allowsDomains(p, tenant, t.domains) {
			return ErrUnavailable
		}
		domains, e := r.resolutionDomains(s, t)
		if e != nil {
			return e
		}
		if !allowsDomains(p, tenant, domains) {
			return ErrUnavailable
		}
		yes, reason, e := r.canResolve(ctx, s, t)
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			reason = "STATE_UNAVAILABLE"
		}
		out = ResolutionPreview{"outpost-management-resolution-preview-1", operation, t.receipt.RequestDigest, t.node, domains, resolutionReceipt(s, t.receipt).State, yes, reason}
		return nil
	})
	return out, e
}
func (r *Registry) resolutionDomains(s registryState, t resolutionTarget) ([]string, error) {
	if v, ok := s.Resolutions[t.receipt.Operation]; ok {
		return append([]string(nil), v.Domains...), nil
	}
	domains := append([]string(nil), t.domains...)
	if t.action == "ENROLL" || t.action == "REVOKE" {
		if raw, ok := s.Enrollments[t.node]; ok {
			current, e := VerifyEnrollment(raw, r.owner)
			if e != nil || current.Tenant != t.tenant {
				return nil, ErrInvalid
			}
			seen := map[string]bool{}
			for _, d := range domains {
				seen[d] = true
			}
			for _, d := range current.Domains {
				if !seen[d.Domain] {
					domains = append(domains, d.Domain)
					seen[d.Domain] = true
				}
			}
		}
	}
	if len(domains) > 128 {
		return nil, ErrCapacity
	}
	sort.Strings(domains)
	return domains, nil
}
func (r *Registry) ResolveUnpublished(ctx context.Context, p Principal, tenant, target string, input ResolveRequest) (Receipt, error) {
	var out Receipt
	if p.Validate() != nil || !p.Role("owner") || !p.Allows(tenant, "") || !storage.ID(target) || !storage.ID(input.Operation) || target == input.Operation || !storage.ID(input.TargetDigest) || input.Reason != "ABANDON_UNPUBLISHED" {
		return out, ErrDenied
	}
	digest := resolveDigest(p.Actor, tenant, target, input)
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		t, e := r.resolutionTarget(s, target)
		if e != nil {
			return e
		}
		if t.tenant != tenant || !allowsDomains(p, tenant, t.domains) {
			return ErrUnavailable
		}
		if old, ok := s.Resolutions[target]; ok {
			if !allowsDomains(p, tenant, old.Domains) {
				return ErrUnavailable
			}
			if old.Receipt.RequestDigest != digest {
				return ErrConflict
			}
			out = old.Receipt
			return nil
		}
		domains, e := r.resolutionDomains(s, t)
		if e != nil {
			return e
		}
		if !allowsDomains(p, tenant, domains) {
			return ErrUnavailable
		}
		if input.TargetDigest != t.receipt.RequestDigest {
			return ErrConflict
		}
		if _, e = r.resolutionTarget(s, input.Operation); !errors.Is(e, ErrUnavailable) {
			return ErrConflict
		}
		if _, used := s.RetentionPlans[input.Operation]; used {
			return ErrConflict
		}
		if resolutionID(s, input.Operation) {
			return ErrConflict
		}
		yes, _, e := r.canResolve(ctx, s, t)
		if e != nil {
			return e
		}
		if !yes {
			return ErrConflict
		}
		if s.Format == registryFormat {
			previous, e := r.store.Read("registry.json")
			if e != nil {
				return e
			}
			checkpoint := storage.Hash(previous)
			name := "registry-v1-" + checkpoint + ".json"
			saved, e := r.store.Read(name)
			if errors.Is(e, os.ErrNotExist) {
				if e = r.store.Write(name, previous); e != nil {
					return e
				}
			} else if e != nil {
				return e
			} else if !bytes.Equal(saved, previous) {
				return ErrInvalid
			}
			if e = r.point("management-resolution-checkpoint-durable"); e != nil {
				return e
			}
			s.Format = resolutionFormat
			s.LegacyCheckpoint = checkpoint
			s.Resolutions = map[string]intentResolution{}
		}
		now := time.Now().Unix()
		result := resolutionResult(target, input.TargetDigest, domains)
		receipt := Receipt{Format: "outpost-management-receipt-1", Operation: input.Operation, RequestDigest: digest, State: "COMPLETE", ObservedUnix: now, ResultDigest: result}
		audit := Audit{Sequence: s.Revision + 1, Actor: p.Actor, Tenant: tenant, Operation: input.Operation, Reason: input.Reason, Action: "ABANDON_INTENT", State: "COMPLETE", ObservedUnix: now, RequestDigest: digest, ResultDigest: result}
		s.Resolutions[target] = intentResolution{target, input.TargetDigest, domains, receipt, audit}
		if e = r.save(s); e != nil {
			return e
		}
		if e = r.point("management-resolution-result-durable"); e != nil {
			return e
		}
		out = receipt
		return nil
	})
	return out, e
}
