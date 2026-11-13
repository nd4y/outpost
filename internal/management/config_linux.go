package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

type configPointer struct {
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}
type configOperation struct {
	Receipt   Receipt  `json:"receipt"`
	Audit     Audit    `json:"audit"`
	Node      string   `json:"node"`
	Expected  uint64   `json:"expectedRevision"`
	Candidate string   `json:"candidate"`
	Domains   []string `json:"domains"`
}
type SignedMutation struct {
	Operation     string `json:"operationId"`
	Reason        string `json:"reason"`
	Document      []byte `json:"document"`
	Expected      uint64 `json:"expectedRevision"`
	PreviewDigest string `json:"previewDigest,omitempty"`
}
type Change struct {
	Kind   string   `json:"kind"`
	Domain string   `json:"domain"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}
type Preview struct {
	Format            string   `json:"format"`
	Node              string   `json:"node"`
	CurrentRevision   uint64   `json:"currentRevision"`
	CandidateRevision uint64   `json:"candidateRevision"`
	CandidateDigest   string   `json:"candidateDigest"`
	ChangedDomains    []string `json:"changedDomains"`
	Changes           []Change `json:"changes"`
	CapacityState     string   `json:"capacityState"`
	EstimatedBytes    *int64   `json:"estimatedBytes"`
}
type Configuration struct {
	Format   string `json:"format"`
	Node     string `json:"node"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
	Document []byte `json:"document"`
}

func (r *Registry) validateConfigState(s registryState) error {
	for node, p := range s.Configurations {
		if !storage.ID(node) || !storage.ID(p.Digest) || p.Revision == 0 || !safe(p.Revision) || len(s.Enrollments[node]) == 0 {
			return ErrInvalid
		}
	}
	for id, o := range s.ConfigOperations {
		_, overlap := s.Operations[id]
		if overlap || !storage.ID(id) || id != o.Receipt.Operation || id != o.Audit.Operation || !storage.ID(o.Node) || !storage.ID(o.Candidate) || !safe(o.Expected) || o.Receipt.Format != "outpost-management-receipt-1" || !oneOf(o.Receipt.State, "ADMITTED", "COMPLETE") || o.Receipt.State != o.Audit.State || o.Receipt.RequestDigest != o.Audit.RequestDigest || !storage.ID(o.Receipt.RequestDigest) || o.Audit.Action != "APPLY_CONFIG" || o.Audit.Reason != "POLICY_CHANGE" || !storage.ID(o.Audit.Actor) || !storage.ID(o.Audit.Tenant) || o.Audit.Sequence == 0 || o.Audit.Sequence > s.Revision || !validTime(o.Receipt.ObservedUnix) || o.Receipt.ObservedUnix > s.ObservedUnix || o.Audit.ObservedUnix != o.Receipt.ObservedUnix {
			return ErrInvalid
		}
		if o.Receipt.State == "COMPLETE" && (o.Receipt.ResultDigest != o.Candidate || o.Audit.ResultDigest != o.Candidate) {
			return ErrInvalid
		}
		if len(o.Domains) == 0 || len(o.Domains) > 128 {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, domain := range o.Domains {
			if !storage.ID(domain) || seen[domain] {
				return ErrInvalid
			}
			seen[domain] = true
		}
	}
	return nil
}
func (r *Registry) cache(node string, initialize bool) (*control.Cache, error) {
	if !storage.ID(node) {
		return nil, ErrInvalid
	}
	name := "config-" + node
	return control.OpenCacheAdmittedAt(r.root, name, node, r.owner, initialize, r.subAdmission(name))
}
func (r *Registry) cacheRaw(ctx context.Context, node string) ([]byte, error) {
	c, e := r.cache(node, false)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer c.Close()
	raw, e := c.Raw(ctx)
	if errors.Is(e, control.ErrInactive) {
		return nil, nil
	}
	return raw, e
}
func (r *Registry) configuration(ctx context.Context, s registryState, node string) (control.Config, []byte, error) {
	var cfg control.Config
	raw, e := r.cacheRaw(ctx, node)
	if e != nil {
		return cfg, nil, e
	}
	pointer, exists := s.Configurations[node]
	if !exists {
		if len(raw) > 0 {
			return cfg, nil, ErrConflict
		}
		return cfg, nil, nil
	}
	if storage.Hash(raw) != pointer.Digest {
		return cfg, nil, ErrConflict
	}
	cfg, e = control.Verify(raw, r.owner, node)
	if e != nil || cfg.Revision != pointer.Revision {
		return cfg, nil, ErrInvalid
	}
	return cfg, raw, nil
}
func (r *Registry) allowConfiguration(s registryState, p Principal, tenant string, c control.Config) error {
	e, eerr := VerifyEnrollment(s.Enrollments[c.Node], r.owner)
	if eerr != nil || e.Tenant != tenant || !e.Active(time.Now()) || !scopeEnrollment(p, e) {
		return ErrDenied
	}
	if !safe(c.Revision) {
		return ErrInvalid
	}
	for _, pending := range s.Operations {
		if pending.Receipt.State == "ADMITTED" && !resolved(s, pending.Receipt.Operation) {
			admission, e := VerifyEnrollment(pending.Document, r.owner)
			if e != nil {
				return e
			}
			if admission.Node == c.Node {
				return ErrConflict
			}
		}
	}
	for _, node := range c.Nodes {
		known, err := VerifyEnrollment(s.Enrollments[node.ID], r.owner)
		if err != nil || known.Tenant != tenant || known.Class != node.Class || !known.Active(time.Now()) {
			return ErrDenied
		}
	}
	for _, d := range c.Domains {
		a, ok := e.Domain(d.Trust.Domain)
		fence := s.Domains[d.Trust.Domain]
		if !ok || !p.Allows(tenant, d.Trust.Domain) || a.Repository != d.Trust.Repository || a.Epoch != d.Trust.Epoch || fence.Tenant != tenant || fence.Repository != a.Repository || fence.Epoch != a.Epoch {
			return ErrDenied
		}
		for _, node := range append(append([]string{}, d.Placement.Holders...), d.Placement.Transit...) {
			holder, err := VerifyEnrollment(s.Enrollments[node], r.owner)
			if err != nil {
				return ErrDenied
			}
			scope, ok := holder.Domain(d.Trust.Domain)
			if !ok || scope.Repository != d.Trust.Repository || scope.Epoch != d.Trust.Epoch {
				return ErrDenied
			}
		}
	}
	for _, raw := range c.Ingress {
		grant, err := ingress.VerifyAuthorityDocument(raw, r.owner)
		if err != nil || grant.Tenant != tenant {
			return ErrDenied
		}
	}
	for _, raw := range c.Commands {
		grant, err := command.VerifyAuthority(raw, r.owner)
		if err != nil || grant.Tenant != tenant {
			return ErrDenied
		}
	}
	return nil
}
func configDigest(value any) string { raw, _ := json.Marshal(value); return storage.Hash(raw) }
func stringsCopy(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
func previewChanges(before, after control.Config) Preview {
	p := Preview{Format: "outpost-management-preview-1", Node: after.Node, CurrentRevision: before.Revision, CandidateRevision: after.Revision, ChangedDomains: []string{}, Changes: []Change{}, CapacityState: "UNKNOWN"}
	ids := map[string]bool{}
	for _, d := range before.Domains {
		ids[d.Trust.Domain] = true
	}
	for _, d := range after.Domains {
		ids[d.Trust.Domain] = true
	}
	ordered := []string{}
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		old, oldExists := before.DomainByID(id)
		next, newExists := after.DomainByID(id)
		start := len(p.Changes)
		add := func(kind string, a, b []string) {
			a = stringsCopy(a)
			b = stringsCopy(b)
			if configDigest(a) != configDigest(b) {
				p.Changes = append(p.Changes, Change{kind, id, a, b})
			}
		}
		if oldExists != newExists {
			var a, b []string
			if oldExists {
				a = []string{id}
			}
			if newExists {
				b = []string{id}
			}
			add("DOMAIN", a, b)
		}
		add("HOLDER", old.Placement.Holders, next.Placement.Holders)
		add("TRANSIT", old.Placement.Transit, next.Placement.Transit)
		add("EXTERNAL_TARGET", old.Placement.Targets, next.Placement.Targets)
		oldRoutes, nextRoutes := []string{}, []string{}
		for _, edge := range old.Placement.Edges {
			oldRoutes = append(oldRoutes, configDigest(edge))
		}
		for _, edge := range old.Placement.CloudEdges {
			oldRoutes = append(oldRoutes, configDigest(edge))
		}
		for _, edge := range next.Placement.Edges {
			nextRoutes = append(nextRoutes, configDigest(edge))
		}
		for _, edge := range next.Placement.CloudEdges {
			nextRoutes = append(nextRoutes, configDigest(edge))
		}
		add("ROUTE", oldRoutes, nextRoutes)
		// Include full domain authority and global endpoint/limit/assignment
		// changes. The exact signed before/after documents remain retrievable.
		a := configDigest(struct {
			Domain       control.Domain
			Nodes        any
			Targets      any
			Limits       control.Limits
			Ingress      any
			Jobs         any
			Replication  any
			Observations any
			Uploads      any
			Commands     any
		}{old, before.Nodes, before.Targets, before.Limits, before.Ingress, before.Jobs, before.Replication, before.Observations, before.Uploads, before.Commands})
		b := configDigest(struct {
			Domain       control.Domain
			Nodes        any
			Targets      any
			Limits       control.Limits
			Ingress      any
			Jobs         any
			Replication  any
			Observations any
			Uploads      any
			Commands     any
		}{next, after.Nodes, after.Targets, after.Limits, after.Ingress, after.Jobs, after.Replication, after.Observations, after.Uploads, after.Commands})
		add("AUTHORITY", []string{a}, []string{b})
		if len(p.Changes) > start {
			p.ChangedDomains = append(p.ChangedDomains, id)
		}
	}
	return p
}
func (r *Registry) PreviewConfiguration(ctx context.Context, p Principal, tenant, node string, input SignedMutation) (Preview, error) {
	var out Preview
	if p.Validate() != nil || !p.Role("owner") || !storage.ID(tenant) || !storage.ID(node) || !storage.ID(input.Operation) || input.Reason != "POLICY_CHANGE" || !safe(input.Expected) {
		return out, ErrDenied
	}
	next, e := control.Verify(input.Document, r.owner, node)
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
		if e := r.allowConfiguration(s, p, tenant, next); e != nil {
			return e
		}
		if next.Active(time.Now()) != nil {
			return ErrDenied
		}
		old, _, e := r.configuration(ctx, s, node)
		if e != nil {
			return e
		}
		if old.Revision != input.Expected || next.Revision <= old.Revision {
			return ErrConflict
		}
		for _, d := range old.Domains {
			if !p.Allows(tenant, d.Trust.Domain) {
				return ErrDenied
			}
		}
		out = previewChanges(old, next)
		out.CandidateDigest = storage.Hash(input.Document)
		return nil
	})
	return out, e
}
func configurationRequestDigest(p Principal, tenant, node string, input SignedMutation) string {
	request, _ := json.Marshal(struct {
		Actor, Tenant, Node string
		Input               SignedMutation
	}{p.Actor, tenant, node, input})
	return storage.Hash(request)
}

func (r *Registry) finishConfiguration(s *registryState, op configOperation, revision uint64) error {
	s.Configurations[op.Node] = configPointer{revision, op.Candidate}
	op.Receipt.State = "COMPLETE"
	op.Receipt.ObservedUnix = time.Now().Unix()
	op.Receipt.ResultDigest = op.Candidate
	op.Audit.State = "COMPLETE"
	op.Audit.ObservedUnix = op.Receipt.ObservedUnix
	op.Audit.ResultDigest = op.Candidate
	s.ConfigOperations[op.Receipt.Operation] = op
	if e := r.save(*s); e != nil {
		return e
	}
	return r.point("management-config-result-durable")
}

func (r *Registry) ApplyConfiguration(ctx context.Context, p Principal, tenant, node string, input SignedMutation) (Receipt, error) {
	var out Receipt
	if p.Validate() != nil || !p.Role("owner") || !storage.ID(tenant) || !storage.ID(node) || !storage.ID(input.Operation) || input.Reason != "POLICY_CHANGE" || input.PreviewDigest != storage.Hash(input.Document) || !safe(input.Expected) {
		return out, ErrDenied
	}
	next, e := control.Verify(input.Document, r.owner, node)
	if e != nil {
		return out, e
	}
	requestDigest := configurationRequestDigest(p, tenant, node, input)
	candidate := storage.Hash(input.Document)
	e = r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		if receipt, ok, err := unseenTargetReceipt(s, p, tenant, node, "configuration", input.Operation, requestDigest); ok {
			out = receipt
			return err
		}
		if resolutionID(s, input.Operation) {
			return ErrConflict
		}
		if v, ok := s.Resolutions[input.Operation]; ok {
			if v.TargetDigest != requestDigest {
				return ErrConflict
			}
			if !allowsDomains(p, tenant, v.Domains) {
				return ErrDenied
			}
			original, ok := s.ConfigOperations[input.Operation]
			if !ok {
				return ErrConflict
			}
			out = resolutionReceipt(s, original.Receipt)
			return nil
		}
		if e := r.allowConfiguration(s, p, tenant, next); e != nil {
			return e
		}
		if _, exists := s.Operations[input.Operation]; exists {
			return ErrConflict
		}
		if _, exists := s.CommandOperations[input.Operation]; exists {
			return ErrConflict
		}
		if _, exists := s.RetentionPlans[input.Operation]; exists {
			return ErrConflict
		}
		if _, used := s.RetentionSteps[input.Operation]; used {
			return ErrConflict
		}
		op, exists := s.ConfigOperations[input.Operation]
		if exists {
			if op.Receipt.RequestDigest != requestDigest {
				return ErrConflict
			}
			if op.Receipt.State == "COMPLETE" {
				out = op.Receipt
				return nil
			}
		} else {
			if registryIntentCount(s) >= maxOperations {
				return ErrCapacity
			}
			for _, o := range s.ConfigOperations {
				if o.Receipt.State == "ADMITTED" && !resolved(s, o.Receipt.Operation) && o.Node == node {
					return ErrConflict
				}
			}
			old, _, e := r.configuration(ctx, s, node)
			if e != nil {
				return e
			}
			if old.Revision != input.Expected || next.Revision <= old.Revision {
				return ErrConflict
			}
			if next.Active(time.Now()) != nil {
				return ErrDenied
			}
			for _, d := range old.Domains {
				if !p.Allows(tenant, d.Trust.Domain) {
					return ErrDenied
				}
			}
			name := "candidate-" + candidate + ".json"
			previous, e := r.blobs.Read(name)
			if e == nil {
				if !bytes.Equal(previous, input.Document) {
					return ErrInvalid
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			} else if e = r.blobs.Write(name, input.Document); e != nil {
				return e
			}
			enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
			if e != nil {
				return e
			}
			domains := []string{}
			seen := map[string]bool{}
			for _, d := range enrollment.Domains {
				domains = append(domains, d.Domain)
				seen[d.Domain] = true
			}
			for _, d := range old.Domains {
				if !seen[d.Trust.Domain] {
					domains = append(domains, d.Trust.Domain)
				}
			}
			sort.Strings(domains)
			if len(domains) > 128 {
				return ErrCapacity
			}
			now := time.Now().Unix()
			op = configOperation{Receipt: Receipt{Format: "outpost-management-receipt-1", Operation: input.Operation, RequestDigest: requestDigest, State: "ADMITTED", ObservedUnix: now}, Audit: Audit{Sequence: s.Revision + 1, Actor: p.Actor, Tenant: tenant, Operation: input.Operation, Reason: input.Reason, Action: "APPLY_CONFIG", State: "ADMITTED", ObservedUnix: now, RequestDigest: requestDigest}, Node: node, Expected: input.Expected, Candidate: candidate, Domains: domains}
			s.ConfigOperations[input.Operation] = op
			if e := r.save(s); e != nil {
				return e
			}
			if e := r.point("management-config-intent-durable"); e != nil {
				return e
			}
			s, e = r.load()
			if e != nil {
				return e
			}
		}
		staged, e := r.blobs.Read("candidate-" + candidate + ".json")
		if e != nil {
			return e
		}
		if !bytes.Equal(staged, input.Document) {
			return ErrInvalid
		}
		_, known := s.Configurations[node]
		cache, e := r.cache(node, !known)
		if e != nil {
			return e
		}
		defer cache.Close()
		current, e := cache.Raw(ctx)
		if errors.Is(e, control.ErrInactive) {
			current = nil
		} else if e != nil {
			return e
		}
		if !bytes.Equal(current, staged) {
			var revision uint64
			if len(current) > 0 {
				old, e := control.Verify(current, r.owner, node)
				if e != nil {
					return e
				}
				revision = old.Revision
			}
			if revision != input.Expected {
				return ErrConflict
			}
			if e := cache.Accept(ctx, staged, time.Now()); e != nil {
				return e
			}
		}
		if e := r.point("management-config-cache-durable"); e != nil {
			return e
		}
		if e := r.finishConfiguration(&s, op, next.Revision); e != nil {
			return e
		}
		out = s.ConfigOperations[input.Operation].Receipt
		return nil
	})
	return out, e
}
func (r *Registry) Configuration(ctx context.Context, p Principal, tenant, node string) (Configuration, error) {
	var out Configuration
	if p.Validate() != nil || !storage.ID(tenant) || !storage.ID(node) || !p.Allows(tenant, "") || !p.Role("owner") && !(p.Role("node") && p.Actor == node) {
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
		enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
		if e != nil || enrollment.Tenant != tenant || !enrollment.Active(time.Now()) {
			return ErrUnavailable
		}
		for _, d := range enrollment.Domains {
			if !p.Allows(tenant, d.Domain) {
				return ErrDenied
			}
		}
		for _, pending := range s.Operations {
			if pending.Receipt.State == "ADMITTED" && !resolved(s, pending.Receipt.Operation) {
				next, e := VerifyEnrollment(pending.Document, r.owner)
				if e != nil {
					return e
				}
				if next.Node == node {
					return ErrConflict
				}
			}
		}
		c, raw, e := r.configuration(ctx, s, node)
		if e != nil {
			return e
		}
		if len(raw) == 0 {
			return ErrUnavailable
		}
		for _, d := range c.Domains {
			admission, ok := enrollment.Domain(d.Trust.Domain)
			fence := s.Domains[d.Trust.Domain]
			if !ok || !p.Allows(tenant, d.Trust.Domain) || admission.Repository != d.Trust.Repository || admission.Epoch != d.Trust.Epoch || fence.Epoch != admission.Epoch {
				return ErrDenied
			}
		}
		out = Configuration{"outpost-management-config-1", node, c.Revision, storage.Hash(raw), raw}
		return nil
	})
	return out, e
}
