package management

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
)

const DomainPolicyFormat = "outpost-management-domain-policy-1"
const MaxDomainPolicy = 2 << 20

type PolicyNode struct {
	ID    string `json:"id"`
	Class string `json:"class"`
}
type PolicyTarget struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	MaxObjectBytes int    `json:"maxObjectBytes"`
}
type PolicySource struct {
	Node        string `json:"node"`
	Profile     string `json:"profile"`
	Ingress     string `json:"ingress"`
	Revision    uint64 `json:"revision"`
	ExpiresUnix int64  `json:"expiresUnix"`
	State       string `json:"state"`
}
type CommandCapability struct {
	Authority   []byte   `json:"authority"`
	Kinds       []string `json:"kinds"`
	ExpiresUnix int64    `json:"expiresUnix"`
}
type DomainPolicy struct {
	Format                string              `json:"format"`
	Tenant                string              `json:"tenant"`
	Node                  string              `json:"node"`
	Domain                string              `json:"domain"`
	Repository            string              `json:"repository"`
	WriterEpoch           uint64              `json:"writerEpoch"`
	ConfigurationRevision uint64              `json:"configurationRevision"`
	ConfigurationDigest   string              `json:"configurationDigest"`
	ConfigurationState    string              `json:"configurationState"`
	ExpiresUnix           int64               `json:"expiresUnix"`
	Placement             policy.Placement    `json:"placement"`
	Nodes                 []PolicyNode        `json:"nodes"`
	Targets               []PolicyTarget      `json:"targets"`
	Sources               []PolicySource      `json:"sources"`
	Capabilities          []CommandCapability `json:"capabilities"`
}

// DomainPolicy is an operator view, not a signed configuration. It exposes no
// private paths, endpoints, credentials, unrelated domains or new authority.
func (r *Registry) DomainPolicy(ctx context.Context, p Principal, tenant, node, domain string) (DomainPolicy, error) {
	out := DomainPolicy{Format: DomainPolicyFormat, Nodes: []PolicyNode{}, Targets: []PolicyTarget{}, Sources: []PolicySource{}, Capabilities: []CommandCapability{}}
	if p.Validate() != nil || !storage.ID(tenant) || !storage.ID(node) || !storage.ID(domain) || !p.Allows(tenant, domain) || !oneOfRole(p, "owner", "operator", "viewer", "recovery") {
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
		now := time.Now()
		enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
		if e != nil || enrollment.Tenant != tenant || !enrollment.Active(now) {
			return ErrDenied
		}
		admission, ok := enrollment.Domain(domain)
		fence := s.Domains[domain]
		if !ok || fence.Tenant != tenant || fence.Repository != admission.Repository || fence.Epoch != admission.Epoch {
			return ErrDenied
		}
		cfg, raw, e := r.configuration(ctx, s, node)
		if e != nil {
			return e
		}
		d, ok := cfg.DomainByID(domain)
		if !ok || d.Trust.Repository != admission.Repository || d.Trust.Epoch != admission.Epoch {
			return ErrUnavailable
		}
		out.Tenant = tenant
		out.Node = node
		out.Domain = domain
		out.Repository = d.Trust.Repository
		out.WriterEpoch = d.Trust.Epoch
		out.ConfigurationRevision = cfg.Revision
		out.ConfigurationDigest = storage.Hash(raw)
		out.ExpiresUnix = cfg.ExpiresUnix
		active := cfg.Active(now) == nil
		out.ConfigurationState = "INACTIVE"
		if active {
			out.ConfigurationState = "ACTIVE"
		}
		out.Placement = d.Placement
		// Nil lists are explicit empty arrays in the public contract.
		out.Placement.AllowedClasses = append([]string{}, d.Placement.AllowedClasses...)
		out.Placement.Holders = append([]string{}, d.Placement.Holders...)
		out.Placement.Transit = append([]string{}, d.Placement.Transit...)
		out.Placement.Targets = append([]string{}, d.Placement.Targets...)
		out.Placement.Edges = append([]policy.Edge{}, d.Placement.Edges...)
		out.Placement.CloudEdges = append([]policy.CloudEdge{}, d.Placement.CloudEdges...)
		members := map[string]bool{node: true}
		for _, id := range append(append([]string{}, d.Placement.Holders...), d.Placement.Transit...) {
			members[id] = true
		}
		for _, n := range cfg.Nodes {
			if members[n.ID] {
				out.Nodes = append(out.Nodes, PolicyNode{n.ID, n.Class})
			}
		}
		for _, id := range d.Placement.Targets {
			target, ok := cfg.TargetByID(id)
			if !ok {
				return ErrInvalid
			}
			out.Targets = append(out.Targets, PolicyTarget{id, target.Profile.Kind, target.Profile.MaxObjectBytes})
		}
		for _, raw := range cfg.Ingress {
			if e := ctx.Err(); e != nil {
				return e
			}
			g, e := ingress.VerifyAuthorityDocument(raw, r.owner)
			if e != nil {
				return e
			}
			if g.Tenant != tenant || g.Trust.Domain != domain {
				continue
			}
			state := "INACTIVE"
			if active && g.NotBefore <= now.Unix() && now.Unix() < g.ExpiresUnix {
				state = "ACTIVE"
			}
			out.Sources = append(out.Sources, PolicySource{g.Source, g.Profile, g.Ingress, g.Revision, g.ExpiresUnix, state})
		}
		// A pending enrollment blocks command admission on this node. Do not
		// advertise grants that the existing mutation path cannot currently use.
		pending := false
		for _, op := range s.Operations {
			if op.Receipt.State == "ADMITTED" {
				next, e := VerifyEnrollment(op.Document, r.owner)
				if e != nil {
					return e
				}
				if next.Node == node {
					pending = true
				}
			}
		}
		if active && !pending {
			for _, raw := range cfg.Commands {
				if e := ctx.Err(); e != nil {
					return e
				}
				a, e := command.VerifyAuthority(raw, r.owner)
				if e != nil {
					return e
				}
				if a.Active(now) != nil || a.Tenant != tenant || a.Domain != domain || a.Node != node || command.Identity(a.Service) != identity(r.signer.Public().(ed25519.PublicKey)) {
					continue
				}
				kinds := []string{}
				for _, kind := range a.Kinds {
					if commandRole(p, kind) {
						kinds = append(kinds, kind)
					}
				}
				if len(kinds) == 0 {
					continue
				}
				sort.Strings(kinds)
				expires := min(a.ExpiresUnix, cfg.ExpiresUnix, enrollment.ExpiresUnix, now.Unix()+86400)
				out.Capabilities = append(out.Capabilities, CommandCapability{Authority: append([]byte(nil), raw...), Kinds: kinds, ExpiresUnix: expires})
			}
		}
		sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
		sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].ID < out.Targets[j].ID })
		encoded, e := json.Marshal(out)
		if e != nil {
			return e
		}
		if len(encoded) > MaxDomainPolicy {
			return ErrCapacity
		}
		return nil
	})
	return out, e
}
