package management

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

type cursor struct {
	Revision  uint64 `json:"revision"`
	Position  string `json:"position"`
	Binding   string `json:"binding"`
	Signature []byte `json:"signature,omitempty"`
}

func cursorBinding(p Principal, path string) string {
	raw, _ := json.Marshal(struct {
		Principal Principal
		Path      string
	}{p, path})
	return storage.Hash(raw)
}
func (r *Registry) readCursor(raw, binding string) (cursor, error) {
	var c cursor
	if raw == "" {
		return c, nil
	}
	if len(raw) > 512 {
		return c, ErrInvalid
	}
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil || canonical(b, &c, 512) != nil || c.Binding != binding || !safe(c.Revision) || len(c.Position) > 64 {
		return c, ErrConflict
	}
	sig := c.Signature
	c.Signature = nil
	payload, _ := json.Marshal(c)
	c.Signature = sig
	if !ed25519.Verify(r.signer.Public().(ed25519.PublicKey), append([]byte("outpost-management-cursor-1\x00"), payload...), sig) {
		return c, ErrConflict
	}
	return c, nil
}
func (r *Registry) writeCursor(revision uint64, position, binding string) string {
	c := cursor{Revision: revision, Position: position, Binding: binding}
	raw, _ := json.Marshal(c)
	c.Signature = ed25519.Sign(r.signer, append([]byte("outpost-management-cursor-1\x00"), raw...))
	raw, _ = json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

type NodeView struct {
	Node               string   `json:"node"`
	Tenant             string   `json:"tenant"`
	Domains            []string `json:"domains"`
	Class              string   `json:"class"`
	EnrollmentRevision uint64   `json:"enrollmentRevision"`
	Revoked            bool     `json:"revoked"`
	ReportSequence     uint64   `json:"reportSequence"`
	ObservedUnix       int64    `json:"observedUnix"`
	ReportState        string   `json:"reportState"`
}
type NodePage struct {
	Format     string     `json:"format"`
	Revision   uint64     `json:"revision"`
	Items      []NodeView `json:"items"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

func (r *Registry) Nodes(ctx context.Context, p Principal, tenant string, limit int, token, path string, maxAge time.Duration) (NodePage, error) {
	out := NodePage{Format: "outpost-management-nodes-1", Items: []NodeView{}}
	if p.Validate() != nil || !p.Allows(tenant, "") || !oneOfRole(p, "owner", "operator", "viewer", "recovery") || limit < 1 || limit > 256 || maxAge < time.Second || maxAge > 24*time.Hour {
		return out, ErrDenied
	}
	binding := cursorBinding(p, path)
	cur, e := r.readCursor(token, binding)
	if e != nil {
		return out, e
	}
	if token != "" && !storage.ID(cur.Position) {
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
		out.Revision = s.Revision
		if token != "" && cur.Revision != s.Revision {
			return ErrConflict
		}
		ids := []string{}
		for id := range s.Enrollments {
			if id > cur.Position {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			if e := ctx.Err(); e != nil {
				return e
			}
			enrollment, e := VerifyEnrollment(s.Enrollments[id], r.owner)
			if e != nil {
				return e
			}
			if enrollment.Tenant != tenant {
				continue
			}
			n := NodeView{Node: id, Tenant: tenant, Class: enrollment.Class, EnrollmentRevision: enrollment.Revision, Revoked: enrollment.Revoked, Domains: []string{}, ReportState: "CURRENT"}
			for _, d := range enrollment.Domains {
				if !p.Allows(tenant, d.Domain) {
					continue
				}
				n.Domains = append(n.Domains, d.Domain)
				report, ok := s.Reports[reportKey(id, d.Domain)]
				if !ok {
					n.ReportState = "MISSING"
					continue
				}
				n.ReportSequence = max(n.ReportSequence, report.Sequence)
				if n.ObservedUnix == 0 || report.ObservedUnix < n.ObservedUnix {
					n.ObservedUnix = report.ObservedUnix
				}
				if n.ReportState != "MISSING" && (time.Now().Unix()-report.ObservedUnix > int64(maxAge/time.Second) || report.EnrollmentRevision != enrollment.Revision) {
					n.ReportState = "STALE"
				}
			}
			if len(n.Domains) == 0 {
				continue
			}
			sort.Strings(n.Domains)
			if !enrollment.Active(time.Now()) && n.ReportState != "MISSING" {
				n.ReportState = "STALE"
			}
			if len(out.Items) == limit {
				last := out.Items[len(out.Items)-1].Node
				out.NextCursor = r.writeCursor(s.Revision, last, binding)
				break
			}
			out.Items = append(out.Items, n)
		}
		return nil
	})
	return out, e
}
func (r *Registry) NodePrincipal(ctx context.Context, actor string) (Principal, error) {
	var p Principal
	if !storage.ID(actor) {
		return p, ErrDenied
	}
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		enrollment, e := VerifyEnrollment(s.Enrollments[actor], r.owner)
		if e != nil || !enrollment.Active(time.Now()) {
			return ErrDenied
		}
		p = Principal{Actor: actor, Roles: []string{"node"}, Scopes: []Scope{}}
		for _, d := range enrollment.Domains {
			p.Scopes = append(p.Scopes, Scope{enrollment.Tenant, d.Domain})
		}
		return nil
	})
	return p, e
}

type AuditPage struct {
	Format     string  `json:"format"`
	Revision   uint64  `json:"revision"`
	Items      []Audit `json:"items"`
	NextCursor string  `json:"nextCursor,omitempty"`
}

func (r *Registry) AuditPage(ctx context.Context, p Principal, tenant string, limit int, token, path string) (AuditPage, error) {
	if limit < 1 || limit > 256 {
		return AuditPage{}, ErrInvalid
	}
	var out AuditPage
	binding := cursorBinding(p, path)
	cur, e := r.readCursor(token, binding)
	if e != nil {
		return out, e
	}
	var after uint64
	if token != "" {
		after, e = strconv.ParseUint(cur.Position, 10, 64)
		if e != nil || after > MaxSafeInteger {
			return out, ErrConflict
		}
	}
	// Fetch one additional record only when the requested page is below the
	// public maximum. At 256, a nonempty next page may be empty on the next read.
	fetch := min(limit+1, 256)
	items, revision, e := r.Audit(ctx, p, tenant, after, fetch)
	if e != nil {
		return out, e
	}
	if token != "" && cur.Revision != revision {
		return out, ErrConflict
	}
	out = AuditPage{Format: "outpost-management-audit-1", Revision: revision, Items: items}
	if len(items) > limit {
		out.Items = items[:limit]
	}
	if len(items) >= limit && limit > 0 {
		out.NextCursor = r.writeCursor(revision, strconv.FormatUint(out.Items[len(out.Items)-1].Sequence, 10), binding)
	}
	return out, nil
}
func (r *Registry) Operation(ctx context.Context, p Principal, tenant, operation string) (Receipt, error) {
	var out Receipt
	if p.Validate() != nil || !p.Allows(tenant, "") || !oneOfRole(p, "owner", "operator", "recovery") || !storage.ID(operation) {
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
		if v, ok := s.Resolutions[operation]; ok && !allowsDomains(p, tenant, v.Domains) {
			return ErrUnavailable
		}
		for _, v := range s.Resolutions {
			if v.Receipt.Operation == operation {
				if v.Audit.Tenant != tenant || !allowsDomains(p, tenant, v.Domains) {
					return ErrUnavailable
				}
				out = v.Receipt
				return nil
			}
		}
		if o, ok := s.Operations[operation]; ok {
			if o.Audit.Tenant != tenant {
				return ErrUnavailable
			}
			enrollment, e := VerifyEnrollment(o.Document, r.owner)
			if e != nil {
				return e
			}
			for _, d := range enrollment.Domains {
				if !p.Allows(tenant, d.Domain) {
					return ErrUnavailable
				}
			}
			out = resolutionReceipt(s, o.Receipt)
			return nil
		}
		if o, ok := s.ConfigOperations[operation]; ok {
			if o.Audit.Tenant != tenant {
				return ErrUnavailable
			}
			for _, d := range o.Domains {
				if !p.Allows(tenant, d) {
					return ErrUnavailable
				}
			}
			out = resolutionReceipt(s, o.Receipt)
			return nil
		}
		if o, ok := s.CommandOperations[operation]; ok {
			if o.Audit.Tenant != tenant || !p.Allows(tenant, o.Audit.Domain) {
				return ErrUnavailable
			}
			out = resolutionReceipt(s, o.Receipt)
			return nil
		}
		return ErrUnavailable
	})
	return out, e
}
