package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
)

func domainPolicyFixture(t *testing.T, h *httpFixture) control.Config {
	f := h.f
	f.e.Domains = append(f.e.Domains, DomainAdmission{id("second-domain"), id("second-repository"), 1})
	cfg, _, _ := commandFixture(t, f)
	cfg.Revision++
	second := cfg.Domains[0]
	second.Trust.Domain = id("second-domain")
	second.Trust.Repository = id("second-repository")
	cfg.Domains = append(cfg.Domains, second)
	for i := range cfg.Domains {
		d := &cfg.Domains[i]
		pub, _, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		source := command.Identity(pub)
		enrollment := f.e
		enrollment.Node = source
		enrollment.PublicKey = pub
		enrollment.Domains = []DomainAdmission{{d.Trust.Domain, d.Trust.Repository, 1}}
		raw, e := SignEnrollment(enrollment, f.owner)
		must(t, e)
		_, e = f.r.ApplyEnrollment(context.Background(), f.p, id("source-enroll/"+d.Trust.Domain), "INITIAL_ENROLLMENT", raw, 0)
		must(t, e)
		cfg.Nodes = append(cfg.Nodes, policy.Node{ID: source, Class: "trusted", Endpoint: "https://private-source.invalid"})
		target := storage.Profile{Kind: "webdav", Endpoint: "https://private-target.invalid", Namespace: storage.Hash([]byte(d.Trust.Domain + "/" + d.Trust.Repository)), MaxObjectBytes: 65536, Concurrency: 1, RequestsPerSecond: 1, Attempts: 1, TimeoutMillis: 1000, CredentialScope: "namespace", NoDelete: true}
		cfg.Targets = append(cfg.Targets, control.Target{ID: target.ID(), Profile: target})
		d.Placement = policy.Placement{Domain: d.Trust.Domain, AllowedClasses: []string{"trusted", "external"}, Holders: []string{f.e.Node}, Transit: []string{source}, Targets: []string{target.ID()}, Edges: []policy.Edge{{From: source, To: f.e.Node, Mode: "push"}}, CloudEdges: []policy.CloudEdge{{Node: f.e.Node, Target: target.ID()}}}
		grant := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: f.e.Tenant, Profile: id("profile/" + d.Trust.Domain), Source: source, Ingress: f.e.Node, Revision: cfg.Revision, NotBefore: cfg.NotBefore, ExpiresUnix: cfg.ExpiresUnix, Trust: d.Trust, MaxObjects: 128, MaxBytes: 64 << 20}
		raw, e = ingress.SignAuthority(grant, f.owner)
		must(t, e)
		cfg.Ingress = append(cfg.Ingress, raw)
	}
	mutation := configurationMutation(t, f, cfg, "domain-policy", 1)
	mutation.PreviewDigest = storage.Hash(mutation.Document)
	_, e := f.r.ApplyConfiguration(context.Background(), f.p, f.e.Tenant, f.e.Node, mutation)
	must(t, e)
	return cfg
}
func TestManagementDomainPolicyHTTPSIsScopedAndGrantsCurrentRoles(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	cfg := domainPolicyFixture(t, h)
	ctx := context.Background()
	path := h.base() + "/domains/" + id("domain") + "/policy"
	status, raw := h.request(t, h.owner, "GET", path, nil)
	if status != 200 {
		t.Fatalf("policy unavailable without reports: %d %s", status, raw)
	}
	var view DomainPolicy
	must(t, json.Unmarshal(raw, &view))
	if view.Format != DomainPolicyFormat || view.ConfigurationRevision != cfg.Revision || view.ConfigurationState != "ACTIVE" || len(view.Nodes) != 2 || len(view.Targets) != 1 || len(view.Sources) != 1 || len(view.Capabilities) != 1 || len(view.Capabilities[0].Kinds) != 6 {
		t.Fatalf("unexpected view %+v", view)
	}
	for _, private := range []string{"private-source.invalid", "private-target.invalid", id("second-domain"), id("second-repository"), cfg.Targets[1].ID, cfg.Domains[1].Placement.Transit[0]} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("unrelated/private configuration disclosed", private)
		}
	}
	before, e := os.ReadFile(filepath.Join(f.dir, "registry.json"))
	must(t, e)
	for _, row := range []struct {
		role  string
		count int
	}{{"owner", 6}, {"operator", 4}, {"viewer", 0}, {"recovery", 1}} {
		p := f.p
		p.Roles = []string{row.role}
		v, e := f.r.DomainPolicy(ctx, p, f.e.Tenant, f.e.Node, id("domain"))
		must(t, e)
		count := 0
		for _, c := range v.Capabilities {
			count += len(c.Kinds)
			if !bytes.Equal(c.Authority, cfg.Commands[0]) {
				t.Fatal("grant re-signed")
			}
		}
		if count != row.count {
			t.Fatalf("%s got %d kinds", row.role, count)
		}
	}
	after, e := os.ReadFile(filepath.Join(f.dir, "registry.json"))
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("policy view changed registry")
	}
	limited := f.p
	limited.Scopes = limited.Scopes[:1]
	if _, e = f.r.DomainPolicy(ctx, limited, f.e.Tenant, f.e.Node, id("second-domain")); !errors.Is(e, ErrDenied) {
		t.Fatal("scope expanded", e)
	}
	if status, _ = h.request(t, h.unknown, "GET", path, nil); status != 403 {
		t.Fatal("unknown actor read policy")
	}
	if status, _ = h.request(t, h.owner, "GET", path+"?limit=1", nil); status != 400 {
		t.Fatal("unknown policy query accepted")
	}
	input := command.Request{Operation: id("from-domain-view"), Reason: "OPERATOR_REQUEST", Tenant: f.e.Tenant, Domain: view.Domain, Kind: "pause", ExpectedRevision: view.ConfigurationRevision, Authority: view.Capabilities[0].Authority, ExpiresUnix: time.Now().Unix() + 60}
	status, _ = h.request(t, h.owner, "POST", h.base()+"/commands", input)
	if status != 202 {
		t.Fatal("offered capability unusable", status)
	}
}
func TestManagementDomainPolicyExpiredGrantAndPendingRevocationOfferNoCommands(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	cfg := domainPolicyFixture(t, h)
	ctx := context.Background()
	grant, e := command.VerifyAuthority(cfg.Commands[0], f.owner.Public().(ed25519.PublicKey))
	must(t, e)
	grant.ExpiresUnix = time.Now().Unix() - 1
	raw, e := command.SignAuthority(grant, f.owner)
	must(t, e)
	cfg.Commands = []json.RawMessage{raw}
	cfg.Revision++
	input := configurationMutation(t, f, cfg, "expired-domain-grant", cfg.Revision-1)
	input.PreviewDigest = storage.Hash(input.Document)
	_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	v, e := f.r.DomainPolicy(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"))
	must(t, e)
	if v.ConfigurationState != "ACTIVE" || len(v.Capabilities) != 0 {
		t.Fatal("expired grant offered")
	}
	grant.ExpiresUnix = cfg.ExpiresUnix
	raw, e = command.SignAuthority(grant, f.owner)
	must(t, e)
	cfg.Commands = []json.RawMessage{raw}
	cfg.Revision++
	input = configurationMutation(t, f, cfg, "renew-domain-grant", cfg.Revision-1)
	input.PreviewDigest = storage.Hash(input.Document)
	_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	f.e.Revision++
	f.e.Revoked = true
	raw, e = SignEnrollment(f.e, f.owner)
	must(t, e)
	f.r.Fault = interruptAt("management-enrollment-intent-durable")
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("pending-revoke"), "REVOKE", raw, f.e.Revision-1)
	if e == nil {
		t.Fatal("missing fault")
	}
	f.reopen(t)
	v, e = f.r.DomainPolicy(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"))
	must(t, e)
	if len(v.Capabilities) != 0 {
		t.Fatal("pending enrollment advertised commands")
	}
	_, e = f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
	must(t, e)
	if _, e = f.r.DomainPolicy(ctx, f.p, f.e.Tenant, f.e.Node, id("domain")); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked node policy offered", e)
	}
}
