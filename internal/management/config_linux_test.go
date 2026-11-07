package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/statefile"
)

func configFixture(t *testing.T, f *fixture) control.Config {
	pub := func() ed25519.PublicKey { p, _, e := ed25519.GenerateKey(rand.Reader); must(t, e); return p }
	return control.Config{Format: control.Format, Node: f.e.Node, Revision: 1, NotBefore: time.Now().Unix() - 60, ExpiresUnix: time.Now().Unix() + 1800, Limits: control.Limits{Parallel: 1, AttemptMillis: 1000, PollSeconds: 1, CapacityBytes: 64 << 20, ReserveBytes: 8 << 20, SpoolBytes: 16 << 20, TelemetryBytes: 1 << 20}, Nodes: []policy.Node{{ID: f.e.Node, Class: "trusted", Endpoint: "https://node.invalid"}}, Domains: []control.Domain{{Trust: generation.Trust{Domain: id("domain"), Repository: id("repository"), Epoch: 1, Writer: pub(), Maintenance: pub()}, Planner: pub(), Placement: policy.Placement{Domain: id("domain"), AllowedClasses: []string{"trusted"}, Holders: []string{f.e.Node}}}}}
}
func configurationMutation(t *testing.T, f *fixture, c control.Config, operation string, expected uint64) SignedMutation {
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	return SignedMutation{Operation: id(operation), Reason: "POLICY_CHANGE", Document: raw, Expected: expected}
}
func TestManagementConfigurationPreviewExactApplyReplayAndTenantBoundary(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enroll(t)
	c := configFixture(t, f)
	input := configurationMutation(t, f, c, "config-one", 0)
	preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	if preview.CurrentRevision != 0 || preview.CandidateRevision != 1 || preview.EstimatedBytes != nil || preview.CapacityState != "UNKNOWN" || len(preview.ChangedDomains) != 1 {
		t.Fatal("wrong preview", preview)
	}
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input); !errors.Is(e, ErrDenied) {
		t.Fatal("missing candidate binding accepted", e)
	}
	input.PreviewDigest = preview.CandidateDigest
	first, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	again, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	if first != again {
		t.Fatal("configuration retry changed effect")
	}
	node := Principal{Actor: f.e.Node, Roles: []string{"node"}, Scopes: []Scope{{f.e.Tenant, id("domain")}}}
	current, e := f.r.Configuration(ctx, node, f.e.Tenant, f.e.Node)
	must(t, e)
	if !bytes.Equal(current.Document, input.Document) || current.Revision != 1 {
		t.Fatal("node received different signed bytes")
	}
	operator := f.p
	operator.Roles = []string{"operator"}
	if _, e = f.r.ApplyConfiguration(ctx, operator, f.e.Tenant, f.e.Node, input); !errors.Is(e, ErrDenied) {
		t.Fatal("operator published owner policy", e)
	}
	c.Revision = 2
	c.Limits.Parallel = 2
	next := configurationMutation(t, f, c, "config-two", 1)
	p2, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, next)
	must(t, e)
	next.PreviewDigest = p2.CandidateDigest
	c.Revision = 3
	third := configurationMutation(t, f, c, "config-three", 1)
	p3, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, third)
	must(t, e)
	third.PreviewDigest = p3.CandidateDigest
	_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, next)
	must(t, e)
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, third); !errors.Is(e, ErrConflict) {
		t.Fatal("stale preview applied", e)
	}
	foreign := f.p
	foreign.Scopes = []Scope{{id("foreign-tenant"), id("domain")}}
	if _, e = f.r.Configuration(ctx, foreign, id("foreign-tenant"), f.e.Node); e == nil {
		t.Fatal("foreign owner read configuration")
	}
	c.Revision = 3
	c.Nodes = append(c.Nodes, policy.Node{ID: id("unenrolled"), Class: "trusted"})
	bad := configurationMutation(t, f, c, "config-foreign", 2)
	if _, e = f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, bad); !errors.Is(e, ErrDenied) {
		t.Fatal("unenrolled recipient previewed", e)
	}
	audit, _, e := f.r.Audit(ctx, f.p, f.e.Tenant, 0, 256)
	must(t, e)
	if len(audit) != 3 || audit[1].Action != "APPLY_CONFIG" {
		t.Fatal("configuration audit missing", audit)
	}
}
func TestManagementConfigurationLostCacheAcknowledgementAndQuota(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enroll(t)
	c := configFixture(t, f)
	input := configurationMutation(t, f, c, "config", 0)
	preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	input.PreviewDigest = preview.CandidateDigest
	f.r.Fault = func(p string) error {
		if p == "management-config-cache-durable" {
			return errors.New("lost cache acknowledgement")
		}
		return nil
	}
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input); e == nil {
		t.Fatal("cache fault absent")
	}
	if _, e = f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node); !errors.Is(e, ErrConflict) {
		t.Fatal("unacknowledged cache published", e)
	}
	f.reopen(t)
	receipt, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	if receipt.State != "COMPLETE" {
		t.Fatal(receipt)
	}
	c.Revision++
	next := configurationMutation(t, f, c, "config-two", 1)
	preview, e = f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, next)
	must(t, e)
	next.PreviewDigest = preview.CandidateDigest
	f.r.blobs.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, next); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("candidate bypassed quota", e)
	}
	current, e := f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node)
	must(t, e)
	if current.Revision != 1 {
		t.Fatal("capacity failure replaced current policy")
	}
}

func TestManagementConfigurationInitialCacheIsQuotaAccounted(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enroll(t)
	c := configFixture(t, f)
	input := configurationMutation(t, f, c, "initial-cache", 0)
	preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	input.PreviewDigest = preview.CandidateDigest
	f.r.admission = func(name string, size int) (func(bool) error, error) {
		if strings.HasPrefix(name, "config-") {
			return nil, statefile.ErrCapacity
		}
		return func(bool) error { return nil }, nil
	}
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("initial configuration cache bypassed admission", e)
	}
	f.r.admission = nil
	_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	current, e := f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node)
	must(t, e)
	if current.Revision != 1 {
		t.Fatal("quota retry lost intent")
	}
}
