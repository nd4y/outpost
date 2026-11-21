package management

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/nd4y/outpost/internal/command"
)

func TestManagementCommandGrantPreviewAndTenantFence(t *testing.T) {
	f := newFixture(t)
	f.enroll(t)
	ctx := context.Background()
	c := configFixture(t, f)
	initial := configurationMutation(t, f, c, "command-config-initial", 0)
	preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, initial)
	must(t, e)
	initial.PreviewDigest = preview.CandidateDigest
	_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, initial)
	must(t, e)
	d := c.Domains[0].Trust
	a := command.Authority{Format: command.AuthorityFormat, Service: f.options.Signer.Public().(ed25519.PublicKey), Node: c.Node, Tenant: f.e.Tenant, Domain: d.Domain, Repository: d.Repository, WriterEpoch: d.Epoch, AuthorityEpoch: 1, Kinds: []string{"pause", "resume"}, NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix}
	grant, e := command.SignAuthority(a, f.owner)
	must(t, e)
	c.Revision++
	c.Commands = []json.RawMessage{grant}
	input := configurationMutation(t, f, c, "command-config-add", 1)
	preview, e = f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	visible := false
	for _, change := range preview.Changes {
		if change.Kind == "AUTHORITY" {
			visible = true
		}
	}
	if !visible || len(preview.ChangedDomains) != 1 {
		t.Fatal("command grant invisible in preview", preview)
	}
	a.Tenant = id("foreign-tenant")
	grant, e = command.SignAuthority(a, f.owner)
	must(t, e)
	c.Commands = []json.RawMessage{grant}
	foreign := configurationMutation(t, f, c, "command-config-foreign", 1)
	if _, e = f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, foreign); e == nil {
		t.Fatal("foreign-tenant command grant admitted")
	}
}
