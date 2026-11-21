package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/storage"
)

func TestOwnerCommandAuthorityNeedsExactCurrentPolicyAndMatchingScope(t *testing.T) {
	c, owner := configFixture(t)
	service, _ := key(t)
	d := c.Domains[0].Trust
	a := command.Authority{Format: command.AuthorityFormat, Service: service, Node: c.Node, Tenant: storage.Hash([]byte("tenant")), Domain: d.Domain, Repository: d.Repository, WriterEpoch: d.Epoch, AuthorityEpoch: 1, Kinds: []string{"pause", "resume", "retry"}, NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix}
	grant, e := command.SignAuthority(a, owner)
	must(t, e)
	c.Commands = []json.RawMessage{grant}
	raw, e := Sign(c, owner)
	must(t, e)
	parsed, e := Verify(raw, owner.Public().(ed25519.PublicKey), c.Node)
	must(t, e)
	_, e = parsed.CommandAuthority(grant, owner.Public().(ed25519.PublicKey), time.Now())
	must(t, e)
	parsed.Commands = nil
	if _, e = parsed.CommandAuthority(grant, owner.Public().(ed25519.PublicKey), time.Now()); e == nil {
		t.Fatal("detached authority bypassed revocation")
	}
	for _, mutate := range []func(*command.Authority){func(a *command.Authority) { a.Node = c.Nodes[1].ID }, func(a *command.Authority) { a.Repository = storage.Hash([]byte("foreign")) }, func(a *command.Authority) { a.WriterEpoch++ }, func(a *command.Authority) { a.NotBefore = c.ExpiresUnix; a.ExpiresUnix = c.ExpiresUnix + 60 }} {
		next := a
		mutate(&next)
		signed, e := command.SignAuthority(next, owner)
		must(t, e)
		bad := c
		bad.Commands = []json.RawMessage{signed}
		if _, e = Sign(bad, owner); e == nil {
			t.Fatal("mismatched command grant admitted")
		}
	}
	dup := c
	dup.Commands = append(append([]json.RawMessage{}, c.Commands...), grant)
	if _, e = Sign(dup, owner); e == nil {
		t.Fatal("ambiguous duplicate service/domain")
	}
	untrusted := c
	untrusted.Node = c.Nodes[2].ID
	untrustedGrant := a
	untrustedGrant.Node = untrusted.Node
	untrustedGrant.Kinds = []string{"restore"}
	signed, e := command.SignAuthority(untrustedGrant, owner)
	must(t, e)
	untrusted.Commands = []json.RawMessage{signed}
	if _, e = Sign(untrusted, owner); e == nil {
		t.Fatal("untrusted restore authority admitted")
	}
}
