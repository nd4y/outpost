package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

func settlementConfig(t *testing.T) (Config, ed25519.PrivateKey) {
	t.Helper()
	c, key := configFixture(t)
	now := time.Now().Unix()
	c.Format = SettlementConfigFormat
	c.Node = c.Nodes[1].ID
	c.NotBefore = now - 1
	c.ExpiresUnix = now + 600
	c.Domains[0].Placement.Holders = append(c.Domains[0].Placement.Holders, c.Node)
	writer, writerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	c.Domains[0].Trust.Writer = writer
	id := func(s string) string { return storage.Hash([]byte(s)) }
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: id("tenant"), Profile: id("profile"), Source: c.Nodes[0].ID, Ingress: c.Node, Revision: 1, NotBefore: now - 100, ExpiresUnix: now - 10, Trust: c.Domains[0].Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	authority, e := ingress.SignAuthority(a, key)
	must(t, e)
	i := ingress.Intent{Format: ingress.IntentFormat, Operation: id("operation"), Authority: storage.Hash(authority), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: a.Trust.Epoch, Sequence: 1, Policy: 1, SnapshotUnix: now - 50, NotBefore: now - 50, ExpiresUnix: a.ExpiresUnix, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	intent, e := ingress.SignIntent(i, authority, key.Public().(ed25519.PublicKey), writerKey, time.Unix(i.NotBefore, 0))
	must(t, e)
	g := ingress.Settlement{Format: ingress.SettlementFormat, ID: id("settlement"), Authority: storage.Hash(authority), Intent: storage.Hash(intent), Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Generation: id("generation"), NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix}
	grant, e := ingress.SignSettlement(g, authority, intent, key, time.Now())
	must(t, e)
	c.Settlements = []SettlementAdmission{{Authority: authority, Intent: intent, Grant: grant}}
	return c, key
}

func TestSettlementControlFormatPreservesCurrentPlacementAndLegacySignatures(t *testing.T) {
	c, key := settlementConfig(t)
	owner := key.Public().(ed25519.PublicKey)
	raw, e := Sign(c, key)
	must(t, e)
	got, e := Verify(raw, owner, c.Node)
	must(t, e)
	must(t, got.Active(time.Now()))
	if _, e = ingress.VerifyAuthority(c.Settlements[0].Authority, owner, time.Now()); !errors.Is(e, ingress.ErrDenied) {
		t.Fatal("original write capability became current", e)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Format = Format },
		func(c *Config) { c.ExpiresUnix++ },
		func(c *Config) { c.NotBefore-- },
		func(c *Config) { c.Node = c.Nodes[0].ID },
		func(c *Config) { c.Nodes[0].Class = "untrusted" },
		func(c *Config) { c.Domains[0].Placement.Edges = nil },
		func(c *Config) { c.Domains[0].Placement.Holders = c.Domains[0].Placement.Holders[:2] },
		func(c *Config) { c.Domains[0].Trust.Epoch++ },
		func(c *Config) { c.Settlements = append(c.Settlements, c.Settlements[0]) },
		func(c *Config) { c.Ingress = []json.RawMessage{c.Settlements[0].Authority} },
	} {
		var bad Config
		must(t, json.Unmarshal(raw, &bad))
		mutate(&bad)
		if _, e = Sign(bad, key); !errors.Is(e, ErrDenied) {
			t.Fatal("settlement escaped current policy or version fence", e)
		}
	}
	legacy, key := configFixture(t)
	old, e := Sign(legacy, key)
	must(t, e)
	_, e = Verify(old, key.Public().(ed25519.PublicKey), legacy.Node)
	must(t, e)
	var unsigned Config
	must(t, json.Unmarshal(old, &unsigned))
	sig := unsigned.Signature
	unsigned.Signature = nil
	payload, e := json.Marshal(unsigned)
	must(t, e)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), append([]byte(Format+"\x00"), payload...), sig) {
		t.Fatal("changed legacy signature domain")
	}
}
