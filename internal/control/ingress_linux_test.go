package control

import (
	"encoding/json"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
	"testing"
)

func TestIngressCapabilityRequiresCurrentPlacementAndIndependentSource(t *testing.T) {
	c, key := configFixture(t)
	c.Domains[0].Placement.Holders = append(c.Domains[0].Placement.Holders, c.Nodes[1].ID)
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: c.Nodes[0].ID, Ingress: c.Nodes[1].ID, Revision: 1, NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix, Trust: c.Domains[0].Trust, MaxBytes: 32 << 20, MaxObjects: 64}
	raw, e := ingress.SignAuthority(a, key)
	must(t, e)
	c.Ingress = []json.RawMessage{raw}
	signed, e := Sign(c, key)
	must(t, e)
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Domains[0].Placement.Edges = nil },
		func(c *Config) { c.Domains[0].Placement.Holders = c.Domains[0].Placement.Holders[:2] },
		func(c *Config) { c.Nodes[0].Class = "untrusted" },
		func(c *Config) { c.ExpiresUnix++ },
		func(c *Config) { c.NotBefore-- },
		func(c *Config) { c.Ingress = append(c.Ingress, c.Ingress[0]) },
		func(c *Config) { c.Node = c.Nodes[2].ID },
	} {
		var bad Config
		must(t, json.Unmarshal(signed, &bad))
		mutate(&bad)
		if _, e := Sign(bad, key); e == nil {
			t.Fatal("capability bypassed current placement")
		}
	}
	c.Revision++
	c.NotBefore++
	_, e = Sign(c, key)
	must(t, e)
}
