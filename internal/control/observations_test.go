package control

import (
	"encoding/json"
	"testing"

	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestObservationGrantCannotExpandPlacementOrReaderAuthority(t *testing.T) {
	c, key := configFixture(t)
	c.Node = c.Nodes[1].ID
	g := observation.Grant{Format: observation.GrantFormat, Trust: c.Domains[0].Trust, Reader: c.Nodes[0].ID, Collector: c.Node, Targets: []string{c.Nodes[2].ID}, Epoch: 1, NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix, MaxAgeSeconds: 3600}
	grant, e := observation.SignGrant(g, key)
	must(t, e)
	c.Observations = []json.RawMessage{grant}
	_, e = Sign(c, key)
	must(t, e)
	for _, mutate := range []func(*observation.Grant){func(g *observation.Grant) { g.Reader = c.Nodes[2].ID; g.Targets = []string{c.Nodes[0].ID} }, func(g *observation.Grant) { g.Targets = []string{c.Node} }, func(g *observation.Grant) { g.Collector = storage.Hash([]byte("unknown")) }, func(g *observation.Grant) { g.Trust.Repository = storage.Hash([]byte("other")) }, func(g *observation.Grant) { g.ExpiresUnix-- }} {
		bad := g
		mutate(&bad)
		raw, e := observation.SignGrant(bad, key)
		must(t, e)
		copy := c
		copy.Observations = []json.RawMessage{raw}
		if _, e = Sign(copy, key); e == nil {
			t.Fatal("observation expanded authority", bad)
		}
	}
	c.Observations = append(c.Observations, grant)
	if _, e = Sign(c, key); e == nil {
		t.Fatal("duplicate observation grant accepted")
	}
}
