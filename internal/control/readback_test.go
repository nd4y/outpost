package control

import (
	"github.com/nd4y/outpost/internal/readback"
	"testing"
)

func TestReadbackPolicyRequiresExplicitBoundedOwnerConfiguration(t *testing.T) {
	c, key := configFixture(t)
	if c.Domains[0].PeerReadbackMaxAgeSeconds != 0 {
		t.Fatal("reuse enabled by default")
	}
	for _, age := range []int64{-1, readback.MaxAgeSeconds + 1} {
		c.Domains[0].PeerReadbackMaxAgeSeconds = age
		if _, e := Sign(c, key); e == nil {
			t.Fatal("unbounded reuse accepted")
		}
	}
	c.Domains[0].PeerReadbackMaxAgeSeconds = 3600
	if _, e := Sign(c, key); e != nil {
		t.Fatal(e)
	}
}
