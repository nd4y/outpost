package control

import (
	"testing"

	"github.com/nd4y/outpost/internal/storage"
)

func TestCompiledAutonomyIsExactImmutableConfigurationView(t *testing.T) {
	c, _ := configFixture(t)
	r := Replication{Domain: c.Domains[0].Trust.Domain, From: c.Nodes[0].ID, To: c.Nodes[1].ID, Mode: "push", Epoch: 1, PeerRevision: 1}
	c.Replication = []Replication{r}
	scope, e := c.CompileAutonomy()
	must(t, e)
	j := r.Job(c.Domains[0].Trust, storage.Hash([]byte("generation")))
	if !scope.Permits(j) {
		t.Fatal("compiled rule lost")
	}
	for _, mutate := range []func(*Job){func(j *Job) { j.Generation = storage.Hash([]byte("other")) }, func(j *Job) { j.Executor = c.Nodes[2].ID }, func(j *Job) { j.Target = storage.Hash([]byte("target")) }, func(j *Job) { j.Delegation = storage.Hash([]byte("grant")) }, func(j *Job) { j.PeerRevision++ }, func(j *Job) { j.Plan = []byte("{}") }} {
		bad := j
		mutate(&bad)
		if scope.Permits(bad) {
			t.Fatal("compiled scope broadened")
		}
	}
	c.Replication = nil
	next, e := c.CompileAutonomy()
	must(t, e)
	if next.Permits(j) || !scope.Permits(j) {
		t.Fatal("configuration views were not independent")
	}
}
