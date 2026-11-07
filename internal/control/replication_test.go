package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/nd4y/outpost/internal/storage"
)

func TestAutonomousReplicationRequiresExplicitCurrentEdge(t *testing.T) {
	c, key := configFixture(t)
	d := c.Domains[0]
	r := Replication{Domain: d.Trust.Domain, From: c.Nodes[0].ID, To: c.Nodes[1].ID, Mode: "push", Epoch: 1, PeerRevision: 1}
	job := r.Job(d.Trust, storage.Hash([]byte("generation")))
	if c.Autonomous(job) {
		t.Fatal("placement alone enabled discovery")
	}
	c.Replication = []Replication{r}
	raw, e := Sign(c, key)
	must(t, e)
	verified, e := Verify(raw, key.Public().(ed25519.PublicKey), c.Node)
	must(t, e)
	if !verified.Autonomous(job) {
		t.Fatal("signed rule unavailable")
	}
	wrong := job
	wrong.Generation = storage.Hash([]byte("different"))
	if c.Autonomous(wrong) {
		t.Fatal("operation not bound to generation")
	}
	wrong = job
	wrong.Peer = c.Nodes[2].ID
	if c.Autonomous(wrong) {
		t.Fatal("unauthorized route accepted")
	}
	for _, mutate := range []func(*Replication){func(r *Replication) { r.To = c.Nodes[2].ID }, func(r *Replication) { r.Mode = "pull" }, func(r *Replication) { r.Epoch = 0 }, func(r *Replication) { r.PeerRevision = 0 }} {
		bad := r
		mutate(&bad)
		copy := c
		copy.Replication = []Replication{bad}
		if _, e := Sign(copy, key); e == nil {
			t.Fatal("invalid autonomous rule signed", bad)
		}
	}
	duplicate := r
	duplicate.Epoch++
	c.Replication = append(c.Replication, duplicate)
	if _, e := Sign(c, key); e == nil {
		t.Fatal("competing incarnations on same edge accepted")
	}
}
