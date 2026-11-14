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

func TestIntegrityRepairDelegationBindsTokenRouteAndOwnerPermission(t *testing.T) {
	c, key := configFixture(t)
	d := c.Domains[0]
	r := Replication{Domain: d.Trust.Domain, From: c.Nodes[0].ID, To: c.Nodes[1].ID, Mode: "push", Epoch: 1, PeerRevision: 1}
	id, token := storage.Hash([]byte("repair generation")), storage.Hash([]byte("damage incarnation"))
	c.Replication = []Replication{r}
	job := r.RepairJob(d.Trust, id, token)
	scope, e := c.CompileAutonomy()
	must(t, e)
	if c.Autonomous(job) || scope.Permits(job) {
		t.Fatal("ordinary discovery granted repair")
	}
	r.Repair = true
	c.Replication = []Replication{r}
	job = r.RepairJob(d.Trust, id, token)
	raw, e := Sign(c, key)
	must(t, e)
	c, e = Verify(raw, key.Public().(ed25519.PublicKey), c.Node)
	must(t, e)
	scope, e = c.CompileAutonomy()
	must(t, e)
	if !c.Autonomous(job) || !scope.Permits(job) {
		t.Fatal("signed repair missing")
	}
	for _, change := range []func(*Job){func(j *Job) { j.Repair = storage.Hash([]byte("new damage")) }, func(j *Job) { j.Repair = "bad" }, func(j *Job) { j.Generation = storage.Hash([]byte("other")) }, func(j *Job) { j.Peer = c.Nodes[2].ID }, func(j *Job) { j.Operation = r.Job(d.Trust, id).Operation }} {
		bad := job
		change(&bad)
		if c.Autonomous(bad) || scope.Permits(bad) {
			t.Fatal("repair binding widened", bad)
		}
	}
	c.Replication = nil
	withdrawn, e := c.CompileAutonomy()
	must(t, e)
	if withdrawn.Permits(job) || c.Autonomous(job) {
		t.Fatal("withdrawn repair remains active")
	}
}

func TestScheduledScrubRequiresBoundedSignedInterval(t *testing.T) {
	for _, seconds := range []int64{-1, 0, 1, 60, 30 * 24 * 3600, 30*24*3600 + 1} {
		c, key := configFixture(t)
		c.Domains[0].ScrubIntervalSeconds = seconds
		raw, e := Sign(c, key)
		valid := seconds >= 0 && seconds <= 30*24*3600
		if valid {
			must(t, e)
			verified, e := Verify(raw, key.Public().(ed25519.PublicKey), c.Node)
			must(t, e)
			if verified.Domains[0].ScrubIntervalSeconds != seconds {
				t.Fatal("signed schedule changed")
			}
		} else if e == nil {
			t.Fatal("unbounded schedule signed", seconds)
		}
	}
}
