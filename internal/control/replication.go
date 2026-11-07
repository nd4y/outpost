package control

import (
	"encoding/json"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

// Replication explicitly delegates discovery and acquisition of all retained
// complete generations along one already permitted placement edge. Placement
// alone never starts work. Epoch is the owner-selected route incarnation.
type Replication struct {
	Domain       string `json:"domain"`
	From         string `json:"from"`
	To           string `json:"to"`
	Mode         string `json:"mode"`
	Epoch        uint64 `json:"epoch"`
	PeerRevision uint64 `json:"peerRevision"`
}

func (r Replication) Executor() string {
	if r.Mode == "pull" {
		return r.To
	}
	return r.From
}
func (r Replication) Peer() string {
	if r.Mode == "pull" {
		return r.From
	}
	return r.To
}
func (r Replication) ID(t generation.Trust) string {
	raw, _ := json.Marshal(struct {
		Format string
		Rule   Replication
		Trust  generation.Trust
	}{"outpost-replication-rule-1", r, t})
	return storage.Hash(raw)
}
func (r Replication) Job(t generation.Trust, id string) Job {
	return Job{PeerRevision: r.PeerRevision, Operation: storage.Hash([]byte(r.ID(t) + "/" + id)), Executor: r.Executor(), Kind: r.Mode, Domain: r.Domain, Generation: id, Peer: r.Peer()}
}
func (c Config) Autonomous(j Job) bool {
	if j.Kind == "upload" {
		return c.AutonomousUpload(j)
	}
	if !storage.ID(j.Generation) {
		return false
	}
	d, ok := c.DomainByID(j.Domain)
	if !ok {
		return false
	}
	actual, _ := json.Marshal(j)
	for _, r := range c.Replication {
		if r.Domain != j.Domain {
			continue
		}
		expected, _ := json.Marshal(r.Job(d.Trust, j.Generation))
		if string(actual) == string(expected) {
			return true
		}
	}
	return false
}
