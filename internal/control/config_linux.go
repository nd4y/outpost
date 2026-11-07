// Package control verifies owner-signed per-node configuration. Neither a
// configuration relay nor a data writer can expand placement authority.
package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

const Format = "outpost-control-1"
const MaxConfig = 32 << 20

var ErrDenied = errors.New("configuration denied")
var ErrRollback = errors.New("configuration rollback or conflict")
var ErrInactive = errors.New("configuration is not active")

type Limits struct {
	Parallel       int   `json:"parallel"`
	AttemptMillis  int64 `json:"attemptMillis"`
	PollSeconds    int64 `json:"pollSeconds"`
	CapacityBytes  int64 `json:"capacityBytes"`
	ReserveBytes   int64 `json:"reserveBytes"`
	SpoolBytes     int64 `json:"spoolBytes"`
	TelemetryBytes int64 `json:"telemetryBytes"`
}

func (l Limits) Validate() error {
	if l.Parallel < 1 || l.Parallel > 4 || l.AttemptMillis < 100 || l.AttemptMillis > 300000 || l.PollSeconds < 1 || l.PollSeconds > 3600 || l.CapacityBytes < 16<<20 || l.CapacityBytes > 1<<60 || l.ReserveBytes < 1<<20 || l.ReserveBytes >= l.CapacityBytes || l.SpoolBytes < 4<<20 || l.SpoolBytes >= l.CapacityBytes-l.ReserveBytes || l.TelemetryBytes < 65536 || l.TelemetryBytes > 64<<20 || l.TelemetryBytes >= l.CapacityBytes-l.ReserveBytes-l.SpoolBytes {
		return ErrDenied
	}
	return nil
}

type Domain struct {
	PeerReadbackMaxAgeSeconds int64             `json:"peerReadbackMaxAgeSeconds,omitempty"`
	Trust                     generation.Trust  `json:"trust"`
	Planner                   ed25519.PublicKey `json:"planner"`
	Placement                 policy.Placement  `json:"placement"`
}
type Target struct {
	ID      string          `json:"id"`
	Profile storage.Profile `json:"profile"`
}

// A job contains opaque identifiers only. Storage credentials and plaintext
// source rules are provisioned locally and never carried in shared jobs.
type Job struct {
	PeerRevision uint64          `json:"peerRevision,omitempty"`
	Operation    string          `json:"operationId"`
	Executor     string          `json:"executor"`
	Kind         string          `json:"kind"`
	Domain       string          `json:"domain"`
	Generation   string          `json:"generation"`
	Peer         string          `json:"peer,omitempty"`
	Target       string          `json:"target,omitempty"`
	Plan         json.RawMessage `json:"plan,omitempty"`
	Delegation   string          `json:"delegation,omitempty"`
}
type Config struct {
	Format       string            `json:"format"`
	Node         string            `json:"node"`
	Revision     uint64            `json:"revision"`
	NotBefore    int64             `json:"notBefore"`
	ExpiresUnix  int64             `json:"expiresUnix"`
	Limits       Limits            `json:"limits"`
	Nodes        []policy.Node     `json:"nodes"`
	Targets      []Target          `json:"targets"`
	Domains      []Domain          `json:"domains"`
	Jobs         []Job             `json:"jobs"`
	Ingress      []json.RawMessage `json:"ingress,omitempty"`
	Replication  []Replication     `json:"replication,omitempty"`
	Observations []json.RawMessage `json:"observations,omitempty"`
	Uploads      []json.RawMessage `json:"uploads,omitempty"`
	Signature    []byte            `json:"signature,omitempty"`
}

func (c Config) NodeByID(id string) (policy.Node, bool) {
	for _, n := range c.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return policy.Node{}, false
}
func (c Config) DomainByID(id string) (Domain, bool) {
	for _, d := range c.Domains {
		if d.Trust.Domain == id {
			return d, true
		}
	}
	return Domain{}, false
}
func (c Config) TargetByID(id string) (Target, bool) {
	for _, t := range c.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return Target{}, false
}
func (c Config) Active(now time.Time) error {
	if now.Unix() < c.NotBefore || now.Unix() >= c.ExpiresUnix {
		return ErrInactive
	}
	return nil
}
func (c Config) validate(owner ed25519.PublicKey) error {
	if c.Format != Format || !storage.ID(c.Node) || c.Revision == 0 || c.NotBefore <= 0 || c.ExpiresUnix <= c.NotBefore || c.ExpiresUnix > 1<<40 || c.Limits.Validate() != nil || len(c.Nodes) < 1 || len(c.Nodes) > 128 || len(c.Targets) > 128 || len(c.Domains) > 128 || len(c.Jobs) > 64 || len(c.Ingress) > 128 || len(c.Replication) > 128 {
		return ErrDenied
	}
	nodes := map[string]policy.Node{}
	for _, n := range c.Nodes {
		if n.Validate() != nil {
			return ErrDenied
		}
		if _, ok := nodes[n.ID]; ok {
			return ErrDenied
		}
		nodes[n.ID] = n
	}
	if _, ok := nodes[c.Node]; !ok {
		return ErrDenied
	}
	targets := map[string]storage.Profile{}
	for _, t := range c.Targets {
		if t.Profile.Validate() != nil || t.ID != t.Profile.ID() {
			return ErrDenied
		}
		if _, ok := targets[t.ID]; ok {
			return ErrDenied
		}
		targets[t.ID] = t.Profile
	}
	domains := map[string]Domain{}
	for _, d := range c.Domains {
		if d.PeerReadbackMaxAgeSeconds < 0 || d.PeerReadbackMaxAgeSeconds > readback.MaxAgeSeconds {
			return ErrDenied
		}
		t := d.Trust
		if !storage.ID(t.Domain) || !storage.ID(t.Repository) || t.Epoch == 0 || len(t.Writer) != 32 || len(t.Maintenance) != 32 || len(d.Planner) != 32 || bytes.Equal(t.Writer, t.Maintenance) || bytes.Equal(t.Writer, d.Planner) || bytes.Equal(t.Maintenance, d.Planner) || bytes.Equal(owner, t.Writer) || bytes.Equal(owner, t.Maintenance) || bytes.Equal(owner, d.Planner) || d.Placement.Domain != t.Domain || d.Placement.Validate(nodes, targets) != nil {
			return ErrDenied
		}
		if _, ok := domains[t.Domain]; ok {
			return ErrDenied
		}
		domains[t.Domain] = d
		for _, id := range d.Placement.Targets {
			if targets[id].Namespace != storage.Hash([]byte(t.Domain+"/"+t.Repository)) {
				return ErrDenied
			}
		}
	}
	operations := map[string]bool{}
	if e := c.validateUploads(); e != nil {
		return e
	}
	if len(c.Observations) > 64 {
		return ErrDenied
	}
	observations := map[string]bool{}
	for _, raw := range c.Observations {
		g, e := observation.VerifyGrant(raw, owner)
		d, ok := domains[g.Trust.Domain]
		if e != nil || !ok || !observation.SameTrust(g.Trust, d.Trust) || g.NotBefore > c.NotBefore || g.ExpiresUnix < c.ExpiresUnix || (g.Collector != c.Node && !g.Target(c.Node)) || observations[storage.Hash(raw)] {
			return ErrDenied
		}
		reader, rok := nodes[g.Reader]
		collector, cok := nodes[g.Collector]
		if !rok || reader.Class != "trusted" || !cok || collector.Endpoint == "" || !d.Placement.PermitsNode(g.Collector) {
			return ErrDenied
		}
		for _, target := range g.Targets {
			holder := false
			for _, id := range d.Placement.Holders {
				if id == target {
					holder = true
				}
			}
			if !holder {
				return ErrDenied
			}
		}
		observations[storage.Hash(raw)] = true
	}
	routes := map[string]bool{}
	for _, r := range c.Replication {
		d, ok := domains[r.Domain]
		if !ok || r.Epoch == 0 || r.PeerRevision == 0 || (c.Node != r.From && c.Node != r.To) || !d.Placement.HasEdge(r.From, r.To, r.Mode) || r.Peer() == c.Node && r.PeerRevision > c.Revision {
			return ErrDenied
		}
		id := r.Domain + "/" + r.From + "/" + r.To + "/" + r.Mode
		if routes[id] {
			return ErrDenied
		}
		routes[id] = true
	}
	grants := map[string]bool{}
	for _, raw := range c.Ingress {
		a, e := ingress.VerifyAuthorityDocument(raw, owner)
		if e != nil || a.Revision > c.Revision || a.NotBefore > c.NotBefore || a.ExpiresUnix < c.ExpiresUnix || c.Node != a.Source && c.Node != a.Ingress {
			return ErrDenied
		}
		d, ok := domains[a.Trust.Domain]
		x, _ := json.Marshal(d.Trust)
		y, _ := json.Marshal(a.Trust)
		if !ok || !bytes.Equal(x, y) || nodes[a.Source].Class != "trusted" || !d.Placement.HasEdge(a.Source, a.Ingress, "push") {
			return ErrDenied
		}
		holder := false
		for _, id := range d.Placement.Holders {
			if id == a.Ingress {
				holder = true
			}
		}
		if !holder {
			return ErrDenied
		}
		binding := a.Trust.Domain + "/" + a.Ingress
		if grants[binding] {
			return ErrDenied
		}
		grants[binding] = true
	}
	for _, j := range c.Jobs {
		d, ok := domains[j.Domain]
		if !ok || j.Delegation != "" || !storage.ID(j.Operation) || !storage.ID(j.Generation) || operations[j.Operation] || !d.Placement.PermitsNode(c.Node) || !d.Placement.PermitsNode(j.Executor) {
			return ErrDenied
		}
		operations[j.Operation] = true
		switch j.Kind {
		case "push", "pull":
			if j.PeerRevision == 0 || c.Node == j.Peer && j.PeerRevision > c.Revision {
				return ErrDenied
			}
			if j.Target != "" || len(j.Plan) != 0 {
				return ErrDenied
			}
			if c.Node != j.Executor && c.Node != j.Peer {
				return ErrDenied
			}
			from, to := j.Executor, j.Peer
			if j.Kind == "pull" {
				from, to = to, from
			}
			if !d.Placement.HasEdge(from, to, j.Kind) {
				return ErrDenied
			}
		case "upload":
			if j.PeerRevision != 0 {
				return ErrDenied
			}
			if j.Executor != c.Node || j.Peer != "" || !d.Placement.PermitsCloud(c.Node, j.Target) {
				return ErrDenied
			}
			p, e := upload.Verify(j.Plan, upload.Authority{Generation: d.Trust, Planner: d.Planner})
			if e != nil || p.Operation != j.Operation || p.Generation != j.Generation || p.Profile.ID() != j.Target || p.ExpiresUnix > c.ExpiresUnix || p.StartMillis < c.NotBefore*1000 {
				return ErrDenied
			}
			self := false
			for _, w := range p.Workers {
				n, ok := nodes[w.ID]
				if !ok || n.Class != w.Class || !d.Placement.PermitsCloud(w.ID, j.Target) {
					return ErrDenied
				}
				if w.ID == c.Node {
					self = true
				}
			}
			if !self {
				return ErrDenied
			}
		default:
			return ErrDenied
		}
	}
	return nil
}
func Sign(c Config, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrDenied
	}
	if e := c.validate(key.Public().(ed25519.PublicKey)); e != nil {
		return nil, e
	}
	c.Signature = nil
	b, e := json.Marshal(c)
	if e != nil || len(b) > MaxConfig-128 {
		return nil, ErrDenied
	}
	c.Signature = ed25519.Sign(key, append([]byte(Format+"\x00"), b...))
	return json.Marshal(c)
}
func Verify(raw []byte, owner ed25519.PublicKey, node string) (Config, error) {
	var c Config
	if len(owner) != 32 || !storage.ID(node) || storage.Decode(raw, &c, MaxConfig) != nil || c.Node != node || len(c.Signature) != 64 {
		return Config{}, ErrDenied
	}
	sig := c.Signature
	c.Signature = nil
	b, e := json.Marshal(c)
	c.Signature = sig
	if e != nil || !ed25519.Verify(owner, append([]byte(Format+"\x00"), b...), sig) {
		return Config{}, ErrDenied
	}
	if e = c.validate(owner); e != nil {
		return Config{}, e
	}
	return c, nil
}
