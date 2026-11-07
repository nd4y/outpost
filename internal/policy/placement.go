package policy

import (
	"net/url"
	"sort"
	"strings"

	"github.com/nd4y/outpost/internal/storage"
)

type Node struct {
	ID       string `json:"id"`
	Class    string `json:"class"`
	Endpoint string `json:"endpoint,omitempty"`
}
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Mode string `json:"mode"`
}
type CloudEdge struct {
	Node   string `json:"node"`
	Target string `json:"target"`
}
type Placement struct {
	Domain         string      `json:"domain"`
	AllowedClasses []string    `json:"allowedClasses"`
	Holders        []string    `json:"holders"`
	Transit        []string    `json:"transit"`
	Targets        []string    `json:"targets"`
	Edges          []Edge      `json:"edges"`
	CloudEdges     []CloudEdge `json:"cloudEdges"`
}

func Endpoint(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(u.Path, "\\\x00\r\n") {
		return false
	}
	for _, s := range strings.Split(u.Path, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}
func (n Node) Validate() error {
	if !storage.ID(n.ID) || n.Class != "trusted" && n.Class != "untrusted" || n.Endpoint != "" && !Endpoint(n.Endpoint) {
		return ErrDenied
	}
	return nil
}
func member(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func ids(values []string) bool {
	if len(values) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !storage.ID(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func (p Placement) PermitsNode(id string) bool { return member(p.Holders, id) || member(p.Transit, id) }
func (p Placement) PermitsCloud(node, target string) bool {
	for _, e := range p.CloudEdges {
		if e.Node == node && e.Target == target {
			return true
		}
	}
	return false
}
func (p Placement) HasEdge(from, to, mode string) bool {
	for _, e := range p.Edges {
		if e.From == from && e.To == to && e.Mode == mode {
			return true
		}
	}
	return false
}
func (p Placement) Validate(nodes map[string]Node, targets map[string]storage.Profile) error {
	if !storage.ID(p.Domain) || len(p.Holders) == 0 || !ids(p.Holders) || !ids(p.Transit) || !ids(p.Targets) || len(p.AllowedClasses) == 0 || len(p.AllowedClasses) > 3 || len(p.Edges) > 512 || len(p.CloudEdges) > 512 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, c := range p.AllowedClasses {
		if c != "trusted" && c != "untrusted" && c != "external" || seen[c] {
			return ErrDenied
		}
		seen[c] = true
	}
	for _, id := range append(append([]string(nil), p.Holders...), p.Transit...) {
		n, ok := nodes[id]
		if !ok || n.ID != id || n.Validate() != nil || !seen[n.Class] {
			return ErrDenied
		}
	}
	for _, id := range p.Targets {
		t, ok := targets[id]
		if !ok || !seen["external"] || t.Validate() != nil {
			return ErrDenied
		}
	}
	edges := map[Edge]bool{}
	for _, e := range p.Edges {
		if e.From == e.To || !p.PermitsNode(e.From) || !p.PermitsNode(e.To) || e.Mode != "push" && e.Mode != "pull" || edges[e] {
			return ErrDenied
		}
		edges[e] = true
		server := e.To
		if e.Mode == "pull" {
			server = e.From
		}
		if nodes[server].Endpoint == "" {
			return ErrDenied
		}
	}
	cloud := map[CloudEdge]bool{}
	for _, e := range p.CloudEdges {
		if !p.PermitsNode(e.Node) || !member(p.Targets, e.Target) || cloud[e] {
			return ErrDenied
		}
		cloud[e] = true
	}
	return nil
}

// Route returns only owner-admitted data-flow edges. A pull edge is dialed by To,
// allowing an outbound-only recipient without inventing a reverse network route.
func (p Placement) Route(from, to string) ([]Edge, error) {
	if len(p.Edges) > 512 || !ids(p.Holders) || !ids(p.Transit) || !p.PermitsNode(from) || !member(p.Holders, to) {
		return nil, ErrDenied
	}
	for _, e := range p.Edges {
		if e.Mode != "push" && e.Mode != "pull" || !p.PermitsNode(e.From) || !p.PermitsNode(e.To) || e.From == e.To {
			return nil, ErrDenied
		}
	}
	if from == to {
		return []Edge{}, nil
	}
	type step struct {
		id    string
		route []Edge
	}
	pending := []step{{id: from}}
	seen := map[string]bool{from: true}
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		for _, e := range p.Edges {
			if e.From != current.id || seen[e.To] || !p.PermitsNode(e.To) {
				continue
			}
			route := append(append([]Edge(nil), current.route...), e)
			if e.To == to {
				return route, nil
			}
			seen[e.To] = true
			pending = append(pending, step{e.To, route})
		}
	}
	return nil, ErrDenied
}

type Change struct {
	Domain         string   `json:"domain"`
	AddedHolders   []string `json:"addedHolders"`
	RemovedHolders []string `json:"removedHolders"`
	AddedTransit   []string `json:"addedTransit"`
	RemovedTransit []string `json:"removedTransit"`
	AddedTargets   []string `json:"addedTargets"`
	RemovedTargets []string `json:"removedTargets"`
	RoutesChanged  bool     `json:"routesChanged"`
}

func difference(a, b []string) []string {
	r := []string{}
	for _, v := range a {
		if !member(b, v) {
			r = append(r, v)
		}
	}
	sort.Strings(r)
	return r
}
func Preview(before, after Placement) (Change, error) {
	if before.Domain != after.Domain || !storage.ID(after.Domain) {
		return Change{}, ErrDenied
	}
	routes := len(before.Edges) != len(after.Edges)
	m := map[Edge]bool{}
	for _, e := range before.Edges {
		m[e] = true
	}
	for _, e := range after.Edges {
		if !m[e] {
			routes = true
		}
	}
	cloud := map[CloudEdge]bool{}
	for _, e := range before.CloudEdges {
		cloud[e] = true
	}
	if len(before.CloudEdges) != len(after.CloudEdges) {
		routes = true
	}
	for _, e := range after.CloudEdges {
		if !cloud[e] {
			routes = true
		}
	}
	return Change{after.Domain, difference(after.Holders, before.Holders), difference(before.Holders, after.Holders), difference(after.Transit, before.Transit), difference(before.Transit, after.Transit), difference(after.Targets, before.Targets), difference(before.Targets, after.Targets), routes}, nil
}
