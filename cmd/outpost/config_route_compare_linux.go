package main

import (
	"maps"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
)

type routeConfigIdentity struct {
	Node         string `json:"node"`
	Revision     uint64 `json:"revision"`
	ConfigDigest string `json:"configDigest"`
}

func (c signedRouteConfig) identity() routeConfigIdentity {
	return routeConfigIdentity{Node: c.config.Node, Revision: c.config.Revision, ConfigDigest: c.digest}
}

type routeComparison struct {
	Format      string              `json:"format"`
	Domain      string              `json:"domain"`
	Primary     routeConfigIdentity `json:"primary"`
	Peer        routeConfigIdentity `json:"peer"`
	Consistent  bool                `json:"consistent"`
	Differences []string            `json:"differences"`
}

func samePlacementSet[T comparable](a, b []T) bool {
	// Verified placements already reject duplicates.
	if len(a) != len(b) {
		return false
	}
	for _, value := range a {
		if !slices.Contains(b, value) {
			return false
		}
	}
	return true
}

func (c signedRouteConfig) peerNodes() map[string]policy.Node {
	nodes := make(map[string]policy.Node)
	for _, node := range c.config.Nodes {
		if c.domain.Placement.PermitsNode(node.ID) {
			nodes[node.ID] = node
		}
	}
	return nodes
}

func compareConfigRoutes(input, peerInput, trustFile, node, peer, domain string, now time.Time) (routeComparison, error) {
	var report routeComparison
	if !storage.ID(node) || !storage.ID(peer) || node == peer || !storage.ID(domain) {
		return report, errUsage
	}
	owner, err := readRouteOwner(trustFile)
	if err != nil {
		return report, err
	}
	first, err := readSignedRouteConfig(input, owner, node, domain, now)
	if err != nil {
		return report, err
	}
	second, err := readSignedRouteConfig(peerInput, owner, peer, domain, now)
	if err != nil {
		return report, err
	}
	a, b := first.domain.Placement, second.domain.Placement
	differences := []string{}
	if !observation.SameTrust(first.domain.Trust, second.domain.Trust) {
		differences = append(differences, "DOMAIN_TRUST")
	}
	if slices.Contains(a.AllowedClasses, "trusted") != slices.Contains(b.AllowedClasses, "trusted") ||
		slices.Contains(a.AllowedClasses, "untrusted") != slices.Contains(b.AllowedClasses, "untrusted") {
		differences = append(differences, "PEER_CLASSES")
	}
	if !samePlacementSet(a.Holders, b.Holders) {
		differences = append(differences, "HOLDERS")
	}
	if !samePlacementSet(a.Transit, b.Transit) {
		differences = append(differences, "TRANSIT")
	}
	if !samePlacementSet(a.Edges, b.Edges) {
		differences = append(differences, "PEER_EDGES")
	}
	if !maps.Equal(first.peerNodes(), second.peerNodes()) {
		differences = append(differences, "PEER_NODES")
	}
	return routeComparison{
		Format: "outpost-config-route-compare-1", Domain: domain,
		Primary: first.identity(), Peer: second.identity(),
		Consistent: len(differences) == 0, Differences: differences,
	}, nil
}
