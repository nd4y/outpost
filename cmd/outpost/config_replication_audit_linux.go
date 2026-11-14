package main

import (
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/policy"
)

type auditReplicationRule struct {
	id           string
	peerRevision uint64
}

type auditReplicationConfig struct {
	revision uint64
	rules    map[policy.Edge]auditReplicationRule
}

func (c signedRouteConfig) replicationAuditView() auditReplicationConfig {
	view := auditReplicationConfig{revision: c.config.Revision, rules: map[policy.Edge]auditReplicationRule{}}
	for _, rule := range c.config.Replication {
		if rule.Domain == c.domain.Trust.Domain {
			edge := policy.Edge{From: rule.From, To: rule.To, Mode: rule.Mode}
			view.rules[edge] = auditReplicationRule{id: rule.ID(c.domain.Trust), peerRevision: rule.PeerRevision}
		}
	}
	return view
}

type routeAuditReplication struct {
	Edge                 policy.Edge `json:"edge"`
	Executor             string      `json:"executor"`
	Peer                 string      `json:"peer"`
	State                string      `json:"state"`
	ExecutorRule         string      `json:"executorRule,omitempty"`
	PeerRule             string      `json:"peerRule,omitempty"`
	RequiredPeerRevision uint64      `json:"requiredPeerRevision,omitempty"`
	PeerRevision         uint64      `json:"peerRevision,omitempty"`
}

func auditReplicationEdges(edges []policy.Edge, configs map[string]auditReplicationConfig) []routeAuditReplication {
	result := make([]routeAuditReplication, 0, len(edges))
	for _, edge := range edges {
		route := control.Replication{From: edge.From, To: edge.To, Mode: edge.Mode}
		executor, executorPresent := configs[route.Executor()]
		peer, peerPresent := configs[route.Peer()]
		executorRule, executorDelegated := executor.rules[edge]
		peerRule, peerDelegated := peer.rules[edge]
		var state string
		switch {
		case !executorPresent || !peerPresent:
			state = "DOCUMENT_MISSING"
		case !executorDelegated && !peerDelegated:
			state = "UNDELEGATED"
		case !executorDelegated:
			state = "EXECUTOR_RULE_MISSING"
		case peer.revision < executorRule.peerRevision:
			state = "PEER_REVISION_TOO_OLD"
		case !peerDelegated:
			state = "PEER_RULE_MISSING"
		case executorRule.id != peerRule.id:
			state = "RULE_MISMATCH"
		default:
			state = "RULES_MATCH"
		}
		result = append(result, routeAuditReplication{
			Edge: edge, Executor: route.Executor(), Peer: route.Peer(), State: state,
			ExecutorRule: executorRule.id, PeerRule: peerRule.id,
			RequiredPeerRevision: executorRule.peerRevision, PeerRevision: peer.revision,
		})
	}
	return result
}
