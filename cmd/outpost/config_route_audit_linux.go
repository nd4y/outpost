package main

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

const routeAuditIndexMax = 256 << 10
const routeAuditConfigBudget = 128 << 20

type routeAuditEntry struct {
	Node   string `json:"node"`
	Config string `json:"config"`
}

type routeAuditIndex struct {
	Format string            `json:"format"`
	Peers  []routeAuditEntry `json:"peers"`
}

type routeAuditPeer struct {
	Document    routeConfigIdentity `json:"document"`
	Differences []string            `json:"differences"`
}

type routeAuditReport struct {
	Format       string                  `json:"format"`
	Domain       string                  `json:"domain"`
	Reference    routeConfigIdentity     `json:"reference"`
	Complete     bool                    `json:"complete"`
	Consistent   bool                    `json:"consistent"`
	Peers        []routeAuditPeer        `json:"peers"`
	MissingPeers []string                `json:"missingPeers"`
	Replication  []routeAuditReplication `json:"replication"`
}

func auditConfigRoutes(ctx context.Context, input, indexFile, trustFile, node, domain string, now time.Time) (routeAuditReport, error) {
	var empty routeAuditReport
	if !storage.ID(node) || !storage.ID(domain) || indexFile == "" {
		return empty, errUsage
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	owner, err := readRouteOwner(trustFile)
	if err != nil {
		return empty, err
	}
	reference, err := readSignedRouteConfig(input, owner, node, domain, now, control.MaxConfig)
	if err != nil {
		return empty, err
	}
	raw, err := worker.ReadPrivate(indexFile, routeAuditIndexMax)
	if err != nil {
		return empty, err
	}
	var index routeAuditIndex
	if worker.DecodeInput(raw, &index, routeAuditIndexMax) != nil || index.Format != "outpost-config-route-index-1" || index.Peers == nil {
		return empty, errUsage
	}
	expected := reference.peerNodes()
	delete(expected, node)
	if len(index.Peers) > len(expected) {
		return empty, errUsage
	}
	paths := make(map[string]string, len(index.Peers))
	for _, entry := range index.Peers {
		if _, ok := expected[entry.Node]; !ok || paths[entry.Node] != "" || !filepath.IsAbs(entry.Config) {
			return empty, errUsage
		}
		paths[entry.Node] = entry.Config
	}
	report := routeAuditReport{
		Format: "outpost-config-route-audit-1", Domain: domain, Reference: reference.identity(),
		Complete: len(paths) == len(expected), Consistent: len(paths) == len(expected),
		Peers: []routeAuditPeer{}, MissingPeers: []string{},
	}
	configs := map[string]auditReplicationConfig{node: reference.replicationAuditView()}
	remaining := routeAuditConfigBudget - reference.size
	for _, id := range slices.Sorted(maps.Keys(expected)) {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		path, ok := paths[id]
		if !ok {
			report.MissingPeers = append(report.MissingPeers, id)
			continue
		}
		peer, err := readSignedRouteConfig(path, owner, id, domain, now, min(remaining, control.MaxConfig))
		if err != nil {
			return empty, err
		}
		remaining -= peer.size
		configs[id] = peer.replicationAuditView()
		differences := peerRouteDifferences(reference, peer)
		report.Peers = append(report.Peers, routeAuditPeer{Document: peer.identity(), Differences: differences})
		report.Consistent = report.Consistent && len(differences) == 0
	}
	report.Replication = auditReplicationEdges(reference.domain.Placement.Edges, configs)
	return report, ctx.Err()
}
