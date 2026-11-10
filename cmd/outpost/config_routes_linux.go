package main

import (
	"crypto/ed25519"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

type configHolderRoute struct {
	Holder    string        `json:"holder"`
	Reachable bool          `json:"reachable"`
	Hops      []policy.Edge `json:"hops"`
}

type configRouteReport struct {
	Format       string              `json:"format"`
	Node         string              `json:"node"`
	Domain       string              `json:"domain"`
	Revision     uint64              `json:"revision"`
	ConfigDigest string              `json:"configDigest"`
	Routes       []configHolderRoute `json:"routes"`
}

func inspectConfigRoutes(input, trustFile, node, domain string, now time.Time) (configRouteReport, error) {
	var report configRouteReport
	if !storage.ID(node) || !storage.ID(domain) {
		return report, errUsage
	}
	trustRaw, err := worker.ReadPrivate(trustFile, 4096)
	if err != nil {
		return report, err
	}
	var trust struct {
		PublicKey ed25519.PublicKey `json:"publicKey"`
	}
	if worker.DecodeInput(trustRaw, &trust, 4096) != nil {
		return report, errUsage
	}
	raw, err := worker.ReadPrivate(input, control.MaxConfig)
	if err != nil {
		return report, err
	}
	config, err := control.Verify(raw, trust.PublicKey, node)
	if err != nil {
		return report, err
	}
	if err := config.Active(now); err != nil {
		return report, err
	}
	d, ok := config.DomainByID(domain)
	if !ok || !d.Placement.PermitsNode(node) {
		return report, control.ErrDenied
	}
	holders := slices.Clone(d.Placement.Holders)
	slices.Sort(holders)
	routes := make([]configHolderRoute, 0, len(holders))
	for _, holder := range holders {
		hops, err := d.Placement.Route(node, holder)
		if err != nil {
			// Placement already passed validation in Verify. An admitted
			// origin and holder can still be disconnected in the graph.
			hops = []policy.Edge{}
		}
		routes = append(routes, configHolderRoute{Holder: holder, Reachable: err == nil, Hops: hops})
	}
	return configRouteReport{
		Format: "outpost-config-routes-1", Node: node, Domain: domain,
		Revision: config.Revision, ConfigDigest: storage.Hash(raw), Routes: routes,
	}, nil
}
