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

type signedRouteConfig struct {
	config control.Config
	domain control.Domain
	digest string
}

func readRouteOwner(trustFile string) (ed25519.PublicKey, error) {
	raw, err := worker.ReadPrivate(trustFile, 4096)
	if err != nil {
		return nil, err
	}
	var trust struct {
		PublicKey ed25519.PublicKey `json:"publicKey"`
	}
	if worker.DecodeInput(raw, &trust, 4096) != nil {
		return nil, errUsage
	}
	return trust.PublicKey, nil
}

func readSignedRouteConfig(input string, owner ed25519.PublicKey, node, domain string, now time.Time) (signedRouteConfig, error) {
	var result signedRouteConfig
	raw, err := worker.ReadPrivate(input, control.MaxConfig)
	if err != nil {
		return result, err
	}
	config, err := control.Verify(raw, owner, node)
	if err != nil {
		return result, err
	}
	if err := config.Active(now); err != nil {
		return result, err
	}
	d, ok := config.DomainByID(domain)
	if !ok || !d.Placement.PermitsNode(node) {
		return result, control.ErrDenied
	}
	return signedRouteConfig{config: config, domain: d, digest: storage.Hash(raw)}, nil
}

func inspectConfigRoutes(input, trustFile, node, domain string, now time.Time) (configRouteReport, error) {
	var report configRouteReport
	if !storage.ID(node) || !storage.ID(domain) {
		return report, errUsage
	}
	owner, err := readRouteOwner(trustFile)
	if err != nil {
		return report, err
	}
	signed, err := readSignedRouteConfig(input, owner, node, domain, now)
	if err != nil {
		return report, err
	}
	d := signed.domain
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
		Revision: signed.config.Revision, ConfigDigest: signed.digest, Routes: routes,
	}, nil
}
