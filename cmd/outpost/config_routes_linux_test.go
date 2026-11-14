package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestCLIConfigRoutesVerifiesAuthorityAndPreservesDirectedPaths(t *testing.T) {
	root := teststore.Root(t)
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	makeKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	public, owner := makeKey()
	writer, _ := makeKey()
	maintenance, _ := makeKey()
	planner, _ := makeKey()
	source := storage.Hash([]byte("origin"))
	bridge := storage.Hash([]byte("bridge"))
	outbound := storage.Hash([]byte("outbound"))
	disconnected := storage.Hash([]byte("disconnected"))
	domain := storage.Hash([]byte("domain"))
	hops := []policy.Edge{
		{From: source, To: bridge, Mode: "push"},
		{From: bridge, To: outbound, Mode: "pull"},
	}
	now := time.Now()
	config := control.Config{
		Format: control.Format, Node: source, Revision: 4,
		NotBefore: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(time.Hour).Unix(),
		Limits: control.Limits{Parallel: 1, AttemptMillis: 1000, PollSeconds: 1, CapacityBytes: 1 << 30, ReserveBytes: 1 << 28, SpoolBytes: 1 << 26, TelemetryBytes: 1 << 20},
		Nodes: []policy.Node{
			{ID: source, Class: "trusted"},
			{ID: bridge, Class: "trusted", Endpoint: "https://bridge.invalid"},
			{ID: outbound, Class: "trusted"},
			{ID: disconnected, Class: "trusted"},
		},
		Domains: []control.Domain{{
			Trust:   generation.Trust{Domain: domain, Repository: storage.Hash([]byte("repository")), Epoch: 1, Writer: writer, Maintenance: maintenance},
			Planner: planner,
			Placement: policy.Placement{
				Domain: domain, AllowedClasses: []string{"trusted"},
				Holders: []string{disconnected, source, outbound}, Transit: []string{bridge},
				Edges: append(slices.Clone(hops), policy.Edge{From: disconnected, To: bridge, Mode: "push"}),
			},
		}},
	}
	sign := func(config control.Config) []byte {
		t.Helper()
		raw, err := control.Sign(config, owner)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	trust := func(name string, public ed25519.PublicKey) string {
		t.Helper()
		raw, err := json.Marshal(map[string]ed25519.PublicKey{"publicKey": public})
		if err != nil {
			t.Fatal(err)
		}
		return write(name, raw)
	}
	runRoutes := func(input, trust, node, domain string) (any, error) {
		return run(context.Background(), []string{"config-routes", "--input", input, "--trust", trust, "--node", node, "--domain", domain})
	}
	raw := sign(config)
	input := write("signed.json", raw)
	trustFile := trust("owner.json", public)
	got, err := runRoutes(input, trustFile, source, domain)
	if err != nil {
		t.Fatal(err)
	}
	report := got.(configRouteReport)
	if report.Format != "outpost-config-routes-1" || report.Node != source || report.Domain != domain || report.ConfigDigest != storage.Hash(raw) || report.Revision != config.Revision {
		t.Fatalf("wrong report identity: %+v", report)
	}
	holders := []string{source, outbound, disconnected}
	slices.Sort(holders)
	if len(report.Routes) != len(holders) {
		t.Fatalf("unexpected holder count: %+v", report.Routes)
	}
	for i, route := range report.Routes {
		if route.Holder != holders[i] || route.Reachable != (route.Holder != disconnected) || route.Hops == nil {
			t.Fatalf("wrong holder route: %+v", route)
		}
		if route.Holder == outbound {
			if !slices.Equal(route.Hops, hops) {
				t.Fatalf("wrong path to outbound-only holder: %+v", route)
			}
		} else if len(route.Hops) != 0 {
			t.Fatalf("unexpected hops: %+v", route)
		}
	}

	t.Run("compare signed peer routes", func(t *testing.T) {
		runCompare := func(path, node string) (any, error) {
			return run(context.Background(), []string{
				"config-route-compare", "--input", input, "--node", source, "--peer-config", path,
				"--peer", node, "--trust", trustFile, "--domain", domain,
			})
		}
		for _, tc := range []struct {
			name   string
			mutate func(*control.Config)
			want   []string
		}{
			{name: "same graph reordered with different revision and external class"},
			{"changed trust epoch", func(c *control.Config) {
				c.Domains[0].Trust.Epoch++
			}, []string{"DOMAIN_TRUST"}},
			{"expanded peer class policy", func(c *control.Config) {
				p := &c.Domains[0].Placement
				p.AllowedClasses = append(p.AllowedClasses, "untrusted")
			}, []string{"PEER_CLASSES"}},
			{"changed transit to holder", func(c *control.Config) {
				p := &c.Domains[0].Placement
				p.Transit = nil
				p.Holders = append(p.Holders, bridge)
			}, []string{"HOLDERS", "TRANSIT"}},
			{"reversed data edge with same HTTPS dialer", func(c *control.Config) {
				p := &c.Domains[0].Placement
				for i, edge := range p.Edges {
					if edge == hops[1] {
						p.Edges[i] = policy.Edge{From: outbound, To: bridge, Mode: "push"}
					}
				}
			}, []string{"PEER_EDGES"}},
			{"changed relay endpoint", func(c *control.Config) {
				for i, node := range c.Nodes {
					if node.ID == bridge {
						c.Nodes[i].Endpoint = "https://new-bridge.invalid"
					}
				}
			}, []string{"PEER_NODES"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				peer, err := control.Verify(raw, public, source)
				if err != nil {
					t.Fatal(err)
				}
				peer.Node = outbound
				peer.Revision++
				peer.Limits.PollSeconds++
				slices.Reverse(peer.Nodes)
				placement := &peer.Domains[0].Placement
				slices.Reverse(placement.Edges)
				slices.Reverse(placement.Holders)
				placement.AllowedClasses = append(placement.AllowedClasses, "external")
				if tc.mutate != nil {
					tc.mutate(&peer)
				}
				peerRaw := sign(peer)
				peerFile := write("peer signed.json", peerRaw)
				result, err := runCompare(peerFile, outbound)
				if err != nil {
					t.Fatal(err)
				}
				comparison := result.(routeComparison)
				primaryIdentity := routeConfigIdentity{Node: source, Revision: config.Revision, ConfigDigest: storage.Hash(raw)}
				peerIdentity := routeConfigIdentity{Node: outbound, Revision: peer.Revision, ConfigDigest: storage.Hash(peerRaw)}
				if comparison.Format != "outpost-config-route-compare-1" || comparison.Domain != domain ||
					comparison.Primary != primaryIdentity || comparison.Peer != peerIdentity ||
					comparison.Consistent != (len(tc.want) == 0) || comparison.Differences == nil || !slices.Equal(comparison.Differences, tc.want) {
					t.Fatalf("unexpected comparison: %+v", comparison)
				}
			})
		}
		if _, err := runCompare(input, outbound); !errors.Is(err, control.ErrDenied) {
			t.Fatalf("misaddressed peer config rejected with %v", err)
		}
		if _, err := runCompare(input, source); !errors.Is(err, errUsage) {
			t.Fatalf("duplicate node rejected with %v", err)
		}
	})

	t.Run("audit every signed peer", func(t *testing.T) {
		runAudit := func(ctx context.Context, reference string, peers []routeAuditEntry) (any, error) {
			index := routeAuditIndex{Format: "outpost-config-route-index-1", Peers: peers}
			rawIndex, err := json.Marshal(index)
			if err != nil {
				t.Fatal(err)
			}
			return run(ctx, []string{
				"config-route-audit", "--input", reference, "--node", source,
				"--peer-configs", write("route index.json", rawIndex), "--trust", trustFile, "--domain", domain,
			})
		}
		peerConfig := func(id string) control.Config {
			t.Helper()
			peer, err := control.Verify(raw, public, source)
			if err != nil {
				t.Fatal(err)
			}
			peer.Node = id
			peer.Revision++
			return peer
		}
		peerIDs := []string{outbound, disconnected, bridge}
		slices.Sort(peerIDs)
		entries := make([]routeAuditEntry, 0, len(peerIDs))
		for _, id := range slices.Backward(peerIDs) {
			entries = append(entries, routeAuditEntry{Node: id, Config: write(id+".json", sign(peerConfig(id)))})
		}
		ctx := context.Background()
		result, err := runAudit(ctx, input, entries)
		if err != nil {
			t.Fatal(err)
		}
		report := result.(routeAuditReport)
		if report.Format != "outpost-config-route-audit-1" || report.Domain != domain ||
			report.Reference != (routeConfigIdentity{Node: source, Revision: config.Revision, ConfigDigest: storage.Hash(raw)}) ||
			!report.Complete || !report.Consistent || report.MissingPeers == nil || len(report.MissingPeers) != 0 || len(report.Peers) != len(peerIDs) {
			t.Fatalf("unexpected complete audit: %+v", report)
		}
		for i, peer := range report.Peers {
			if peer.Document.Node != peerIDs[i] || peer.Document.Revision != config.Revision+1 || peer.Differences == nil || len(peer.Differences) != 0 {
				t.Fatalf("unexpected audited peer: %+v", peer)
			}
		}
		drift := peerConfig(outbound)
		drift.Domains[0].Placement.Edges = drift.Domains[0].Placement.Edges[:1]
		driftEntry := routeAuditEntry{Node: outbound, Config: write("drift.json", sign(drift))}
		changed := slices.Clone(entries)
		for i, entry := range changed {
			if entry.Node == outbound {
				changed[i] = driftEntry
			}
		}
		result, err = runAudit(ctx, input, changed)
		if err != nil {
			t.Fatal(err)
		}
		report = result.(routeAuditReport)
		if !report.Complete || report.Consistent || len(report.MissingPeers) != 0 {
			t.Fatalf("complete graph with drift was not distinguished: %+v", report)
		}
		result, err = runAudit(ctx, input, []routeAuditEntry{driftEntry})
		if err != nil {
			t.Fatal(err)
		}
		report = result.(routeAuditReport)
		missing := []string{bridge, disconnected}
		slices.Sort(missing)
		if report.Complete || report.Consistent || !slices.Equal(report.MissingPeers, missing) ||
			len(report.Peers) != 1 || !slices.Equal(report.Peers[0].Differences, []string{"PEER_EDGES"}) {
			t.Fatalf("missing or changed peer hidden: %+v", report)
		}
		for _, tc := range []struct {
			name  string
			peers []routeAuditEntry
			want  error
		}{
			{"duplicate peer", []routeAuditEntry{entries[0], entries[0]}, errUsage},
			{"reference listed as peer", []routeAuditEntry{{Node: source, Config: input}}, errUsage},
			{"unexpected peer", []routeAuditEntry{{Node: storage.Hash([]byte("unexpected")), Config: input}}, errUsage},
			{"relative path", []routeAuditEntry{{Node: outbound, Config: "peer.json"}}, errUsage},
			{"wrong recipient", []routeAuditEntry{{Node: outbound, Config: input}}, control.ErrDenied},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := runAudit(ctx, input, tc.peers); !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
			})
		}
		t.Run("autonomous replication rules", func(t *testing.T) {
			push := control.Replication{Domain: domain, From: source, To: bridge, Mode: "push", Epoch: 1, PeerRevision: 5}
			pull := control.Replication{Domain: domain, From: bridge, To: outbound, Mode: "pull", Epoch: 1, PeerRevision: 5}
			ref := peerConfig(source)
			ref.Replication = []control.Replication{push}
			refPath := write("replication-reference.json", sign(ref))
			for _, tc := range []struct {
				name           string
				mutate         func(*control.Config, *control.Config)
				omitBridge     bool
				pushState      string
				pullState      string
				remainingState string
			}{
				{"matching signed push and pull", nil, false, "RULES_MATCH", "RULES_MATCH", "UNDELEGATED"},
				{"peer lacks push rule", func(b, _ *control.Config) {
					b.Replication = b.Replication[1:]
				}, false, "PEER_RULE_MISSING", "RULES_MATCH", "UNDELEGATED"},
				{"executor lacks pull rule", func(_, c *control.Config) {
					c.Replication = nil
				}, false, "RULES_MATCH", "EXECUTOR_RULE_MISSING", "UNDELEGATED"},
				{"peer revision too old", func(b, _ *control.Config) {
					b.Revision--
					b.Replication = nil
				}, false, "PEER_REVISION_TOO_OLD", "PEER_REVISION_TOO_OLD", "UNDELEGATED"},
				{"different route epoch and repair right", func(b, c *control.Config) {
					b.Replication[0].Epoch++
					c.Replication[0].Repair = true
				}, false, "RULE_MISMATCH", "RULE_MISMATCH", "UNDELEGATED"},
				{"bridge document missing", nil, true, "DOCUMENT_MISSING", "DOCUMENT_MISSING", "DOCUMENT_MISSING"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					b, c := peerConfig(bridge), peerConfig(outbound)
					b.Replication = []control.Replication{push, pull}
					c.Replication = []control.Replication{pull}
					if tc.mutate != nil {
						tc.mutate(&b, &c)
					}
					peers := []routeAuditEntry{{Node: outbound, Config: write("replication-outbound.json", sign(c))}}
					for _, entry := range entries {
						if entry.Node == disconnected {
							peers = append(peers, entry)
						}
					}
					if !tc.omitBridge {
						peers = append(peers, routeAuditEntry{Node: bridge, Config: write("replication-bridge.json", sign(b))})
					}
					got, err := runAudit(ctx, refPath, peers)
					if err != nil {
						t.Fatal(err)
					}
					audit := got.(routeAuditReport)
					if audit.Consistent == tc.omitBridge || len(audit.Replication) != 3 {
						t.Fatalf("unexpected graph consistency or rules: %+v", audit)
					}
					pushResult, pullResult := audit.Replication[0], audit.Replication[1]
					if pushResult.Edge != hops[0] || pullResult.Edge != hops[1] ||
						pushResult.Executor != source || pushResult.Peer != bridge ||
						pullResult.Executor != outbound || pullResult.Peer != bridge ||
						pushResult.State != tc.pushState || pullResult.State != tc.pullState ||
						audit.Replication[2].State != tc.remainingState {
						t.Fatalf("unexpected replication audit: %+v", audit.Replication)
					}
					if pushResult.ExecutorRule != push.ID(ref.Domains[0].Trust) ||
						pushResult.RequiredPeerRevision != push.PeerRevision ||
						!tc.omitBridge && pushResult.PeerRevision != b.Revision ||
						tc.omitBridge && (pushResult.PeerRevision != 0 || pushResult.PeerRule != "") {
						t.Fatalf("incorrect revision or rule evidence: %+v", pushResult)
					}
				})
			}
		})

		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := runAudit(canceled, input, entries); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v for canceled audit", err)
		}
	})

	other, _ := makeKey()
	tampered := strings.Replace(string(raw), `"revision":4`, `"revision":5`, 1)
	if tampered == string(raw) {
		t.Fatal("test did not alter signed config")
	}
	config.ExpiresUnix = now.Add(-time.Second).Unix()
	expired := write("expired.json", sign(config))
	for _, tc := range []struct {
		name, input, trust, node, domain string
		want                             error
	}{
		{"foreign signer", input, trust("other.json", other), source, domain, control.ErrDenied},
		{"wrong recipient", input, trustFile, outbound, domain, control.ErrDenied},
		{"unknown domain", input, trustFile, source, storage.Hash([]byte("other-domain")), control.ErrDenied},
		{"tampered signature", write("tampered.json", []byte(tampered)), trustFile, source, domain, control.ErrDenied},
		{"expired config", expired, trustFile, source, domain, control.ErrInactive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := runRoutes(tc.input, tc.trust, tc.node, tc.domain); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
