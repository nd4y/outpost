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
