package policy

import (
	"errors"
	"reflect"
	"testing"

	"github.com/nd4y/outpost/internal/storage"
)

func testProfile() storage.Profile {
	return storage.Profile{
		Kind:              "s3",
		Endpoint:          "https://objects.example/",
		Namespace:         testID("namespace"),
		Region:            "us-east-1",
		MaxObjectBytes:    64 << 10,
		Concurrency:       1,
		RequestsPerSecond: 1,
		Attempts:          1,
		TimeoutMillis:     1000,
		CredentialScope:   "namespace",
		NoDelete:          true,
	}
}

func testNode(id, class, endpoint string) Node {
	return Node{ID: id, Class: class, Endpoint: endpoint}
}

func TestPlacementPushThenPullRoute(t *testing.T) {
	a, b, c := testID("node-a"), testID("node-b"), testID("node-c")
	nodes := map[string]Node{
		a: testNode(a, "trusted", ""),
		b: testNode(b, "trusted", "https://b.example"),
		c: testNode(c, "trusted", ""), // C is outbound-only: no endpoint needed.
	}
	p := Placement{
		Domain:         testID("domain-route"),
		AllowedClasses: []string{"trusted"},
		Holders:        []string{a, b, c},
		Edges: []Edge{
			{From: a, To: b, Mode: "push"},
			{From: b, To: c, Mode: "pull"},
		},
	}
	if err := p.Validate(nodes, nil); err != nil {
		t.Fatalf("Validate() = %v; want explicit A->B push and B->C pull accepted", err)
	}
	route, err := p.Route(a, c)
	if err != nil {
		t.Fatalf("Route(A, C) = %v; want two-hop route", err)
	}
	want := []Edge{{From: a, To: b, Mode: "push"}, {From: b, To: c, Mode: "pull"}}
	if !reflect.DeepEqual(route, want) {
		t.Fatalf("Route(A, C) = %+v; want %+v", route, want)
	}
	for _, e := range route {
		if e.From == a && e.To == c {
			t.Fatalf("route contains implicit direct edge %+v", e)
		}
	}
	if p.HasEdge(a, c, "push") || p.HasEdge(a, c, "pull") {
		t.Fatal("direct A->C edge must not be synthesized")
	}
	// No reverse edge: C cannot send back to A merely because it is a holder.
	if _, err := p.Route(c, a); !errors.Is(err, ErrDenied) {
		t.Fatalf("Route(C, A) = %v; want %v", err, ErrDenied)
	}
	if _, err := p.Route(b, a); !errors.Is(err, ErrDenied) {
		t.Fatalf("Route(B, A) = %v; want %v", err, ErrDenied)
	}
}

func TestPlacementTransitMustBeDeclaredAndTrusted(t *testing.T) {
	a, c := testID("node-a"), testID("node-c")
	undeclared, untrusted := testID("node-undeclared"), testID("node-untrusted")
	nodes := map[string]Node{
		a:          testNode(a, "trusted", ""),
		c:          testNode(c, "trusted", ""),
		undeclared: testNode(undeclared, "trusted", "https://undeclared.example"),
		untrusted:  testNode(untrusted, "untrusted", "https://untrusted.example"),
	}
	base := Placement{
		Domain:         testID("domain-transit"),
		AllowedClasses: []string{"trusted"},
		Holders:        []string{a, c},
	}
	t.Run("undeclared transit", func(t *testing.T) {
		p := base
		p.Edges = []Edge{
			{From: a, To: undeclared, Mode: "push"},
			{From: undeclared, To: c, Mode: "pull"},
		}
		if err := p.Validate(nodes, nil); !errors.Is(err, ErrDenied) {
			t.Fatalf("Validate() = %v; want %v for undeclared transit", err, ErrDenied)
		}
		if _, err := p.Route(a, c); !errors.Is(err, ErrDenied) {
			t.Fatalf("Route() = %v; want %v for undeclared transit", err, ErrDenied)
		}
	})
	t.Run("untrusted transit", func(t *testing.T) {
		p := base
		p.Transit = []string{untrusted}
		p.Edges = []Edge{
			{From: a, To: untrusted, Mode: "push"},
			{From: untrusted, To: c, Mode: "pull"},
		}
		if err := p.Validate(nodes, nil); !errors.Is(err, ErrDenied) {
			t.Fatalf("Validate() = %v; want %v for untrusted transit", err, ErrDenied)
		}
	})
}

func TestPlacementCloudEgressExplicit(t *testing.T) {
	a, b := testID("node-a"), testID("node-b")
	target := testID("cloud-target")
	nodes := map[string]Node{
		a: testNode(a, "trusted", ""),
		b: testNode(b, "trusted", "https://b.example"),
	}
	targets := map[string]storage.Profile{target: testProfile()}
	base := Placement{
		Domain:         testID("domain-cloud"),
		AllowedClasses: []string{"trusted", "external"},
		Holders:        []string{a},
		Targets:        []string{target},
	}
	if err := base.Validate(nodes, targets); err != nil {
		t.Fatalf("Validate() = %v; want external target accepted", err)
	}
	if base.PermitsCloud(a, target) {
		t.Fatal("holding a node must not by itself grant cloud egress")
	}
	withEdge := base
	withEdge.CloudEdges = []CloudEdge{{Node: a, Target: target}}
	if err := withEdge.Validate(nodes, targets); err != nil {
		t.Fatalf("Validate() = %v; want explicit cloud edge accepted", err)
	}
	if !withEdge.PermitsCloud(a, target) {
		t.Fatal("explicit cloud edge must grant egress")
	}
	t.Run("node lacks holder or transit role", func(t *testing.T) {
		p := base
		p.CloudEdges = []CloudEdge{{Node: b, Target: target}}
		if err := p.Validate(nodes, targets); !errors.Is(err, ErrDenied) {
			t.Fatalf("Validate() = %v; want %v", err, ErrDenied)
		}
	})
	t.Run("unknown cloud target", func(t *testing.T) {
		p := base
		p.CloudEdges = []CloudEdge{{Node: a, Target: testID("unknown-target")}}
		if err := p.Validate(nodes, targets); !errors.Is(err, ErrDenied) {
			t.Fatalf("Validate() = %v; want %v", err, ErrDenied)
		}
	})
	t.Run("target profile absent", func(t *testing.T) {
		p := base
		p.Targets = []string{testID("absent-target")}
		if err := p.Validate(nodes, targets); !errors.Is(err, ErrDenied) {
			t.Fatalf("Validate() = %v; want %v", err, ErrDenied)
		}
	})
	t.Run("external class not allowed", func(t *testing.T) {
		p := base
		p.AllowedClasses = []string{"trusted"}
		if err := p.Validate(nodes, targets); !errors.Is(err, ErrDenied) {
			t.Fatalf("Validate() = %v; want %v", err, ErrDenied)
		}
	})
}

func TestPreviewDiffsWithoutMutatingInputs(t *testing.T) {
	domain := testID("domain-preview")
	a, b, c := testID("node-a"), testID("node-b"), testID("node-c")
	t1, t2 := testID("target-1"), testID("target-2")
	before := Placement{
		Domain:         domain,
		AllowedClasses: []string{"trusted", "external"},
		Holders:        []string{a, b},
		Transit:        []string{c},
		Targets:        []string{t1},
		Edges:          []Edge{{From: a, To: b, Mode: "push"}},
		CloudEdges:     []CloudEdge{{Node: a, Target: t1}},
	}
	after := Placement{
		Domain:         domain,
		AllowedClasses: []string{"trusted", "external"},
		Holders:        []string{a, c},
		Transit:        []string{b},
		Targets:        []string{t1, t2},
		Edges: []Edge{
			{From: a, To: b, Mode: "push"},
			{From: b, To: c, Mode: "pull"},
		},
		CloudEdges: []CloudEdge{{Node: a, Target: t1}},
	}
	cloneStrings := func(in []string) []string { return append([]string(nil), in...) }
	cloneEdges := func(in []Edge) []Edge { return append([]Edge(nil), in...) }
	cloneCloud := func(in []CloudEdge) []CloudEdge { return append([]CloudEdge(nil), in...) }
	beforeHolders, beforeTransit := cloneStrings(before.Holders), cloneStrings(before.Transit)
	beforeTargets, beforeEdges := cloneStrings(before.Targets), cloneEdges(before.Edges)
	beforeCloud := cloneCloud(before.CloudEdges)
	afterHolders, afterTransit := cloneStrings(after.Holders), cloneStrings(after.Transit)
	afterTargets, afterEdges := cloneStrings(after.Targets), cloneEdges(after.Edges)
	afterCloud := cloneCloud(after.CloudEdges)

	change, err := Preview(before, after)
	if err != nil {
		t.Fatalf("Preview() = %v; want nil", err)
	}
	checks := []struct {
		name string
		got  []string
		want []string
	}{
		{"added holders", change.AddedHolders, []string{c}},
		{"removed holders", change.RemovedHolders, []string{b}},
		{"added transit", change.AddedTransit, []string{b}},
		{"removed transit", change.RemovedTransit, []string{c}},
		{"added targets", change.AddedTargets, []string{t2}},
		{"removed targets", change.RemovedTargets, []string{}},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %v; want %v", check.name, check.got, check.want)
		}
	}
	if change.Domain != domain || !change.RoutesChanged {
		t.Fatalf("Preview() = %+v; want domain %q and changed routes", change, domain)
	}
	// Preview must not rewrite or reorder the caller's slices.
	if !reflect.DeepEqual(before.Holders, beforeHolders) || !reflect.DeepEqual(before.Transit, beforeTransit) ||
		!reflect.DeepEqual(before.Targets, beforeTargets) || !reflect.DeepEqual(before.Edges, beforeEdges) ||
		!reflect.DeepEqual(before.CloudEdges, beforeCloud) {
		t.Fatal("Preview mutated the before placement")
	}
	if !reflect.DeepEqual(after.Holders, afterHolders) || !reflect.DeepEqual(after.Transit, afterTransit) ||
		!reflect.DeepEqual(after.Targets, afterTargets) || !reflect.DeepEqual(after.Edges, afterEdges) ||
		!reflect.DeepEqual(after.CloudEdges, afterCloud) {
		t.Fatal("Preview mutated the after placement")
	}
	targetOnly := before
	targetOnly.Targets = []string{t1, t2}
	if change, err := Preview(before, targetOnly); err != nil || change.RoutesChanged {
		t.Fatalf("Preview(targets only) = %+v, %v; want routes unchanged", change, err)
	}
	if _, err := Preview(before, Placement{Domain: testID("other-domain")}); !errors.Is(err, ErrDenied) {
		t.Fatalf("Preview(cross-domain) = %v; want %v", err, ErrDenied)
	}
}
