package policy

import (
	"errors"
	"testing"

	"github.com/nd4y/outpost/internal/storage"
)

func testID(s string) string { return storage.Hash([]byte(s)) }

func testDomains(ids ...string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}
func TestSelectDefaultDeny(t *testing.T) {
	a := testID("domain-a")
	tests := []struct {
		name  string
		rules []Rule
	}{
		{"no rules", nil},
		{"no matching prefix", []Rule{{Prefix: "data", Domain: a}}},
		{"label mismatch", []Rule{{Prefix: ".", Domain: a, Labels: map[string]string{"env": "prod"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.rules, "other", nil)
			if got != "" || !errors.Is(err, ErrDenied) {
				t.Fatalf("Select() = %q, %v; want default deny", got, err)
			}
		})
	}
}

func TestSelectPrefixSegmentBoundary(t *testing.T) {
	a := testID("domain-a")
	rules := []Rule{{Prefix: "data", Domain: a}}
	tests := []struct {
		name string
		want string
		err  error
	}{
		{"data", a, nil},
		{"data/file", a, nil},
		{"database/file", "", ErrDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(rules, tt.name, nil)
			if got != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("Select(%q) = %q, %v; want %q, %v", tt.name, got, err, tt.want, tt.err)
			}
		})
	}
}

func TestSelectDenyWinsOverHigherPriorityAllow(t *testing.T) {
	a := testID("domain-a")
	rules := []Rule{
		{Prefix: ".", Priority: 10, Domain: a},
		{Prefix: "secret", Deny: true},
	}
	if got, err := Select(rules, "secret/file", nil); got != "" || !errors.Is(err, ErrDenied) {
		t.Fatalf("Select() = %q, %v; want deny to win", got, err)
	}
}

func TestValidateRulesRejectsEqualPriorityOverlap(t *testing.T) {
	a, b := testID("domain-a"), testID("domain-b")
	rules := []Rule{
		{Prefix: ".", Priority: 1, Domain: a},
		{Prefix: "docs", Priority: 1, Domain: b},
	}
	if err := ValidateRules(rules, testDomains(a, b)); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ValidateRules() = %v; want %v", err, ErrAmbiguous)
	}
}

func TestSelectLabels(t *testing.T) {
	a, b := testID("domain-a"), testID("domain-b")
	rules := []Rule{
		{Prefix: ".", Priority: 1, Domain: a, Labels: map[string]string{"env": "prod"}},
		{Prefix: ".", Priority: 2, Domain: b, Labels: map[string]string{"env": "dev"}},
	}
	tests := []struct {
		name   string
		labels map[string]string
		want   string
		err    error
	}{
		{"dev", map[string]string{"env": "dev"}, b, nil},
		{"prod with extra label", map[string]string{"env": "prod", "team": "x"}, a, nil},
		{"missing label", nil, "", ErrDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(rules, "file", tt.labels)
			if got != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("Select() = %q, %v; want %q, %v", got, err, tt.want, tt.err)
			}
		})
	}
}

func TestSelectRejectsInvalidNames(t *testing.T) {
	a := testID("domain-a")
	rules := []Rule{{Prefix: ".", Domain: a}}
	for _, name := range []string{"../escape", "dir\\file", "/absolute"} {
		t.Run(name, func(t *testing.T) {
			if got, err := Select(rules, name, nil); got != "" || !errors.Is(err, ErrDenied) {
				t.Fatalf("Select(%q) = %q, %v; want %v", name, got, err, ErrDenied)
			}
		})
	}
}

func TestSelectAliases(t *testing.T) {
	a, b := testID("domain-a"), testID("domain-b")
	t.Run("same domain accepted", func(t *testing.T) {
		rules := []Rule{{Prefix: ".", Domain: a}}
		if got, err := SelectAliases(rules, []string{"one", "dir/two"}, nil); got != a || err != nil {
			t.Fatalf("SelectAliases() = %q, %v; want %q, nil", got, err, a)
		}
	})
	t.Run("different classification rejected", func(t *testing.T) {
		rules := []Rule{{Prefix: "a", Domain: a}, {Prefix: "b", Domain: b}}
		if got, err := SelectAliases(rules, []string{"a", "b"}, nil); got != "" || !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("SelectAliases() = %q, %v; want %v", got, err, ErrAmbiguous)
		}
	})
	t.Run("denied alias rejected", func(t *testing.T) {
		rules := []Rule{{Prefix: ".", Domain: a}, {Prefix: "secret", Deny: true}}
		if got, err := SelectAliases(rules, []string{"ok", "secret/file"}, nil); got != "" || !errors.Is(err, ErrDenied) {
			t.Fatalf("SelectAliases() = %q, %v; want %v", got, err, ErrDenied)
		}
	})
}
