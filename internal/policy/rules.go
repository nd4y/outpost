// Package policy checks owner-defined placement before encryption or scheduling.
package policy

import (
	"errors"
	"path"
	"strings"

	"github.com/nd4y/outpost/internal/storage"
)

var ErrDenied = errors.New("policy denied")
var ErrAmbiguous = errors.New("ambiguous or cross-domain selection")

const MaxRules = 1024

// Rules belong only to the trusted source. Their paths and labels are not worker jobs.
// Prefix is a slash-separated source-relative directory/file, or "." for all paths.
type Rule struct {
	Prefix   string            `json:"prefix"`
	Labels   map[string]string `json:"labels,omitempty"`
	Priority int               `json:"priority"`
	Domain   string            `json:"domain,omitempty"`
	Deny     bool              `json:"deny"`
}

func Relative(name string) bool {
	if name == "" || name == "." || len(name) > 4096 || strings.ContainsAny(name, "\\\x00\r\n") || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}
func labelsValid(labels map[string]string) bool {
	if len(labels) > 32 {
		return false
	}
	for k, v := range labels {
		if len(k) == 0 || len(k) > 64 || len(v) > 128 || strings.ContainsAny(k+v, "\x00\r\n") {
			return false
		}
	}
	return true
}
func contains(prefix, name string) bool {
	return prefix == "." || prefix == name || strings.HasPrefix(name, prefix+"/")
}
func overlap(a, b Rule) bool {
	if !contains(a.Prefix, b.Prefix) && !contains(b.Prefix, a.Prefix) {
		return false
	}
	for k, v := range a.Labels {
		if other, ok := b.Labels[k]; ok && other != v {
			return false
		}
	}
	return true
}
func ruleValid(r Rule) bool {
	return (r.Prefix == "." || Relative(r.Prefix)) && labelsValid(r.Labels) && r.Priority >= 0 && r.Priority <= 1000000 && (r.Deny && r.Domain == "" || !r.Deny && storage.ID(r.Domain))
}
func ValidateRules(rules []Rule, domains map[string]bool) error {
	if len(rules) == 0 || len(rules) > MaxRules || len(domains) == 0 || len(domains) > 128 {
		return ErrDenied
	}
	for id := range domains {
		if !storage.ID(id) || !domains[id] {
			return ErrDenied
		}
	}
	for i, r := range rules {
		if !ruleValid(r) || !r.Deny && !domains[r.Domain] {
			return ErrDenied
		}
		for _, other := range rules[:i] {
			if !r.Deny && !other.Deny && r.Priority == other.Priority && r.Domain != other.Domain && overlap(r, other) {
				return ErrAmbiguous
			}
		}
	}
	return nil
}
func Select(rules []Rule, name string, labels map[string]string) (string, error) {
	if !Relative(name) || !labelsValid(labels) || len(rules) > MaxRules {
		return "", ErrDenied
	}
	chosen := ""
	priority := -1
	ambiguous := false
	for _, r := range rules {
		if !ruleValid(r) {
			return "", ErrDenied
		}
	}
	for _, r := range rules {
		if !contains(r.Prefix, name) {
			continue
		}
		matches := true
		for k, v := range r.Labels {
			if actual, ok := labels[k]; !ok || actual != v {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if r.Deny {
			return "", ErrDenied
		}
		if r.Priority > priority {
			chosen = r.Domain
			priority = r.Priority
			ambiguous = false
		} else if r.Priority == priority && chosen != r.Domain {
			ambiguous = true
		}
	}
	if ambiguous {
		return "", ErrAmbiguous
	}
	if !storage.ID(chosen) {
		return "", ErrDenied
	}
	return chosen, nil
}

// Aliases must include every discovered hardlink name before capture. A denied or
// differently classified alias cannot be used to bypass the inode's restrictions.
func SelectAliases(rules []Rule, names []string, labels map[string]string) (string, error) {
	if len(names) == 0 || len(names) > 4096 {
		return "", ErrDenied
	}
	domain := ""
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			return "", ErrAmbiguous
		}
		seen[name] = true
		id, e := Select(rules, name, labels)
		if e != nil {
			return "", e
		}
		if domain != "" && domain != id {
			return "", ErrAmbiguous
		}
		domain = id
	}
	return domain, nil
}
