package readback

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
)

func TestReadbackEvidenceRetainsAgeAcrossRestartAndIsolatesScopes(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "cache")
	s, e := statefile.Open(dir, MaxPage, true)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Truncate(time.Second)
	ref := generation.Object{ID: generation.Hash([]byte("payload")), Bytes: 7}
	original := Record{Bytes: 7, ObservedUnix: now.Add(-time.Minute).Unix()}
	scope := generation.Hash([]byte("exact target reader trust"))
	c := Cache{s, scope}
	if e = c.Remember(ctx, map[string]Record{ref.ID: original}, now); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = statefile.Open(dir, MaxPage, false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c.Store = s
	got, e := c.Lookup(ctx, []generation.Object{ref}, now, 120)
	if e != nil || got[ref.ID] != original {
		t.Fatal("original evidence changed", got, e)
	}
	for _, age := range []int64{0, 59} {
		got, e = c.Lookup(ctx, []generation.Object{ref}, now, age)
		if e != nil || len(got) != 0 {
			t.Fatal("stale or fresh-only evidence reused", e)
		}
	}
	other := Cache{s, generation.Hash([]byte("different target reader trust"))}
	got, e = other.Lookup(ctx, []generation.Object{ref}, now, 120)
	if e != nil || len(got) != 0 {
		t.Fatal("cross-scope reuse", e)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, e = c.Lookup(cancelled, []generation.Object{ref}, now, 120); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = c.Lookup(ctx, []generation.Object{ref}, now.Add(-2*time.Minute), 120); !errors.Is(e, ErrInvalid) {
		t.Fatal("clock rollback accepted", e)
	}
	if e = os.WriteFile(filepath.Join(dir, c.name(ref.ID[:2])), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Lookup(ctx, []generation.Object{ref}, now, 120); !errors.Is(e, ErrInvalid) {
		t.Fatal("malformed cache ignored", e)
	}
}

func TestReadbackPageEvictionNeverRewritesOriginalObservation(t *testing.T) {
	ctx := context.Background()
	s, e := statefile.Open(filepath.Join(t.TempDir(), "cache"), MaxPage, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now().Truncate(time.Second)
	c := Cache{s, generation.Hash([]byte("scope"))}
	// Seed one legal full page. Eviction concerns evidence only, never payload.
	p := page{Format: Format, Scope: c.Scope, Prefix: "ab", Records: map[string]Record{}}
	for i := 0; i < maxEntries; i++ {
		id := "ab" + generation.Hash([]byte(time.Unix(int64(i), 0).String()))[2:]
		p.Records[id] = Record{Bytes: 1, ObservedUnix: now.Unix() - 10}
	}
	raw, _ := json.Marshal(p)
	if e = s.Write(c.name("ab"), raw); e != nil {
		t.Fatal(e)
	}
	ref := generation.Object{ID: "ab" + generation.Hash([]byte("new object"))[2:], Bytes: 1}
	r := Record{Bytes: 1, ObservedUnix: now.Unix()}
	if e = c.Remember(ctx, map[string]Record{ref.ID: r}, now); e != nil {
		t.Fatal(e)
	}
	saved, e := c.load("ab", now.Unix())
	if e != nil || len(saved.Records) != maxEntries || saved.Records[ref.ID] != r {
		t.Fatal("bounded eviction", e)
	}
	older := r
	older.ObservedUnix--
	if e = c.Remember(ctx, map[string]Record{ref.ID: older}, now); e != nil {
		t.Fatal(e)
	}
	saved, e = c.load("ab", now.Unix())
	if e != nil || saved.Records[ref.ID] != r {
		t.Fatal("newer actual read replaced by older evidence", e)
	}
}
