package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerRecordedDamageStatusIsScopedAndReadOnly(t *testing.T) {
	f := newFixture(t)
	f.domain.Placement.Edges = nil
	f.config(t, 0, nil)
	w := f.nodes[0]
	ctx := t.Context()
	domain := f.domain.Trust.Domain
	status := func(state string) generation.RecordedDamage {
		t.Helper()
		got, err := w.ReplicaDamageStatus(ctx, domain, f.generation)
		must(t, err)
		if got.Format != generation.RecordedDamageFormat || got.Generation != f.generation || got.State != state {
			t.Fatalf("expected %s, got %+v", state, got)
		}
		return got
	}
	if got := status("NO_RECORDED_DAMAGE"); got.Affected == nil || len(got.Affected) != 0 {
		t.Fatal(got)
	}
	foreign := storage.Hash([]byte("unassigned domain"))
	if got, err := w.ReplicaDamageStatus(ctx, foreign, f.generation); !errors.Is(err, ErrDenied) || got.Format != "" {
		t.Fatal(got, err)
	}
	need := damageWorkerReplica(t, f, 0)
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	index := filepath.Join(dir, "state.json")
	before, err := os.ReadFile(index)
	must(t, err)
	damaged := status("DAMAGE_RECORDED")
	if len(damaged.Affected) != 1 || damaged.Affected[0].Version != f.version {
		t.Fatal(damaged)
	}
	raw, err := json.Marshal(damaged)
	must(t, err)
	if bytes.Contains(raw, []byte(need.Token)) || bytes.Contains(raw, []byte("objects")) ||
		bytes.Contains(raw, []byte(dir)) {
		t.Fatal("repair credential, object identifiers or local path in status")
	}
	must(t, os.Remove(filepath.Join(dir, "catalogs", f.generation)))
	if got := status("CATALOG_UNAVAILABLE"); got.Affected != nil {
		t.Fatal("catalog loss presented as measured empty coverage", got)
	}
	after, err := os.ReadFile(index)
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("passive catalog read persisted diagnosis")
	}
	lock := filepath.Join(dir, ".lock")
	must(t, os.Remove(lock))
	if got, err := w.ReplicaDamageStatus(ctx, domain, f.generation); !errors.Is(err, os.ErrNotExist) || got.Format != "" {
		t.Fatal(got, err)
	}
	if _, err := os.Lstat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("status recreated the replica lock", err)
	}
}

func TestWorkerRecordedDamageStatusRejectsWithdrawnHolder(t *testing.T) {
	f := newFixture(t)
	f.domain.Placement.Edges = nil
	f.config(t, 0, nil)
	w := f.nodes[0]
	ctx := t.Context()
	domain := f.domain.Trust.Domain
	damageWorkerReplica(t, f, 0)
	before, err := w.ReplicaDamageStatus(ctx, domain, f.generation)
	must(t, err)
	if before.State != "DAMAGE_RECORDED" || len(before.Affected) != 1 {
		t.Fatal(before)
	}

	f.domain.Placement.Holders = []string{f.nodes[1].node, f.nodes[2].node}
	for _, tc := range []struct {
		name    string
		transit []string
	}{
		{name: "withdrawn"},
		{name: "transit-only", transit: []string{w.node}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.cfg.Revision++
			f.domain.Placement.Transit = tc.transit
			cfg := f.config(t, 0, nil)
			if _, ok := cfg.DomainByID(domain); !ok {
				t.Fatal("domain unexpectedly removed")
			}
			state := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica", "state.json")
			if _, err := os.Stat(state); err != nil {
				t.Fatal("previous replica absent", err)
			}
			got, err := w.ReplicaDamageStatus(ctx, domain, f.generation)
			if !errors.Is(err, ErrDenied) || got.Format != "" || got.Affected != nil {
				t.Fatal(got, err)
			}
		})
	}
}
