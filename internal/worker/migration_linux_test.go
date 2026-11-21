package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestOperatorMigrationUsesWorkerLeaseDomainAndBudget(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.config(t, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	r, e := generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	catalog, e := r.Catalog(ctx, f.generation)
	must(t, e)
	status, e := r.Status(ctx)
	must(t, e)
	must(t, r.Close())
	// Exact old serialized layout, solely inside this synthetic fixture.
	type item struct {
		Catalog  json.RawMessage `json:"catalog"`
		Complete bool            `json:"complete"`
	}
	old := struct {
		Format          string                    `json:"format"`
		Trust           generation.Trust          `json:"trust"`
		Revision        uint64                    `json:"revision"`
		HighestSequence uint64                    `json:"highestSequence"`
		HighestID       string                    `json:"highestId"`
		Latest          string                    `json:"latestComplete"`
		Generations     map[string]item           `json:"generations"`
		Pins            map[string]generation.Pin `json:"pins"`
		Receipts        map[string]string         `json:"maintenanceReceipts"`
	}{generation.Format, f.domain.Trust, status.Revision, status.HighestSequence, f.generation, status.LatestComplete, map[string]item{f.generation: {catalog, true}}, status.Pins, map[string]string{}}
	raw, e := json.Marshal(old)
	must(t, e)
	must(t, os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600))
	must(t, os.RemoveAll(filepath.Join(dir, "catalogs")))
	before, e := w.budget.Status(ctx)
	must(t, e)
	must(t, w.MigrateDomain(ctx, f.domain.Trust.Domain, false))
	after, e := w.budget.Status(ctx)
	must(t, e)
	if after.Revision <= before.Revision || len(after.Pending) != 0 {
		t.Fatal("migration bypassed admission or left reservations")
	}
	r, e = generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	must(t, r.VerifyComplete(ctx, f.generation))
	must(t, r.Close())
	must(t, w.MigrateDomain(ctx, f.domain.Trust.Domain, true))
	restored, e := os.ReadFile(filepath.Join(dir, "state.json"))
	must(t, e)
	if !bytes.Equal(raw, restored) {
		t.Fatal("rollback changed old state")
	}
	must(t, w.MigrateDomain(ctx, f.domain.Trust.Domain, false))
	stop := start(t, w)
	wait(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.active != nil })
	if e = w.MigrateDomain(ctx, f.domain.Trust.Domain, false); !errors.Is(e, generation.ErrConflict) {
		t.Fatalf("migrated running worker: %v", e)
	}
	stop()
	if e = w.MigrateDomain(ctx, storage.Hash([]byte("unknown domain")), false); !errors.Is(e, ErrDenied) {
		t.Fatalf("unknown domain accepted: %v", e)
	}
}
