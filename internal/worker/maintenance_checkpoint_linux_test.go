package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerMaintenancePlanCheckpointUsesStoppedAdmittedReplica(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	r, head, _ := maintenanceCommandFixture(t, f)
	w := f.nodes[0]
	domain := f.domain.Trust.Domain
	ctx := context.Background()
	operation := storage.Hash([]byte("exact maintenance plan checkpoint"))
	permission := maintenancePermit(t, f, r, operation, f.maintenance, f.generation)
	interrupted := errors.New("stop after durable retirement")
	r.Fault = func(point string) error {
		if point == "retirement-durable" {
			return interrupted
		}
		return nil
	}
	if _, err := r.Maintain(ctx, permission); !errors.Is(err, interrupted) {
		t.Fatal("fixture did not reach pending maintenance", err)
	}
	r.Fault = nil
	raw, err := w.MaintenancePlanCheckpoint(ctx, domain, operation)
	must(t, err)
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	name := filepath.Join(dir, "gc-"+operation+".json")
	before, err := os.ReadFile(filepath.Join(dir, "state.json"))
	must(t, err)
	must(t, os.Remove(name))
	must(t, w.lease.WithLock(ctx, func() error {
		if _, err := w.MaintenancePlanCheckpoint(ctx, domain, operation); !errors.Is(err, generation.ErrConflict) {
			t.Fatal("export ignored active worker", err)
		}
		changed, err := w.RestoreMaintenancePlanCheckpoint(ctx, domain, operation, raw, storage.Hash(raw))
		if changed || !errors.Is(err, generation.ErrConflict) {
			t.Fatal("restore ignored active worker", changed, err)
		}
		return nil
	}))
	if _, err := w.RestoreMaintenancePlanCheckpoint(ctx, storage.Hash([]byte("other domain")), operation, raw, storage.Hash(raw)); !errors.Is(err, ErrDenied) {
		t.Fatal("foreign domain admitted", err)
	}
	changed, err := w.RestoreMaintenancePlanCheckpoint(ctx, domain, operation, raw, storage.Hash(raw))
	must(t, err)
	if !changed {
		t.Fatal("pending plan not restored")
	}
	after, err := os.ReadFile(filepath.Join(dir, "state.json"))
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("restore changed index")
	}
	_, err = r.Maintain(ctx, permission)
	must(t, err)
	must(t, r.VerifyComplete(ctx, head))
}
