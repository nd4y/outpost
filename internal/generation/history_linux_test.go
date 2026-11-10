package generation

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPendingMaintenanceRequiresExactRetentionCheckpointAfterLoss(t *testing.T) {
	tt, writer, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	old, oldObjects := synthetic(t, tt, writer, 1, "retiring")
	id, e := r.Receive(ctx, old, fetch(oldObjects))
	ok(t, e)
	latest, newObjects := synthetic(t, tt, writer, 2, "protected")
	head, e := r.Receive(ctx, latest, fetch(newObjects))
	ok(t, e)
	stale, e := r.RetentionCheckpoint(ctx)
	ok(t, e)
	permission := permit(t, r, maintenance, id)
	p, e := VerifyPermit(permission, tt)
	ok(t, e)
	r.Fault = func(point string) error {
		if point == "retirement-durable" {
			return ioFailure
		}
		return nil
	}
	if _, e = r.Maintain(ctx, permission); !errors.Is(e, ioFailure) {
		t.Fatal("interruption did not reach pending GC", e)
	}
	r.Fault = nil
	raw, e := r.RetentionCheckpoint(ctx)
	ok(t, e)
	ledger := filepath.Join(dir, "retention.json")
	ok(t, os.Remove(ledger))
	if removed, e := r.Maintain(ctx, permission); removed != 0 || !errors.Is(e, ErrMigrationRequired) {
		t.Fatal("pending cleanup proceeded after journal loss", removed, e)
	}
	for id, data := range oldObjects {
		got, e := os.ReadFile(filepath.Join(dir, "objects", id))
		ok(t, e)
		if !bytes.Equal(got, data) {
			t.Fatal("pending cleanup changed a candidate")
		}
	}
	if e = r.RestoreRetentionCheckpoint(ctx, raw, Hash(stale)); !errors.Is(e, ErrInvalid) {
		t.Fatal("wrong independently retained digest accepted", e)
	}
	if e = r.RestoreRetentionCheckpoint(ctx, stale, Hash(stale)); !errors.Is(e, ErrMigrationRequired) {
		t.Fatal("stale checkpoint forgot a retirement receipt", e)
	}
	ok(t, r.RestoreRetentionCheckpoint(ctx, raw, Hash(raw)))
	if e = r.RestoreRetentionCheckpoint(ctx, raw, Hash(raw)); !errors.Is(e, ErrConflict) {
		t.Fatal("existing ledger was replaced", e)
	}
	orphan := []byte("new orphan outside the frozen candidates")
	path := filepath.Join(dir, "objects", Hash(orphan))
	ok(t, os.WriteFile(path, orphan, 0600))
	_, e = r.Maintain(ctx, permission)
	ok(t, e)
	result, e := r.MaintenanceResult(ctx, p.Operation)
	ok(t, e)
	if result.AbsentObjects != len(oldObjects) || result.AbsentCatalogs != 1 {
		t.Fatal("unexpected frozen candidate result", result)
	}
	got, e := os.ReadFile(path)
	ok(t, e)
	if !bytes.Equal(got, orphan) {
		t.Fatal("replay changed an object outside the frozen candidates")
	}
	if _, e = r.BeginHistorical(ctx, old); !errors.Is(e, ErrProtected) {
		t.Fatal("recovered tombstone did not block readmission", e)
	}
	ok(t, r.VerifyComplete(ctx, head))
	ok(t, os.Remove(ledger))
	if removed, e := r.Maintain(ctx, permission); removed != 0 || e != nil {
		t.Fatal("completed historical replay should remain a no-op", removed, e)
	}
	again, e := r.MaintenanceResult(ctx, p.Operation)
	ok(t, e)
	if again != result {
		t.Fatal("historical result changed", again)
	}
}

func TestHistoricalAdmissionKeepsHeadAndRejectsRetiredOrConflictingCatalog(t *testing.T) {
	tt, key, maintenance := trust(t)
	r := openTest(t, filepath.Join(temp(t), "replica"), tt)
	latest, objects := synthetic(t, tt, key, 7, "latest")
	head, e := r.Receive(ctx, latest, fetch(objects))
	ok(t, e)
	old, prior := synthetic(t, tt, key, 2, "history")
	if _, e = r.Begin(ctx, old); !errors.Is(e, ErrRollback) {
		t.Fatal("ordinary rollback guard removed", e)
	}
	id, e := r.BeginHistorical(ctx, old)
	ok(t, e)
	inventory, e := r.Inventory(ctx)
	ok(t, e)
	if len(inventory) != 1 || inventory[0].Generation != head {
		t.Fatal("incomplete history advertised", inventory)
	}
	for name, data := range prior {
		ok(t, r.Put(ctx, id, name, data))
	}
	ok(t, r.Complete(ctx, id))
	s, e := r.Status(ctx)
	ok(t, e)
	if s.HighestSequence != 7 || s.LatestComplete != head {
		t.Fatal("historical admission rolled back head", s)
	}
	inventory, e = r.Inventory(ctx)
	ok(t, e)
	if len(inventory) != 2 || inventory[0].Sequence != 2 || inventory[1].Sequence != 7 {
		t.Fatal("wrong sorted history", inventory)
	}
	fork, _ := synthetic(t, tt, key, 2, "conflicting history")
	if _, e = r.BeginHistorical(ctx, fork); !errors.Is(e, ErrConflict) {
		t.Fatal("conflicting sequence admitted", e)
	}
	permission := permit(t, r, maintenance, id)
	_, e = r.Maintain(ctx, permission)
	ok(t, e)
	if _, e = r.BeginHistorical(ctx, old); !errors.Is(e, ErrProtected) {
		t.Fatal("retired history resurrected", e)
	}
	ok(t, r.VerifyComplete(ctx, head))
}

func TestMissingRetentionEvidenceBlocksHistoryUntilSignedReconstruction(t *testing.T) {
	tt, key, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	old, objects := synthetic(t, tt, key, 1, "old")
	id, e := r.Receive(ctx, old, fetch(objects))
	ok(t, e)
	latest, newObjects := synthetic(t, tt, key, 5, "latest")
	head, e := r.Receive(ctx, latest, fetch(newObjects))
	ok(t, e)
	permission := permit(t, r, maintenance, id)
	_, e = r.Maintain(ctx, permission)
	ok(t, e)
	ok(t, os.Remove(filepath.Join(dir, "retention.json")))
	missing, other := synthetic(t, tt, key, 3, "not retired")
	if _, e = r.BeginHistorical(ctx, missing); !errors.Is(e, ErrMigrationRequired) {
		t.Fatal("unknown retirement assumed empty", e)
	}
	if e = r.RestoreRetentionLedger(ctx, nil); !errors.Is(e, ErrMigrationRequired) {
		t.Fatal("incomplete reconstruction accepted", e)
	}
	wrong := append([]byte(nil), permission...)
	wrong[len(wrong)-5] ^= 1
	if e = r.RestoreRetentionLedger(ctx, [][]byte{wrong}); e == nil {
		t.Fatal("invalid authority reconstructed")
	}
	ok(t, r.RestoreRetentionLedger(ctx, [][]byte{permission}))
	if e = r.RestoreRetentionLedger(ctx, [][]byte{permission}); !errors.Is(e, ErrConflict) {
		t.Fatal("present ledger overwritten", e)
	}
	if _, e = r.BeginHistorical(ctx, old); !errors.Is(e, ErrProtected) {
		t.Fatal("reconstructed deletion lost", e)
	}
	third, e := r.BeginHistorical(ctx, missing)
	ok(t, e)
	for name, data := range other {
		ok(t, r.Put(ctx, third, name, data))
	}
	ok(t, r.Complete(ctx, third))
	s, e := r.Status(ctx)
	ok(t, e)
	if s.LatestComplete != head || s.HighestSequence != 5 {
		t.Fatal("head changed", s)
	}
	// Maintenance upgrades local state; immutable catalog and independent
	// recovery material retain their original format.
	ok(t, r.VerifyComplete(ctx, head))
}

func TestRetirementAuthorityCrashKeepsDataAndFencesReacquisition(t *testing.T) {
	tt, key, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	old, objects := synthetic(t, tt, key, 1, "old")
	id, e := r.Receive(ctx, old, fetch(objects))
	ok(t, e)
	latest, other := synthetic(t, tt, key, 2, "latest")
	head, e := r.Receive(ctx, latest, fetch(other))
	ok(t, e)
	permission := permit(t, r, maintenance, id)
	r.Fault = func(p string) error {
		if p == "retirement-authority-durable" {
			return errors.New("interrupted after authority")
		}
		return nil
	}
	if _, e = r.Maintain(ctx, permission); e == nil {
		t.Fatal("fault not reached")
	}
	ok(t, r.VerifyComplete(ctx, id))
	ok(t, r.VerifyComplete(ctx, head))
	r.Fault = nil
	_, e = r.Maintain(ctx, permission)
	ok(t, e)
	if _, e = r.BeginHistorical(ctx, old); !errors.Is(e, ErrProtected) {
		t.Fatal("retired catalog admitted after retry", e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "retention.json"))
	ok(t, e)
	raw[len(raw)/2] ^= 1
	ok(t, os.WriteFile(filepath.Join(dir, "retention.json"), raw, 0600))
	unknown, _ := synthetic(t, tt, key, 1, "unknown")
	if _, e = r.BeginHistorical(ctx, unknown); e == nil {
		t.Fatal("corrupt ledger treated as empty")
	}
}
