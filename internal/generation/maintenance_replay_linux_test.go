package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMaintenanceFrozenReplayPreservesLaterOrphansAndCurrentReferences(t *testing.T) {
	for _, protect := range []bool{false, true} {
		t.Run(map[bool]string{false: "later-orphan", true: "new-references"}[protect], func(t *testing.T) {
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
			p, e := VerifyPermit(permission, tt)
			ok(t, e)
			r.Fault = func(point string) error {
				if point == "retirement-durable" {
					return ioFailure
				}
				return nil
			}
			_, e = r.Maintain(ctx, permission)
			if !errors.Is(e, ioFailure) {
				t.Fatal("retirement fault not reached", e)
			}
			ok(t, r.Close())
			r, e = Open(dir, tt, false)
			ok(t, e)
			defer r.Close()
			if protect {
				newer, same := synthetic(t, tt, key, 3, "old")
				head, e = r.Receive(ctx, newer, fetch(same))
				ok(t, e)
			}
			later := []byte("new orphan outside original permission")
			laterPath := filepath.Join(dir, "objects", Hash(later))
			ok(t, os.WriteFile(laterPath, later, 0600))
			removed, e := r.Maintain(ctx, permission)
			ok(t, e)
			if protect && removed != 0 || !protect && removed != len(objects) {
				t.Fatal("wrong deletion scope", removed)
			}
			actual, e := os.ReadFile(laterPath)
			ok(t, e)
			if !bytes.Equal(actual, later) {
				t.Fatal("new orphan changed")
			}
			ok(t, r.VerifyComplete(ctx, head))
			result, e := r.MaintenanceResult(ctx, p.Operation)
			ok(t, e)
			if result.CandidateObjects != len(objects) || result.CandidateCatalogs != 1 || result.AbsentCatalogs != 1 || result.Permit != Hash(permission) {
				t.Fatal(result)
			}
			if protect && result.ProtectedObjects != len(objects) || !protect && result.AbsentObjects != len(objects) {
				t.Fatal(result)
			}
			// A completed replay has no new effect even if an old object returns.
			for object, data := range objects {
				ok(t, os.WriteFile(filepath.Join(dir, "objects", object), data, 0600))
			}
			removed, e = r.Maintain(ctx, permission)
			ok(t, e)
			if removed != 0 {
				t.Fatal("completed permit reused")
			}
			again, e := r.MaintenanceResult(ctx, p.Operation)
			ok(t, e)
			if again != result {
				t.Fatal("historical result changed")
			}
			for object := range objects {
				if _, e = os.Stat(filepath.Join(dir, "objects", object)); e != nil {
					t.Fatal("replay deleted reappeared object", e)
				}
			}
		})
	}
}

func TestMaintenanceMissingOrTamperedFrozenPlanCannotRecalculate(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "tampered"}[missing], func(t *testing.T) {
			tt, key, maintenance := trust(t)
			dir := filepath.Join(temp(t), "replica")
			r := openTest(t, dir, tt)
			a, objects := synthetic(t, tt, key, 1, "old")
			id, e := r.Receive(ctx, a, fetch(objects))
			ok(t, e)
			b, other := synthetic(t, tt, key, 2, "new")
			_, e = r.Receive(ctx, b, fetch(other))
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
			_, e = r.Maintain(ctx, permission)
			if !errors.Is(e, ioFailure) {
				t.Fatal(e)
			}
			r.Fault = nil
			name := filepath.Join(dir, gcName(p.Operation))
			if missing {
				ok(t, os.Remove(name))
			} else {
				ok(t, os.WriteFile(name, []byte("{}"), 0600))
			}
			_, e = r.Maintain(ctx, permission)
			if e == nil {
				t.Fatal("lost plan silently rebuilt")
			}
			for object, data := range objects {
				got, e := os.ReadFile(filepath.Join(dir, "objects", object))
				ok(t, e)
				if !bytes.Equal(got, data) {
					t.Fatal("payload lost")
				}
			}
		})
	}
}

func TestMaintenanceLegacyReceiptNeedsNewAuthorityAndOldReaderRejectsV3(t *testing.T) {
	tt, _, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	permission := permit(t, r, maintenance)
	_, e := r.Maintain(ctx, permission)
	ok(t, e)
	current, e := os.ReadFile(filepath.Join(dir, "state.json"))
	ok(t, e)
	var old legacyState
	if canonical(current, &old, MaxState) == nil {
		t.Fatal("old writer accepted new maintenance state")
	}
	// A retained state2 receipt predates frozen candidates; never infer its set.
	ok(t, r.locked(ctx, func(s *state) error { s.Format = StateFormat; s.GC = nil; return r.save(*s) }))
	orphan := []byte("legacy later orphan")
	name := filepath.Join(dir, "objects", Hash(orphan))
	ok(t, os.WriteFile(name, orphan, 0600))
	if _, e = r.Maintain(ctx, permission); !errors.Is(e, ErrMigrationRequired) {
		t.Fatal("legacy replay expanded scope", e)
	}
	if _, e = os.Stat(name); e != nil {
		t.Fatal(e)
	}
	next := permit(t, r, maintenance)
	removed, e := r.Maintain(ctx, next)
	ok(t, e)
	if removed != 1 {
		t.Fatal("new authority did not collect orphan", removed)
	}
}

func TestMaintenanceCancelledAfterDeletionResumesOriginalSet(t *testing.T) {
	tt, key, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	a, objects := synthetic(t, tt, key, 1, "old")
	id, e := r.Receive(ctx, a, fetch(objects))
	ok(t, e)
	b, other := synthetic(t, tt, key, 2, "new")
	head, e := r.Receive(ctx, b, fetch(other))
	ok(t, e)
	permission := permit(t, r, maintenance, id)
	p, e := VerifyPermit(permission, tt)
	ok(t, e)
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	r.Fault = func(point string) error {
		if point == "gc-object-removed" {
			cancel()
		}
		return nil
	}
	removed, e := r.Maintain(bounded, permission)
	if removed != 1 || !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation lost", removed, e)
	}
	if _, e = r.MaintenanceResult(ctx, p.Operation); !errors.Is(e, ErrIncomplete) {
		t.Fatal("partial GC falsely complete", e)
	}
	r.Fault = nil
	_, e = r.Maintain(ctx, permission)
	ok(t, e)
	result, e := r.MaintenanceResult(ctx, p.Operation)
	ok(t, e)
	if result.AbsentObjects != len(objects) {
		t.Fatal(result)
	}
	ok(t, r.VerifyComplete(ctx, head))
	encoded, e := json.Marshal(result)
	ok(t, e)
	if !bytes.Contains(encoded, []byte(`"completedUnix":`)) {
		t.Fatal("missing durable outcome")
	}
}

func TestMaintenanceAdmissionRevokedBetweenRemovals(t *testing.T) {
	tt, _, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	for _, data := range [][]byte{[]byte("orphan one"), []byte("orphan two")} {
		ok(t, os.WriteFile(filepath.Join(dir, "objects", Hash(data)), data, 0600))
	}
	permission := permit(t, r, maintenance)
	denied := errors.New("current command authority revoked")
	revoked := false
	r.Fault = func(point string) error {
		if point == "gc-object-removed" {
			revoked = true
		}
		return nil
	}
	removed, e := r.MaintainAdmitted(ctx, permission, func() error {
		if revoked {
			return denied
		}
		return nil
	})
	if removed != 1 || !errors.Is(e, denied) {
		t.Fatal("admission not rechecked between deletions", removed, e)
	}
	r.Fault = nil
	removed, e = r.MaintainAdmitted(ctx, permission, func() error { return nil })
	ok(t, e)
	if removed != 1 {
		t.Fatal("original set not resumed", removed)
	}
}
