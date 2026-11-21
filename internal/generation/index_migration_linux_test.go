package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func legacyFixture(t *testing.T) (string, Trust, string, []byte) {
	t.Helper()
	base := temp(t)
	trust, key, _ := trust(t)
	dir := filepath.Join(base, "replica")
	r := openTest(t, dir, trust)
	a, objects := synthetic(t, trust, key, 1, "old")
	id, e := r.Receive(ctx, a, fetch(objects))
	ok(t, e)
	ok(t, r.Pin(ctx, Hash([]byte("pin")), id, "restore"))
	b, other := synthetic(t, trust, key, 2, "latest")
	_, e = r.Receive(ctx, b, fetch(other))
	ok(t, e)
	s, e := r.load()
	ok(t, e)
	old := legacyState{Format: Format, Trust: s.Trust, Revision: s.Revision, HighestSequence: s.HighestSequence, HighestID: s.HighestID, Latest: s.Latest, Generations: map[string]legacyEntry{}, Pins: s.Pins, Receipts: s.Receipts}
	for generation, item := range s.Generations {
		raw, e := r.Catalog(ctx, generation)
		ok(t, e)
		old.Generations[generation] = legacyEntry{raw, item.Complete}
	}
	raw, e := json.Marshal(old)
	ok(t, e)
	ok(t, r.Close())
	ok(t, os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600))
	// This is a disposable synthetic fixture, not a live migration cleanup.
	ok(t, os.RemoveAll(filepath.Join(dir, "catalogs")))
	return dir, trust, id, raw
}
func TestExplicitIndexMigrationPreservesHistoryAndGuardsRollback(t *testing.T) {
	dir, trust, id, old := legacyFixture(t)
	if r, e := Open(dir, trust, false); !errors.Is(e, ErrMigrationRequired) {
		if r != nil {
			r.Close()
		}
		t.Fatalf("open legacy: %v", e)
	}
	ok(t, MigrateLocal(ctx, dir, trust, nil))
	ok(t, MigrateLocal(ctx, dir, trust, nil))
	backup, e := os.ReadFile(filepath.Join(dir, "state.v1.json"))
	ok(t, e)
	if !bytes.Equal(backup, old) {
		t.Fatal("backup changed")
	}
	r, e := Open(dir, trust, false)
	ok(t, e)
	ok(t, r.VerifyComplete(ctx, id))
	status, e := r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 2 || len(status.Pins) != 1 {
		t.Fatalf("history lost: %+v", status)
	}
	ok(t, r.Close())
	ok(t, RollbackLocal(ctx, dir, trust, nil))
	raw, e := os.ReadFile(filepath.Join(dir, "state.json"))
	ok(t, e)
	if !bytes.Equal(raw, old) {
		t.Fatal("rollback bytes differ")
	}
	ok(t, MigrateLocal(ctx, dir, trust, nil))
	r, e = Open(dir, trust, false)
	ok(t, e)
	ok(t, r.Pin(ctx, Hash([]byte("new pin")), id, "kit"))
	ok(t, r.Close())
	if e = RollbackLocal(ctx, dir, trust, nil); !errors.Is(e, ErrProtected) {
		t.Fatalf("new state discarded: %v", e)
	}
}
func TestIndexMigrationInterruptedBeforePublicationIsRetryable(t *testing.T) {
	for _, point := range []string{"migration-backup-durable", "catalog-durable", "migration-before-switch"} {
		t.Run(point, func(t *testing.T) {
			dir, trust, id, old := legacyFixture(t)
			stop := errors.New("interrupted")
			e := migrateLocal(ctx, dir, trust, nil, func(at string) error {
				if at == point {
					return stop
				}
				return nil
			})
			if !errors.Is(e, stop) {
				t.Fatalf("fault not reached: %v", e)
			}
			raw, e := os.ReadFile(filepath.Join(dir, "state.json"))
			ok(t, e)
			if !bytes.Equal(raw, old) {
				t.Fatal("legacy state changed early")
			}
			ok(t, MigrateLocal(ctx, dir, trust, nil))
			r, e := Open(dir, trust, false)
			ok(t, e)
			defer r.Close()
			ok(t, r.VerifyComplete(ctx, id))
		})
	}
}
func TestIndexMigrationRejectsCorruptOrMissingCompletePayload(t *testing.T) {
	for _, damage := range []string{"catalog", "payload"} {
		t.Run(damage, func(t *testing.T) {
			dir, trust, id, old := legacyFixture(t)
			var s legacyState
			ok(t, json.Unmarshal(old, &s))
			if damage == "catalog" {
				item := s.Generations[id]
				item.Catalog = bytes.Replace(item.Catalog, []byte(`"policyVersion":1`), []byte(`"policyVersion":2`), 1)
				s.Generations[id] = item
				raw, e := json.Marshal(s)
				ok(t, e)
				ok(t, os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600))
			} else {
				c, e := VerifyCatalog(s.Generations[id].Catalog, trust)
				ok(t, e)
				ok(t, os.Remove(filepath.Join(dir, "objects", c.Kits[0].Objects[0].ID)))
			}
			if e := MigrateLocal(ctx, dir, trust, nil); e == nil {
				t.Fatal("damaged history migrated")
			}
			raw, e := os.ReadFile(filepath.Join(dir, "state.json"))
			ok(t, e)
			if !bytes.Contains(raw, []byte(`"format":"`+Format+`"`)) {
				t.Fatal("published damaged v2")
			}
		})
	}
}
func TestIndexMigrationCrashChild(t *testing.T) {
	if os.Getenv("OUTPOST_INDEX_CHILD") != "1" {
		return
	}
	dir := os.Getenv("OUTPOST_INDEX_DIR")
	raw, e := os.ReadFile(filepath.Join(filepath.Dir(dir), "trust.json"))
	ok(t, e)
	var trust Trust
	ok(t, json.Unmarshal(raw, &trust))
	e = migrateLocal(ctx, dir, trust, nil, func(point string) error {
		if point == "migration-before-switch" {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	})
	t.Fatalf("kill not reached: %v", e)
}
func TestIndexMigrationSIGKILLBeforeSwitchKeepsOldState(t *testing.T) {
	dir, trust, id, old := legacyFixture(t)
	raw, e := json.Marshal(trust)
	ok(t, e)
	ok(t, os.WriteFile(filepath.Join(filepath.Dir(dir), "trust.json"), raw, 0600))
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestIndexMigrationCrashChild$", "-test.timeout=10s")
	command.Env = append(os.Environ(), "OUTPOST_INDEX_CHILD=1", "OUTPOST_INDEX_DIR="+dir)
	log, e := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(e, &exit) {
		t.Fatalf("not killed: %v %s", e, log)
	}
	wait, yes := exit.Sys().(syscall.WaitStatus)
	if !yes || !wait.Signaled() || wait.Signal() != syscall.SIGKILL {
		t.Fatalf("wrong exit: %v %s", e, log)
	}
	raw, e = os.ReadFile(filepath.Join(dir, "state.json"))
	ok(t, e)
	if !bytes.Equal(raw, old) {
		t.Fatal("old state lost")
	}
	ok(t, MigrateLocal(ctx, dir, trust, nil))
	r, e := Open(dir, trust, false)
	ok(t, e)
	defer r.Close()
	ok(t, r.VerifyComplete(ctx, id))
}
func TestCatalogCacheCannotHideTamperingFromCompletionOrMaintenance(t *testing.T) {
	trust, key, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, trust)
	raw, objects := synthetic(t, trust, key, 1, "cache")
	id, e := r.Receive(ctx, raw, fetch(objects))
	ok(t, e)
	for oid, data := range objects {
		_, e = r.ReadObject(ctx, id, Object{oid, len(data)})
		ok(t, e)
	}
	p := permit(t, r, maintenance)
	bad := append([]byte(nil), raw...)
	bad[len(bad)-2] ^= 1
	ok(t, os.WriteFile(filepath.Join(dir, "catalogs", id), bad, 0600))
	if e = r.VerifyComplete(ctx, id); e == nil {
		t.Fatal("scrub used cached catalog")
	}
	if _, e = r.Maintain(ctx, p); e == nil {
		t.Fatal("maintenance used cached catalog")
	}
	for oid, data := range objects {
		if _, e = r.ReadObject(ctx, id, Object{oid, len(data)}); e == nil {
			t.Fatal("changed file stamp not detected")
		}
		break
	}
	needs, e := r.RepairNeeds(ctx)
	ok(t, e)
	if len(needs) != 1 || needs[0].Generation != id {
		t.Fatal("missing catalog repair fence", needs)
	}
	ok(t, r.RepairCatalogFor(ctx, id, needs[0].Token, raw))
	if e = r.VerifyComplete(ctx, id); !errors.Is(e, ErrIncomplete) {
		t.Fatal("catalog repair published unchecked payload", e)
	}
	verified, e := r.VerifyWindow(ctx, id, Hash([]byte("cache-repair-full-verification")), 16, 64<<20)
	ok(t, e)
	if !verified.Complete {
		t.Fatal("full verification unfinished", verified)
	}
	ok(t, r.VerifyComplete(ctx, id))
}
func TestCompactIndexSupportsHistoryBeyondFormerEmbeddedLimit(t *testing.T) {
	trust, key, _ := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, trust)
	raw, _ := synthetic(t, trust, key, 1, "large catalog")
	c, e := VerifyCatalog(raw, trust)
	ok(t, e)
	c.Kits[0].Objects = nil
	for i := 0; i < 10000; i++ {
		c.Kits[0].Objects = append(c.Kits[0].Objects, Object{Hash([]byte(fmt.Sprint(i))), 1})
	}
	// Sort opaque references once; only metadata is written, no large payloads.
	refs := map[string]Object{}
	for _, o := range c.Kits[0].Objects {
		refs[o.ID] = o
	}
	c.Kits[0].Objects = nil
	for _, id := range sortedIDs(refs) {
		c.Kits[0].Objects = append(c.Kits[0].Objects, refs[id])
	}
	total := 0
	for n := 1; n <= 42; n++ {
		c.Sequence = uint64(n)
		if n > 1 {
			c.Parent = Hash(raw)
		}
		raw, e = SignCatalog(c, key)
		ok(t, e)
		_, e = r.Begin(ctx, raw)
		ok(t, e)
		total += len(raw)
	}
	if total <= MaxState {
		t.Fatal("fixture did not exceed former embedded-state limit")
	}
	info, e := os.Stat(filepath.Join(dir, "state.json"))
	ok(t, e)
	if info.Size() > 32768 {
		t.Fatalf("index grew with catalog payloads: %d", info.Size())
	}
	// Normal lookup populates shared cache, with one global allocation budget.
	status, e := r.Status(ctx)
	ok(t, e)
	ok(t, r.locked(ctx, func(s *state) error {
		for _, id := range status.Receiving {
			if _, _, e := r.get(s, id, false); e != nil {
				return e
			}
		}
		return nil
	}))
	catalogCache.Lock()
	used := catalogCache.bytes
	catalogCache.Unlock()
	if used > catalogCacheBytes {
		t.Fatalf("cache budget: %d", used)
	}
	ok(t, r.Close())
	r, e = Open(dir, trust, false)
	ok(t, e)
	defer r.Close()
	after, e := r.Status(ctx)
	ok(t, e)
	if len(after.Receiving) != 42 {
		t.Fatal("history lost")
	}
}
