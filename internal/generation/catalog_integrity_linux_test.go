package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/statefile"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCatalogDamageReopenIsolatesGenerationAndAdmitsJournalBeforeServing(t *testing.T) {
	tt, key, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	first, objects := synthetic(t, tt, key, 1, "healthy-catalog")
	one, e := r.Receive(ctx, first, fetch(objects))
	ok(t, e)
	second, other := synthetic(t, tt, key, 2, "damaged-catalog")
	two, e := r.Receive(ctx, second, fetch(other))
	ok(t, e)
	keep := Hash([]byte("retained kit"))
	ok(t, r.Pin(ctx, keep, two, "kit"))
	ok(t, r.Close())
	original, e := os.ReadFile(filepath.Join(dir, "state.json"))
	ok(t, e)
	bad := bytes.Clone(second)
	bad[len(bad)/2] ^= 1
	ok(t, os.WriteFile(filepath.Join(dir, "catalogs", two), bad, 0600))
	r, e = Open(dir, tt, false)
	ok(t, e)
	defer r.Close()
	r.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if _, e = r.Status(ctx); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("unadmitted damage journal", e)
	}
	after, e := os.ReadFile(filepath.Join(dir, "state.json"))
	ok(t, e)
	if !bytes.Equal(after, original) {
		t.Fatal("open wrote before caller admission")
	}
	r.Admit = nil
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		go func() { _, e := r.Status(ctx); results <- e }()
	}
	for i := 0; i < 12; i++ {
		ok(t, <-results)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 1 || status.Complete[0] != one || len(status.Corrupt) != 1 || status.Corrupt[0] != two || status.LatestComplete != one || status.HighestSequence != 2 || status.Pins[keep].Generation != two {
		t.Fatal("healthy history or highest fence lost", status)
	}
	raw, e := r.Catalog(ctx, one)
	ok(t, e)
	if !bytes.Equal(raw, first) {
		t.Fatal("healthy catalog unavailable")
	}
	before := permit(t, r, maintenance)
	if _, e = r.Maintain(ctx, before); !errors.Is(e, ErrCatalogUnavailable) {
		t.Fatal("unknown closure allowed GC", e)
	}
	needs, e := r.RepairNeeds(ctx)
	ok(t, e)
	if len(needs) != 1 || needs[0].Generation != two {
		t.Fatal(needs)
	}
	if e = r.RepairCatalogFor(ctx, two, Hash([]byte("wrong-case")), second); !errors.Is(e, ErrConflict) {
		t.Fatal("stale repair authorized", e)
	}
	writes := 0
	r.Admit = func(name string, _ int) (func(bool) error, error) {
		if len(name) > 8 && name[:8] == "objects/" {
			writes++
		}
		return func(bool) error { return nil }, nil
	}
	ok(t, r.RepairCatalogFor(ctx, two, needs[0].Token, second))
	if writes != 0 {
		t.Fatal("metadata repair rewrote payload")
	}
	s, e := r.load()
	ok(t, e)
	if s.Format != CatalogStateFormat || len(s.CatalogDamage) != 0 || len(s.CatalogRepairs) != 1 || !s.Generations[two].Damaged {
		t.Fatal("repair certified unchecked payload", s)
	}
	for id, record := range s.CatalogRepairs {
		body, e := os.ReadFile(filepath.Join(dir, "quarantine/catalogs", id))
		ok(t, e)
		if !bytes.Equal(body, bad) || record.CompletedUnix < 1 {
			t.Fatal("catalog evidence lost")
		}
	}
	done, e := r.VerifyWindow(ctx, two, Hash([]byte("fresh after catalog repair")), 16, 64<<20)
	ok(t, e)
	if !done.Complete {
		t.Fatal(done)
	}
	status, e = r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 2 || status.LatestComplete != two {
		t.Fatal("full verification failed to republish", status)
	}
	// A new incident gets a new token. An old completed transfer cannot repair it.
	ok(t, os.WriteFile(filepath.Join(dir, "catalogs", two), bad, 0600))
	if _, e = r.Catalog(ctx, two); !errors.Is(e, ErrCatalogUnavailable) {
		t.Fatal(e)
	}
	fresh, e := r.RepairNeeds(ctx)
	ok(t, e)
	if fresh[0].Token == needs[0].Token {
		t.Fatal("catalog damage reused old incarnation")
	}
	if e = r.RepairCatalogFor(ctx, two, needs[0].Token, second); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestCatalogDamageDoesNotPreventSharedObjectFencing(t *testing.T) {
	tt, key, _ := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	first, objects := synthetic(t, tt, key, 1, "shared-with-unknown")
	one, e := r.Receive(ctx, first, fetch(objects))
	ok(t, e)
	second, _ := synthetic(t, tt, key, 2, "shared-with-unknown")
	two, e := r.Receive(ctx, second, fetch(objects))
	ok(t, e)
	bad := bytes.Clone(second)
	bad[0] ^= 1
	ok(t, os.WriteFile(filepath.Join(dir, "catalogs", two), bad, 0600))
	refs, e := Dependencies(first, tt)
	ok(t, e)
	ref := refs[0]
	payload := bytes.Clone(objects[ref.ID])
	payload[0] ^= 1
	ok(t, os.WriteFile(filepath.Join(dir, "objects", ref.ID), payload, 0600))
	if _, e = r.VerifyWindow(ctx, one, Hash([]byte("shared detection")), 16, 64<<20); !errors.Is(e, ErrIncomplete) {
		t.Fatal(e)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 0 || len(status.Corrupt) != 2 {
		t.Fatal("unknown catalog prevented shared fencing", status)
	}
	s, e := r.load()
	ok(t, e)
	if len(s.Damage) != 1 || len(s.CatalogDamage) != 1 {
		t.Fatal("lost independent incidents")
	}
	s.Format = IntegrityStateFormat
	if _, e = r.validateState(s); e == nil {
		t.Fatal("new catalog state accepted old reader format")
	}
}
func TestCatalogRepairSIGKILLPreservesOriginalAndReplay(t *testing.T) {
	for _, point := range []string{"repair-intent-durable", "quarantine-durable", "repair-object-durable", "repair-result-durable"} {
		t.Run(point, func(t *testing.T) {
			tt, key, _ := trust(t)
			dir := filepath.Join(temp(t), "replica")
			r := openTest(t, dir, tt)
			raw, objects := synthetic(t, tt, key, 1, "catalog-crash")
			id, e := r.Receive(ctx, raw, fetch(objects))
			ok(t, e)
			bad := bytes.Clone(raw)
			bad[0] ^= 1
			ok(t, os.WriteFile(filepath.Join(dir, "catalogs", id), bad, 0600))
			if _, e = r.Catalog(ctx, id); !errors.Is(e, ErrCatalogUnavailable) {
				t.Fatal(e)
			}
			needs, e := r.RepairNeeds(ctx)
			ok(t, e)
			in := catalogRepairChild{dir, tt, id, needs[0].Token, raw, point}
			body, e := json.Marshal(in)
			ok(t, e)
			file := filepath.Join(filepath.Dir(dir), "child.json")
			ok(t, os.WriteFile(file, body, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestCatalogRepairCrashChild$")
			child.Env = append(os.Environ(), "OUTPOST_CATALOG_CHILD="+file)
			output, e := child.CombinedOutput()
			exit, okExit := e.(*exec.ExitError)
			if !okExit || bounded.Err() != nil {
				t.Fatalf("not killed %v %s", e, output)
			}
			status, okStatus := exit.Sys().(syscall.WaitStatus)
			if !okStatus || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("wrong termination", e)
			}
			reopened, e := Open(dir, tt, false)
			ok(t, e)
			defer reopened.Close()
			ok(t, reopened.RepairCatalogFor(ctx, id, needs[0].Token, raw))
			s, e := reopened.load()
			ok(t, e)
			if len(s.CatalogRepairs) != 1 {
				t.Fatal("duplicate repair")
			}
			for caseID, record := range s.CatalogRepairs {
				old, e := os.ReadFile(filepath.Join(dir, "quarantine/catalogs", caseID))
				ok(t, e)
				if !bytes.Equal(old, bad) || record.CompletedUnix == 0 {
					t.Fatal("lost original catalog")
				}
			}
			prior, _ := json.Marshal(s.CatalogRepairs)
			ok(t, reopened.RepairCatalogFor(ctx, id, needs[0].Token, raw))
			after, e := reopened.load()
			ok(t, e)
			again, _ := json.Marshal(after.CatalogRepairs)
			if !bytes.Equal(prior, again) {
				t.Fatal("receipt refreshed")
			}
			done, e := reopened.VerifyWindow(ctx, id, Hash([]byte("post-crash-check")), 16, 64<<20)
			ok(t, e)
			if !done.Complete {
				t.Fatal(done)
			}
		})
	}
}

type catalogRepairChild struct {
	Directory string
	Trust     Trust
	ID, Token string
	Raw       []byte
	Point     string
}

func TestCatalogRepairCrashChild(t *testing.T) {
	file := os.Getenv("OUTPOST_CATALOG_CHILD")
	if file == "" {
		return
	}
	raw, e := os.ReadFile(file)
	ok(t, e)
	var in catalogRepairChild
	ok(t, json.Unmarshal(raw, &in))
	r, e := Open(in.Directory, in.Trust, false)
	ok(t, e)
	defer r.Close()
	r.Fault = func(point string) error {
		if point == in.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	ok(t, r.RepairCatalogFor(ctx, in.ID, in.Token, in.Raw))
	t.Fatal("kill point absent")
}

func TestCatalogRepairMissingEmptyAndUnsafeEntryPreservation(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			tt, key, _ := trust(t)
			base := temp(t)
			dir := filepath.Join(base, "replica")
			r := openTest(t, dir, tt)
			raw, objects := synthetic(t, tt, key, 1, "catalog-edge")
			id, e := r.Receive(ctx, raw, fetch(objects))
			ok(t, e)
			ok(t, r.Close())
			name := filepath.Join(dir, "catalogs", id)
			target := filepath.Join(base, "unrelated")
			switch kind {
			case "missing":
				ok(t, os.Remove(name))
			case "empty":
				ok(t, os.WriteFile(name, nil, 0600))
			case "symlink":
				ok(t, os.WriteFile(target, []byte("retained unrelated bytes"), 0600))
				ok(t, os.Remove(name))
				ok(t, os.Symlink(target, name))
			}
			r, e = Open(dir, tt, false)
			ok(t, e)
			defer r.Close()
			needs, e := r.RepairNeeds(ctx)
			ok(t, e)
			if len(needs) != 1 {
				t.Fatal("reopen missed unknown catalog")
			}
			e = r.RepairCatalogFor(ctx, id, needs[0].Token, raw)
			if kind == "symlink" {
				if e == nil {
					t.Fatal("unsafe catalog overwritten")
				}
				body, e := os.ReadFile(target)
				ok(t, e)
				if string(body) != "retained unrelated bytes" {
					t.Fatal("followed unsafe catalog")
				}
				info, e := os.Lstat(name)
				ok(t, e)
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("removed unsafe evidence")
				}
				return
			}
			ok(t, e)
			journal, e := r.Integrity(ctx)
			ok(t, e)
			if len(journal.CatalogRepairs) != 1 {
				t.Fatal("missing catalog receipt")
			}
			for caseID, v := range journal.CatalogRepairs {
				if v.Missing != (kind == "missing") {
					t.Fatal("absence/empty confused")
				}
				if kind == "empty" {
					body, e := os.ReadFile(filepath.Join(dir, "quarantine/catalogs", caseID))
					ok(t, e)
					if len(body) != 0 {
						t.Fatal("empty original not retained")
					}
				}
			}
			result, e := r.VerifyWindow(ctx, id, Hash([]byte("edge verify")), 16, 64<<20)
			ok(t, e)
			if !result.Complete {
				t.Fatal(result)
			}
		})
	}
}
