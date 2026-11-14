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
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDetectedCorruptionRevokesEveryDependentPublication(t *testing.T) {
	tt, key, _ := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	first, objects := synthetic(t, tt, key, 1, "shared")
	one, e := r.Receive(ctx, first, fetch(objects))
	ok(t, e)
	second, same := synthetic(t, tt, key, 2, "shared")
	two, e := r.Receive(ctx, second, fetch(same))
	ok(t, e)
	pin := Hash([]byte("retained damaged file kit"))
	ok(t, r.Pin(ctx, pin, one, "kit"))
	refs, e := Dependencies(second, tt)
	ok(t, e)
	victim := refs[0]
	bad := bytes.Clone(objects[victim.ID])
	bad[0] ^= 1
	name := filepath.Join(dir, "objects", victim.ID)
	ok(t, os.WriteFile(name, bad, 0600))
	_, e = r.VerifyWindow(ctx, two, Hash([]byte("detect-corruption")), 2, MaxObject)
	if !errors.Is(e, ErrIncomplete) {
		t.Fatal("corrupt ciphertext not detected", e)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 0 || status.LatestComplete != "" {
		t.Fatal("detected shared damage still advertised as complete", status)
	}
	if status.Pins[pin].Generation != one {
		t.Fatal("detection discarded retained recovery root")
	}
	ok(t, r.Close())
	r, e = Open(dir, tt, false)
	ok(t, e)
	defer r.Close()
	status, e = r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 0 || status.LatestComplete != "" {
		t.Fatal("reopen lost corruption state", status)
	}
	for _, id := range []string{one, two} {
		if _, e = r.Catalog(ctx, id); !errors.Is(e, ErrIncomplete) {
			t.Fatal("damaged catalog offered for replication", e)
		}
	}
	preserved, e := os.ReadFile(name)
	ok(t, e)
	if !bytes.Equal(preserved, bad) {
		t.Fatal("detection erased corrupt evidence")
	}
}

func TestIntegrityRepairQuarantinesAndReverifiesSharedGenerations(t *testing.T) {
	tt, key, _ := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	first, objects := synthetic(t, tt, key, 1, "repair-shared")
	one, e := r.Receive(ctx, first, fetch(objects))
	ok(t, e)
	second, _ := synthetic(t, tt, key, 2, "repair-shared")
	two, e := r.Receive(ctx, second, fetch(objects))
	ok(t, e)
	pin := Hash([]byte("repair retained kit"))
	ok(t, r.Pin(ctx, pin, one, "kit"))
	refs, e := Dependencies(second, tt)
	ok(t, e)
	victim := refs[0]
	bad := bytes.Clone(objects[victim.ID])
	bad[0] ^= 1
	name := filepath.Join(dir, "objects", victim.ID)
	ok(t, os.WriteFile(name, bad, 0600))
	if e = r.RepairPut(ctx, two, victim.ID, bad); !errors.Is(e, ErrInvalid) {
		t.Fatal("bad replacement accepted", e)
	}
	reads := 0
	window := Hash([]byte("repair-shared-window"))
	result, e := r.RepairWindow(ctx, two, window, 2, MaxObject, func(ref Object) ([]byte, error) { reads++; return objects[ref.ID], nil })
	ok(t, e)
	if !result.Complete || reads != 1 || result.WrittenBytes != int64(victim.Bytes) {
		t.Fatal("repair copied healthy payload or missed completion", result, reads)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 1 || status.Complete[0] != two || len(status.Corrupt) != 1 || status.Corrupt[0] != one || status.Pins[pin].Generation != one {
		t.Fatal("dependent generation was republished without its own verification", status)
	}
	state, e := r.Integrity(ctx)
	ok(t, e)
	if len(state.Damage) != 0 || len(state.Repairs) != 1 {
		t.Fatal("missing repair journal", state)
	}
	for id, receipt := range state.Repairs {
		preserved, e := os.ReadFile(filepath.Join(dir, "quarantine/objects", id))
		ok(t, e)
		if !bytes.Equal(preserved, bad) || receipt.CompletedUnix == 0 || receipt.OriginalHash != Hash(bad) {
			t.Fatal("lost quarantine/receipt", receipt)
		}
	}
	ok(t, r.Close())
	r, e = Open(dir, tt, false)
	ok(t, e)
	defer r.Close()
	result, e = r.RepairWindow(ctx, two, window, 2, MaxObject, func(Object) ([]byte, error) { t.Fatal("replay fetched bytes"); return nil, nil })
	ok(t, e)
	if !result.Complete || result.ReadBytes != 0 {
		t.Fatal("replay did not reuse completed window", result)
	}
	after, e := r.Integrity(ctx)
	ok(t, e)
	a, _ := json.Marshal(state)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Fatal("replay changed historical receipt")
	}
	_, e = r.VerifyWindow(ctx, one, Hash([]byte("other-dependent-window")), 2, MaxObject)
	ok(t, e)
	ok(t, r.VerifyComplete(ctx, one))
	ok(t, r.VerifyComplete(ctx, two))
}

func TestIntegrityRepairQuarantineAdmissionAndTampering(t *testing.T) {
	tt, key, _ := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	raw, objects := synthetic(t, tt, key, 1, "repair-quota")
	id, e := r.Receive(ctx, raw, fetch(objects))
	ok(t, e)
	refs, e := Dependencies(raw, tt)
	ok(t, e)
	victim := refs[0]
	bad := bytes.Clone(objects[victim.ID])
	bad[0] ^= 1
	name := filepath.Join(dir, "objects", victim.ID)
	ok(t, os.WriteFile(name, bad, 0600))
	r.Admit = func(name string, size int) (func(bool) error, error) {
		if strings.HasPrefix(name, "quarantine/objects/") {
			return nil, statefile.ErrCapacity
		}
		return func(bool) error { return nil }, nil
	}
	if e = r.RepairPut(ctx, id, victim.ID, objects[victim.ID]); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("quarantine bypassed data admission", e)
	}
	preserved, e := os.ReadFile(name)
	ok(t, e)
	if !bytes.Equal(preserved, bad) {
		t.Fatal("quota denial replaced original")
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if len(status.Complete) != 0 {
		t.Fatal("quota denied but advertised healthy")
	}
	r.Admit = nil
	r.Fault = func(point string) error {
		if point == "quarantine-durable" {
			return errors.New("lost quarantine reply")
		}
		return nil
	}
	if e = r.RepairPut(ctx, id, victim.ID, objects[victim.ID]); e == nil {
		t.Fatal("fault not reached")
	}
	journal, e := r.Integrity(ctx)
	ok(t, e)
	for caseID := range journal.Repairs {
		ok(t, os.WriteFile(filepath.Join(dir, "quarantine/objects", caseID), []byte("tampered"), 0600))
	}
	r.Fault = nil
	if e = r.RepairPut(ctx, id, victim.ID, objects[victim.ID]); !errors.Is(e, ErrConflict) {
		t.Fatal("tampered evidence overwritten", e)
	}
	preserved, e = os.ReadFile(name)
	ok(t, e)
	if !bytes.Equal(preserved, bad) {
		t.Fatal("failed repair replaced original")
	}
}

func TestIntegrityRepairHandlesMissingEmptyAndRejectsUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "oversize", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			tt, key, _ := trust(t)
			dir := filepath.Join(temp(t), "replica")
			r := openTest(t, dir, tt)
			raw, objects := synthetic(t, tt, key, 1, "repair-entries")
			id, e := r.Receive(ctx, raw, fetch(objects))
			ok(t, e)
			refs, e := Dependencies(raw, tt)
			ok(t, e)
			victim := refs[0]
			name := filepath.Join(dir, "objects", victim.ID)
			ok(t, os.Remove(name))
			switch kind {
			case "empty":
				ok(t, os.WriteFile(name, nil, 0600))
			case "oversize":
				f, e := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
				ok(t, e)
				ok(t, f.Truncate(MaxObject+1))
				ok(t, f.Close())
			case "symlink":
				ok(t, os.Symlink("../state.json", name))
			case "fifo":
				ok(t, syscall.Mkfifo(name, 0600))
			}
			e = r.RepairPut(ctx, id, victim.ID, objects[victim.ID])
			if kind != "missing" && kind != "empty" {
				if e == nil {
					t.Fatal("unsafe entry replaced")
				}
				i, e := os.Lstat(name)
				ok(t, e)
				if kind == "symlink" && i.Mode()&os.ModeSymlink == 0 || kind == "fifo" && i.Mode()&os.ModeNamedPipe == 0 || kind == "oversize" && i.Size() != MaxObject+1 {
					t.Fatal("unsafe original changed")
				}
				return
			}
			ok(t, e)
			journal, e := r.Integrity(ctx)
			ok(t, e)
			if len(journal.Repairs) != 1 {
				t.Fatal("no missing/empty journal")
			}
			for caseID, receipt := range journal.Repairs {
				if receipt.Missing != (kind == "missing") || receipt.OriginalBytes != 0 {
					t.Fatal("incorrect evidence", receipt)
				}
				if kind == "empty" {
					old, e := os.ReadFile(filepath.Join(dir, "quarantine/objects", caseID))
					ok(t, e)
					if len(old) != 0 {
						t.Fatal("empty original lost")
					}
				}
			}
			if e = r.VerifyComplete(ctx, id); !errors.Is(e, ErrIncomplete) {
				t.Fatal("replacement automatically republished", e)
			}
			ok(t, r.Complete(ctx, id))
			ok(t, r.VerifyComplete(ctx, id))
		})
	}
}

func TestIntegrityRepairSIGKILLBoundaries(t *testing.T) {
	for _, point := range []string{"corruption-durable", "repair-intent-durable", "quarantine-durable", "repair-object-durable", "repair-result-durable", "before-complete"} {
		t.Run(point, func(t *testing.T) {
			base := temp(t)
			tt, key, _ := trust(t)
			dir := filepath.Join(base, "replica")
			r := openTest(t, dir, tt)
			raw, objects := synthetic(t, tt, key, 1, "repair-crash")
			id, e := r.Receive(ctx, raw, fetch(objects))
			ok(t, e)
			refs, e := Dependencies(raw, tt)
			ok(t, e)
			victim := refs[0]
			bad := bytes.Clone(objects[victim.ID])
			bad[0] ^= 1
			ok(t, os.WriteFile(filepath.Join(dir, "objects", victim.ID), bad, 0600))
			input, e := json.Marshal(crashInput{Trust: tt, Raw: raw, Objects: objects, ID: id})
			ok(t, e)
			ok(t, os.WriteFile(filepath.Join(base, "child.json"), input, 0600))
			ok(t, r.Close())
			bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			command := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestReplicaCrashChild$", "-test.timeout=10s")
			command.Env = append(os.Environ(), "OUTPOST_G2_CHILD=1", "OUTPOST_G2_ROOT="+base, "OUTPOST_G2_POINT="+point, "OUTPOST_G2_ACTION=repair")
			log, e := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatalf("child not killed: %v %s", e, log)
			}
			wait, yes := exit.Sys().(syscall.WaitStatus)
			if !yes || !wait.Signaled() || wait.Signal() != syscall.SIGKILL {
				t.Fatalf("not SIGKILL: %v %s", e, log)
			}
			r, e = Open(dir, tt, false)
			ok(t, e)
			defer r.Close()
			status, e := r.Status(ctx)
			ok(t, e)
			if len(status.Complete) != 0 || len(status.Corrupt) != 1 {
				t.Fatal("crash advertised unreverified closure", status)
			}
			result, e := r.RepairWindow(ctx, id, Hash([]byte("crash-repair-window")), 2, MaxObject, fetch(objects))
			ok(t, e)
			if !result.Complete {
				t.Fatal("repair restart incomplete", result)
			}
			journal, e := r.Integrity(ctx)
			ok(t, e)
			if len(journal.Repairs) != 1 || len(journal.Damage) != 0 {
				t.Fatal("duplicated/lost repair journal", journal)
			}
			for caseID, receipt := range journal.Repairs {
				preserved, e := os.ReadFile(filepath.Join(dir, "quarantine/objects", caseID))
				ok(t, e)
				if !bytes.Equal(preserved, bad) || receipt.CompletedUnix == 0 {
					t.Fatal("crash lost evidence")
				}
			}
			ok(t, r.VerifyComplete(ctx, id))
		})
	}
}
