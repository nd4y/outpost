package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nd4y/outpost/internal/statefile"
)

type maintenanceCheckpointFixture struct {
	replica       *Replica
	directory     string
	trust         Trust
	operation     string
	permission    []byte
	checkpoint    []byte
	latest        string
	later         string
	index, ledger []byte
}

func pendingMaintenanceCheckpoint(t *testing.T) maintenanceCheckpointFixture {
	t.Helper()
	trust, writer, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, trust)
	first, objects := synthetic(t, trust, writer, 1, "checkpoint-old")
	old, err := r.Receive(ctx, first, fetch(objects))
	ok(t, err)
	second, newer := synthetic(t, trust, writer, 2, "checkpoint-new")
	latest, err := r.Receive(ctx, second, fetch(newer))
	ok(t, err)
	permission := permit(t, r, maintenance, old)
	p, err := VerifyPermit(permission, trust)
	ok(t, err)
	r.Fault = func(point string) error {
		if point == "retirement-durable" {
			return ioFailure
		}
		return nil
	}
	_, err = r.Maintain(ctx, permission)
	if !errors.Is(err, ioFailure) {
		t.Fatal("pending retirement not reached", err)
	}
	r.Fault = nil
	raw, err := r.MaintenancePlanCheckpoint(ctx, p.Operation)
	ok(t, err)
	original, err := os.ReadFile(filepath.Join(dir, gcName(p.Operation)))
	ok(t, err)
	if !bytes.Equal(raw, original) {
		t.Fatal("checkpoint changed frozen bytes")
	}
	later := []byte("orphan created after the frozen plan")
	name := filepath.Join(dir, "objects", Hash(later))
	ok(t, os.WriteFile(name, later, 0600))
	index, err := os.ReadFile(filepath.Join(dir, "state.json"))
	ok(t, err)
	ledger, err := os.ReadFile(filepath.Join(dir, "retention.json"))
	ok(t, err)
	return maintenanceCheckpointFixture{r, dir, trust, p.Operation, permission, raw, latest, name, index, ledger}
}

func (f maintenanceCheckpointFixture) removePlan(t *testing.T) {
	t.Helper()
	ok(t, os.Remove(filepath.Join(f.directory, gcName(f.operation))))
}

func (f maintenanceCheckpointFixture) unchangedAuthority(t *testing.T) {
	t.Helper()
	for name, expected := range map[string][]byte{"state.json": f.index, "retention.json": f.ledger} {
		actual, err := os.ReadFile(filepath.Join(f.directory, name))
		ok(t, err)
		if !bytes.Equal(actual, expected) {
			t.Fatal("restoring metadata changed authority", name)
		}
	}
}

func TestMaintenancePlanCheckpointRestoresExactCandidatesAndPreservesLaterOrphan(t *testing.T) {
	f := pendingMaintenanceCheckpoint(t)
	f.removePlan(t)
	if _, err := f.replica.Maintain(ctx, f.permission); err == nil {
		t.Fatal("missing plan recalculated")
	}
	if _, err := f.replica.MaintenancePlanCheckpoint(ctx, f.operation); err == nil {
		t.Fatal("export invented missing checkpoint")
	}
	changed, err := f.replica.RestoreMaintenancePlanCheckpoint(ctx, f.operation, f.checkpoint, Hash(f.checkpoint))
	ok(t, err)
	if !changed {
		t.Fatal("absent pending plan not restored")
	}
	f.unchangedAuthority(t)
	changed, err = f.replica.RestoreMaintenancePlanCheckpoint(ctx, f.operation, f.checkpoint, Hash(f.checkpoint))
	ok(t, err)
	if changed {
		t.Fatal("replay rewrote plan")
	}
	f.unchangedAuthority(t)
	_, err = f.replica.Maintain(ctx, f.permission)
	ok(t, err)
	ok(t, f.replica.VerifyComplete(ctx, f.latest))
	if _, err := os.Stat(f.later); err != nil {
		t.Fatal("restored plan deleted a later orphan", err)
	}
	result, err := f.replica.MaintenanceResult(ctx, f.operation)
	ok(t, err)
	changed, err = f.replica.RestoreMaintenancePlanCheckpoint(ctx, f.operation, f.checkpoint, Hash(f.checkpoint))
	ok(t, err)
	if changed {
		t.Fatal("completed operation recreated plan")
	}
	f.removePlan(t)
	if _, err = f.replica.RestoreMaintenancePlanCheckpoint(ctx, f.operation, f.checkpoint, Hash(f.checkpoint)); !errors.Is(err, ErrConflict) {
		t.Fatal("completed operation's absent plan recreated", err)
	}
	again, err := f.replica.MaintenanceResult(ctx, f.operation)
	ok(t, err)
	if again != result {
		t.Fatal("recovery refreshed maintenance result")
	}
}

func TestMaintenancePlanCheckpointRefusesUnprovenOrConflictingRecovery(t *testing.T) {
	for _, kind := range []string{"hash", "operation", "changed", "ledger", "index", "existing", "symlink", "cancel", "quota", "appeared-during-admission"} {
		t.Run(kind, func(t *testing.T) {
			f := pendingMaintenanceCheckpoint(t)
			f.removePlan(t)
			operation, raw, expected := f.operation, f.checkpoint, Hash(f.checkpoint)
			request := context.Background()
			name := filepath.Join(f.directory, gcName(f.operation))
			foreign := []byte("foreign metadata must survive")
			switch kind {
			case "hash":
				expected = Hash([]byte("other checkpoint"))
			case "operation":
				operation = Hash([]byte("other operation"))
			case "changed":
				raw = append(bytes.Clone(raw), '\n')
				expected = Hash(raw)
			case "ledger":
				ok(t, os.Remove(filepath.Join(f.directory, "retention.json")))
			case "index":
				ok(t, os.Remove(filepath.Join(f.directory, "state.json")))
			case "existing":
				ok(t, os.WriteFile(name, foreign, 0600))
			case "symlink":
				outside := filepath.Join(temp(t), "foreign")
				ok(t, os.WriteFile(outside, foreign, 0600))
				ok(t, os.Symlink(outside, name))
			case "cancel":
				var cancel context.CancelFunc
				request, cancel = context.WithCancel(request)
				cancel()
			case "quota":
				f.replica.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
			case "appeared-during-admission":
				f.replica.Admit = func(part string, _ int) (func(bool) error, error) {
					if part != gcName(f.operation) {
						t.Fatal("unexpected mutation", part)
					}
					ok(t, os.WriteFile(name, foreign, 0600))
					return func(bool) error { return nil }, nil
				}
			}
			changed, err := f.replica.RestoreMaintenancePlanCheckpoint(request, operation, raw, expected)
			if err == nil || changed {
				t.Fatal("unproven recovery admitted", changed, err)
			}
			if kind == "existing" || kind == "symlink" || kind == "appeared-during-admission" {
				got, err := os.ReadFile(name)
				ok(t, err)
				if !bytes.Equal(got, foreign) {
					t.Fatal("foreign path overwritten")
				}
			} else if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refusal created a plan", err)
			}
			if kind != "index" && kind != "ledger" {
				f.unchangedAuthority(t)
			}
		})
	}
}

type maintenanceCheckpointChild struct {
	Directory, Operation string
	Trust                Trust
	Plan                 []byte
}

func TestMaintenancePlanCheckpointSIGKILLReplay(t *testing.T) {
	f := pendingMaintenanceCheckpoint(t)
	f.removePlan(t)
	config, err := json.Marshal(maintenanceCheckpointChild{f.directory, f.operation, f.trust, f.checkpoint})
	ok(t, err)
	name := filepath.Join(temp(t), "child.json")
	ok(t, os.WriteFile(name, config, 0600))
	binary, err := os.Executable()
	ok(t, err)
	child := exec.Command(binary, "-test.run=^TestMaintenancePlanCheckpointSIGKILLChild$", "-test.timeout=30s")
	child.Env = append(os.Environ(), "OUTPOST_MAINTENANCE_PLAN_CHILD="+name)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("expected real SIGKILL, got %v: %s", err, output)
	}
	changed, err := f.replica.RestoreMaintenancePlanCheckpoint(ctx, f.operation, f.checkpoint, Hash(f.checkpoint))
	ok(t, err)
	if changed {
		t.Fatal("lost reply repeated durable creation")
	}
	f.unchangedAuthority(t)
	_, err = f.replica.Maintain(ctx, f.permission)
	ok(t, err)
	ok(t, f.replica.VerifyComplete(ctx, f.latest))
	if _, err = os.Stat(f.later); err != nil {
		t.Fatal("SIGKILL recovery expanded frozen scope", err)
	}
	t.Log("actual SIGKILL after maintenance-plan-restored; exact replay and frozen maintenance completed")
}

func TestMaintenancePlanCheckpointSIGKILLChild(t *testing.T) {
	name := os.Getenv("OUTPOST_MAINTENANCE_PLAN_CHILD")
	if name == "" {
		t.Skip("child only")
	}
	raw, err := os.ReadFile(name)
	ok(t, err)
	var config maintenanceCheckpointChild
	ok(t, json.Unmarshal(raw, &config))
	r, err := Open(config.Directory, config.Trust, false)
	ok(t, err)
	defer r.Close()
	r.Fault = func(point string) error {
		if point == "maintenance-plan-restored" {
			ok(t, syscall.Kill(os.Getpid(), syscall.SIGKILL))
		}
		return nil
	}
	_, err = r.RestoreMaintenancePlanCheckpoint(ctx, config.Operation, config.Plan, Hash(config.Plan))
	t.Fatal("child did not stop at durable boundary", err)
}
