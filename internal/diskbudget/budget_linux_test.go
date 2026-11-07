package diskbudget

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/teststore"
)

var testLimits = Limits{Capacity: 16 << 20, Reserve: 8 << 20, Spool: 4 << 20, Telemetry: 1 << 20}

func TestReconciliationUsesOpenedTreeAfterPathReplacement(t *testing.T) {
	b, root := newBudget(t)
	ctx := context.Background()
	must(t, os.WriteFile(filepath.Join(root, "objects", "retained"), make([]byte, 8192), 0600))
	held := root + "-held"
	must(t, os.Rename(root, held))
	must(t, os.Mkdir(root, 0700))
	t.Cleanup(func() { os.RemoveAll(held) })
	must(t, b.Reconcile(ctx, testLimits))
	state, e := b.Status(ctx)
	must(t, e)
	if state.Used["data"] < 8192 {
		t.Fatal("did not account retained tree", state.Used)
	}
	entries, e := os.ReadDir(root)
	must(t, e)
	if len(entries) != 0 {
		t.Fatal("replacement written", entries)
	}
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func newBudget(t *testing.T) (*Budget, string) {
	t.Helper()
	root := teststore.Root(t)
	must(t, os.Mkdir(filepath.Join(root, "objects"), 0700))
	b, e := Open(context.Background(), root, testLimits, true)
	must(t, e)
	t.Cleanup(func() { b.Close() })
	return b, root
}
func TestConcurrentReservationsShareQuotaAndKeepSeparateSpool(t *testing.T) {
	b, root := newBudget(t)
	other, e := Open(context.Background(), root, testLimits, false)
	must(t, e)
	defer other.Close()
	finish, e := b.Reserve(context.Background(), "objects/first", 2<<20)
	must(t, e)
	if release, e := other.Reserve(context.Background(), "objects/second", 2<<20); !errors.Is(e, ErrCapacity) {
		if release != nil {
			release(false)
		}
		t.Fatal("independent process handle oversubscribed data quota", e)
	}
	meta, e := other.Reserve(context.Background(), "jobs.json", 512<<10)
	must(t, e)
	must(t, meta(false))
	must(t, finish(false))
	s, e := b.Status(context.Background())
	must(t, e)
	if len(s.Pending) != 0 || s.Used["data"] < 2<<20 || s.Used["spool"] < 512<<10 {
		t.Fatal("uncertain write released its accounting charge")
	}
	must(t, b.Reconcile(context.Background(), testLimits))
	s, e = b.Status(context.Background())
	must(t, e)
	if s.Used["data"] >= 2<<20 {
		t.Fatal("reconciliation did not measure actual retained files")
	}
}
func TestReconciliationWaitsForActiveWriterAndNeverDeletesFiles(t *testing.T) {
	b, root := newBudget(t)
	finish, e := b.Reserve(context.Background(), "objects/keep", 1<<20)
	must(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if e = b.Reconcile(ctx, testLimits); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("reconciliation crossed active write lease", e)
	}
	must(t, os.WriteFile(filepath.Join(root, "objects", "keep"), make([]byte, 128<<10), 0600))
	must(t, finish(true))
	must(t, b.Reconcile(context.Background(), testLimits))
	s, e := b.Status(context.Background())
	must(t, e)
	if s.Used["data"] < 128<<10 || len(s.Pending) != 0 {
		t.Fatal(s)
	}
	info, e := os.Stat(filepath.Join(root, "objects", "keep"))
	must(t, e)
	if info.Size() != 128<<10 {
		t.Fatal("retained data changed")
	}
}
func TestCapacityCrashChild(t *testing.T) {
	if os.Getenv("OUTPOST_BUDGET_CHILD") != "1" {
		return
	}
	root := os.Getenv("OUTPOST_BUDGET_ROOT")
	b, e := Open(context.Background(), root, testLimits, false)
	must(t, e)
	defer b.Close()
	_, e = b.Reserve(context.Background(), "objects/crashed", 2<<20)
	must(t, e)
	f, e := os.OpenFile(filepath.Join(root, "objects", "crashed"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, e)
	_, e = f.Write(make([]byte, 128<<10))
	must(t, e)
	must(t, f.Sync())
	must(t, f.Close())
	fmt.Println("durable-reservation")
	for {
		time.Sleep(time.Hour)
	}
}
func TestSIGKILLReservationReconcilesWithoutDiscardingPayload(t *testing.T) {
	b, root := newBudget(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCapacityCrashChild$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "OUTPOST_BUDGET_CHILD=1", "OUTPOST_BUDGET_ROOT="+root)
	pipe, e := cmd.StdoutPipe()
	must(t, e)
	must(t, cmd.Start())
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line := make(chan bool, 1)
	go func() { scan := bufio.NewScanner(pipe); line <- scan.Scan() && scan.Text() == "durable-reservation" }()
	select {
	case ok := <-line:
		if !ok {
			t.Fatal("child did not reserve")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("child startup timeout")
	}
	must(t, cmd.Process.Kill())
	if e = cmd.Wait(); e == nil {
		t.Fatal("child was not killed")
	}
	s, e := b.Status(context.Background())
	must(t, e)
	if len(s.Pending) != 1 {
		t.Fatal("crash reservation was forgotten")
	}
	must(t, b.Reconcile(context.Background(), testLimits))
	s, e = b.Status(context.Background())
	must(t, e)
	if len(s.Pending) != 0 || s.Used["data"] < 128<<10 {
		t.Fatal("restart accounting lost payload", s)
	}
	finish, e := b.Reserve(context.Background(), "objects/next", 2<<20)
	must(t, e)
	must(t, finish(false))
	info, e := os.Stat(filepath.Join(root, "objects", "crashed"))
	must(t, e)
	if info.Size() != 128<<10 {
		t.Fatal("reconciliation deleted the crashed payload")
	}
}
func TestBudgetRejectsTraversalAndPreservesOverLimitHistory(t *testing.T) {
	b, root := newBudget(t)
	for _, name := range []string{"../escape", "/absolute", ".capacity/ledger.json", "objects/../hidden"} {
		if finish, e := b.Reserve(context.Background(), name, 1); e == nil {
			finish(false)
			t.Fatal("invalid path admitted")
		}
	}
	must(t, os.WriteFile(filepath.Join(root, "objects", "retained"), make([]byte, 4<<20), 0600))
	must(t, b.Reconcile(context.Background(), testLimits))
	if finish, e := b.Reserve(context.Background(), "objects/new", 1); !errors.Is(e, ErrCapacity) {
		if finish != nil {
			finish(false)
		}
		t.Fatal("over-limit history admitted a new object")
	}
	if _, e := os.Stat(filepath.Join(root, "objects", "retained")); e != nil {
		t.Fatal("retained file removed", e)
	}
}
