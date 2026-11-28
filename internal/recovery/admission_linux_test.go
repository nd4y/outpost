package recovery

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

var smallLimits = Limits{Bytes: 16 << 20, Entries: 128, FreeBytes: 1 << 20, FreeInodes: 32}

func TestRecoveryAdmissionFreeFloorsAndEntryExhaustion(t *testing.T) {
	for _, kind := range []string{"bytes", "inodes"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(teststore.Root(t), "empty")
			must(t, os.Mkdir(dir, 0700))
			root, e := localfs.OpenRoot(dir)
			must(t, e)
			defer root.Close()
			limits := smallLimits
			if kind == "bytes" {
				limits.FreeBytes = 1 << 60
			} else {
				limits.FreeInodes = 1 << 40
			}
			if unexpected, e := OpenAdmission(context.Background(), root, limits, true, func(ctx context.Context) error { return ctx.Err() }); !errors.Is(e, ErrCapacity) {
				if unexpected != nil {
					unexpected.Close()
				}
				t.Fatal("free floor ignored", e)
			}
			entries, e := os.ReadDir(dir)
			must(t, e)
			if len(entries) != 0 {
				t.Fatal("failed admission created metadata")
			}
		})
	}
	a, dir, _ := admissionFixture(t)
	for i := 0; i < smallLimits.Entries; i++ {
		put(t, dir, "entry-"+strconv.Itoa(i), nil)
	}
	called := false
	if e := a.WithReservation(context.Background(), request("entry-overload", 4096), func(*Lease) error { called = true; return nil }); !errors.Is(e, ErrCapacity) || called {
		t.Fatal("entry capacity ignored", e, called)
	}
}

func TestRecoveryAdmissionMidWriteVolumeLossRetainsPromise(t *testing.T) {
	a, dir, _ := admissionFixture(t)
	ctx := context.Background()
	moved := dir + "-held"
	e := a.WithReservation(ctx, request("identity-loss", 4096), func(l *Lease) error {
		put(t, dir, "partial", []byte("retained"))
		must(t, os.Rename(dir, moved))
		must(t, os.Mkdir(dir, 0700))
		return l.Guard(ctx)
	})
	if e == nil {
		t.Fatal("mid-write replacement ignored")
	}
	s, e := a.load()
	must(t, e)
	if len(s.Pending) != 1 {
		t.Fatal("unknown volume state discarded promise", s)
	}
	b, e := os.ReadFile(filepath.Join(moved, "partial"))
	must(t, e)
	if string(b) != "retained" {
		t.Fatal("lost original output")
	}
	entries, e := os.ReadDir(dir)
	must(t, e)
	if len(entries) != 0 {
		t.Fatal("fallback path modified")
	}
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func request(name string, size int64) ReservationRequest {
	return ReservationRequest{Operation: storage.Hash([]byte(name)), Binding: storage.Hash([]byte("bound/" + name)), Estimate: Estimate{Bytes: size, Entries: 8}}
}
func admissionFixture(t *testing.T) (*Admission, string, func(context.Context) error) {
	t.Helper()
	dir := filepath.Join(teststore.Root(t), "admitted")
	must(t, os.Mkdir(dir, 0700))
	root, e := localfs.OpenRoot(dir)
	must(t, e)
	defer root.Close()
	original, e := root.Stat(".")
	must(t, e)
	guard := func(ctx context.Context) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		r, e := localfs.OpenRoot(dir)
		if e != nil {
			return e
		}
		defer r.Close()
		now, e := r.Stat(".")
		if e != nil {
			return e
		}
		if !os.SameFile(original, now) {
			return localfs.ErrBoundary
		}
		return nil
	}
	a, e := OpenAdmission(context.Background(), root, smallLimits, true, guard)
	must(t, e)
	t.Cleanup(func() { a.Close() })
	return a, dir, guard
}
func put(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, e)
	_, e = f.Write(b)
	must(t, e)
	must(t, f.Sync())
	must(t, f.Close())
}

func TestRecoveryAdmissionPreservesCrashReservationsAndRefusesConflicts(t *testing.T) {
	a, dir, guard := admissionFixture(t)
	ctx := context.Background()
	first := request("retained", 8<<20)
	fault := errors.New("after durable reservation")
	a.Fault = func(point string) error {
		if point == "recovery-reservation-durable" {
			return fault
		}
		return nil
	}
	called := false
	if e := a.WithReservation(ctx, first, func(*Lease) error { called = true; return nil }); !errors.Is(e, fault) || called {
		t.Fatal("reservation boundary", e, called)
	}
	r, e := localfs.OpenRoot(dir)
	must(t, e)
	defer r.Close()
	b, e := OpenAdmission(ctx, r, smallLimits, false, guard)
	must(t, e)
	defer b.Close()
	s, e := b.Status(ctx)
	must(t, e)
	if len(s.Pending) != 1 || s.Pending[first.Operation] != first {
		t.Fatal("lost reservation", s)
	}
	if e = b.WithReservation(ctx, request("other", 8<<20), func(*Lease) error { called = true; return nil }); !errors.Is(e, ErrCapacity) || called {
		t.Fatal("ignored foreign promise", e, called)
	}
	wrong := first
	wrong.Binding = storage.Hash([]byte("changed"))
	if e = b.WithReservation(ctx, wrong, func(*Lease) error { return nil }); !errors.Is(e, ErrConflict) {
		t.Fatal("rebound accepted operation", e)
	}
	must(t, b.WithReservation(ctx, first, func(l *Lease) error {
		put(t, dir, "retained-data", bytes.Repeat([]byte{9}, 65536))
		return l.BeforePublish(ctx)
	}))
	s, e = b.Status(ctx)
	must(t, e)
	if len(s.Pending) != 0 {
		t.Fatal("completed writer retained promise", s)
	}
	payload, e := os.ReadFile(filepath.Join(dir, "retained-data"))
	must(t, e)
	if len(payload) != 65536 {
		t.Fatal("reconciliation erased bytes")
	}
	changed := smallLimits
	changed.Bytes++
	if unexpected, e := OpenAdmission(ctx, r, changed, false, guard); e == nil {
		unexpected.Close()
		t.Fatal("changed capacity profile silently admitted")
	}
}

func TestRecoveryAdmissionSerializesWritersAndRetainsCanceledOutput(t *testing.T) {
	a, dir, guard := admissionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, e := localfs.OpenRoot(dir)
	must(t, e)
	defer r.Close()
	other, e := OpenAdmission(context.Background(), r, smallLimits, false, guard)
	must(t, e)
	defer other.Close()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- a.WithReservation(ctx, request("active", 1<<20), func(l *Lease) error {
			put(t, dir, "partial", []byte("preserved partial plaintext"))
			close(started)
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	<-started
	limited, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	called := false
	if e = other.WithReservation(limited, request("waiting", 1<<20), func(*Lease) error { called = true; return nil }); !errors.Is(e, context.DeadlineExceeded) || called {
		t.Fatal("parallel reservation escaped global lock", e, called)
	}
	cancel()
	if e = <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	s, e := other.Status(context.Background())
	must(t, e)
	if len(s.Pending) != 0 {
		t.Fatal(s)
	}
	if b, e := os.ReadFile(filepath.Join(dir, "partial")); e != nil || string(b) != "preserved partial plaintext" {
		t.Fatal("cancellation erased owned output", e)
	}
	must(t, other.WithReservation(context.Background(), request("next", 1<<20), func(l *Lease) error { return l.BeforePublish(context.Background()) }))
}

func TestRecoveryAdmissionCountsTreesWithoutFollowingLinksAndChecksGrowth(t *testing.T) {
	a, dir, _ := admissionFixture(t)
	ctx := context.Background()
	outside := filepath.Join(filepath.Dir(dir), "outside")
	must(t, os.Mkdir(outside, 0700))
	put(t, outside, "external", []byte("outside stays untouched"))
	must(t, os.Symlink(outside, filepath.Join(dir, "link")))
	must(t, a.WithReservation(ctx, request("bounded", 4096), func(l *Lease) error { return l.BeforePublish(ctx) }))
	e := a.WithReservation(ctx, request("underestimated", 4096), func(l *Lease) error {
		put(t, dir, "oversized", bytes.Repeat([]byte{3}, 5<<20))
		return l.BeforePublish(ctx)
	})
	if !errors.Is(e, ErrCapacity) {
		t.Fatal("actual tree growth ignored", e)
	}
	b, e := os.ReadFile(filepath.Join(outside, "external"))
	must(t, e)
	if string(b) != "outside stays untouched" {
		t.Fatal("followed/restored into link")
	}
	must(t, syscall.Mkfifo(filepath.Join(dir, "special"), 0600))
	called := false
	if e = a.WithReservation(ctx, request("after-fifo", 4096), func(*Lease) error { called = true; return nil }); !errors.Is(e, ErrInvalid) || called {
		t.Fatal("unsafe tree admitted", e, called)
	}
}

func TestRecoveryAdmissionVolumeLossNeverFallsBack(t *testing.T) {
	a, dir, _ := admissionFixture(t)
	moved := dir + "-held"
	must(t, os.Rename(dir, moved))
	must(t, os.Mkdir(dir, 0700))
	called := false
	if e := a.WithReservation(context.Background(), request("moved", 4096), func(*Lease) error { called = true; return nil }); e == nil || called {
		t.Fatal("volume replacement admitted", e, called)
	}
	entries, e := os.ReadDir(dir)
	must(t, e)
	if len(entries) != 0 {
		t.Fatal("wrote fallback root")
	}
}

func TestRecoveryAdmissionSIGKILLPreservesOwnedOutputAndReservation(t *testing.T) {
	for _, point := range []string{"recovery-reservation-durable", "recovery-attempt-returned", "recovery-reservation-released"} {
		t.Run(point, func(t *testing.T) {
			a, dir, guard := admissionFixture(t)
			child := exec.Command(os.Args[0], "-test.run=^TestRecoveryAdmissionCrashChild$")
			child.Env = append(os.Environ(), "OUTPOST_RECOVERY_CHILD="+dir, "OUTPOST_RECOVERY_POINT="+point)
			output, e := child.CombinedOutput()
			if e == nil {
				t.Fatalf("child did not crash: %s", output)
			}
			exit, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatal(e)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("unexpected exit %v: %s", e, output)
			}
			r, e := localfs.OpenRoot(dir)
			must(t, e)
			defer r.Close()
			b, e := OpenAdmission(context.Background(), r, smallLimits, false, guard)
			must(t, e)
			defer b.Close()
			s, e := b.Status(context.Background())
			must(t, e)
			want := 1
			if point == "recovery-reservation-released" {
				want = 0
			}
			if len(s.Pending) != want {
				t.Fatal("wrong durable promise", s)
			}
			if point != "recovery-reservation-durable" {
				body, e := os.ReadFile(filepath.Join(dir, "owned-output"))
				must(t, e)
				if string(body) != "retained after real process kill" {
					t.Fatal("lost output")
				}
			}
			must(t, a.WithReservation(context.Background(), request("crash", 1<<20), func(l *Lease) error { return l.BeforePublish(context.Background()) }))
		})
	}
}
func TestRecoveryAdmissionCrashChild(t *testing.T) {
	dir := os.Getenv("OUTPOST_RECOVERY_CHILD")
	if dir == "" {
		return
	}
	ctx := context.Background()
	r, e := localfs.OpenRoot(dir)
	must(t, e)
	defer r.Close()
	a, e := OpenAdmission(ctx, r, smallLimits, false, func(ctx context.Context) error { return ctx.Err() })
	must(t, e)
	defer a.Close()
	a.Fault = func(point string) error {
		if point == os.Getenv("OUTPOST_RECOVERY_POINT") {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	must(t, a.WithReservation(ctx, request("crash", 1<<20), func(l *Lease) error {
		put(t, dir, "owned-output", []byte("retained after real process kill"))
		return l.BeforePublish(ctx)
	}))
}
