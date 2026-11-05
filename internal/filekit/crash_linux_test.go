package filekit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// This helper is a separate OS process. The parent waits for an explicit
// durability boundary and sends SIGKILL; no deferred cleanup can run.
func TestCrashChild(t *testing.T) {
	if os.Getenv("OUTPOST_CRASH_CHILD") != "1" {
		return
	}
	o, err := ReadOwner(os.Getenv("OUTPOST_OWNER"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(os.Getenv("OUTPOST_STORE"), o, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	point := os.Getenv("OUTPOST_POINT")
	s.Fault = func(p string) error {
		if p == point {
			if e := os.WriteFile(os.Getenv("OUTPOST_READY"), []byte(p), 0600); e != nil {
				return e
			}
			for {
				time.Sleep(time.Second)
			}
		}
		return nil
	}
	ctx := context.Background()
	switch os.Getenv("OUTPOST_ACTION") {
	case "backup":
		_, err = s.Backup(ctx, os.Getenv("OUTPOST_SOURCE"), BackupOptions{File: os.Getenv("OUTPOST_FILE"), Previous: os.Getenv("OUTPOST_PREVIOUS"), Names: []string{"file"}})
	case "repack":
		_, err = s.Repack(ctx)
	case "retire":
		_, err = s.Retire(ctx, []string{os.Getenv("OUTPOST_PREVIOUS")})
	default:
		t.Fatal("unknown crash action")
	}
	t.Fatalf("checkpoint not reached: %v", err)
}

func TestSIGKILLCommitBoundaries(t *testing.T) {
	cases := []struct{ action, point string }{
		{"backup", "object-written"}, {"backup", "object-synced"}, {"backup", "object-linked"}, {"backup", "object-durable"},
		{"backup", "descriptor-written"}, {"backup", "descriptor-synced"}, {"backup", "descriptor-renamed"}, {"backup", "descriptor-durable"},
		{"repack", "descriptor-written"}, {"repack", "descriptor-synced"}, {"repack", "descriptor-renamed"}, {"repack", "descriptor-durable"},
		{"repack", "repack-version-published"}, {"repack", "gc-object-removed"}, {"retire", "retire-unpublished"}, {"retire", "gc-object-removed"},
	}
	for _, tc := range cases {
		t.Run(tc.action+"/"+tc.point, func(t *testing.T) {
			base, s, source, old := fixture(t, 10<<20)
			ctx := context.Background()
			first := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
			changed := append([]byte(nil), old...)
			for i := 0; i < 256<<10; i++ {
				changed[(4<<20)+i] ^= 0x55
			}
			if err := os.WriteFile(source, changed, 0600); err != nil {
				t.Fatal(err)
			}
			versions := map[string][]byte{first.Version: old}
			if tc.action != "backup" {
				second := mustBackup(t, s, source, BackupOptions{File: first.File, Previous: first.Version, Names: []string{"file"}})
				versions[second.Version] = changed
			}
			saved := filepath.Join(base, "saved")
			if err := s.Export(ctx, first.Version, saved); err != nil {
				t.Fatal(err)
			}
			ownerPath := filepath.Join(base, "owner.json")
			if err := WriteOwner(ownerPath, s.Owner); err != nil {
				t.Fatal(err)
			}
			ready := filepath.Join(base, "ready")
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.timeout=45s")
			cmd.Env = append(os.Environ(), "OUTPOST_CRASH_CHILD=1", "OUTPOST_OWNER="+ownerPath, "OUTPOST_STORE="+filepath.Join(base, "store"), "OUTPOST_POINT="+tc.point, "OUTPOST_ACTION="+tc.action, "OUTPOST_READY="+ready, "OUTPOST_SOURCE="+source, "OUTPOST_FILE="+first.File, "OUTPOST_PREVIOUS="+first.Version)
			log, err := os.Create(filepath.Join(base, "child.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd.Stdout = log
			cmd.Stderr = log
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			killed := false
			defer func() {
				if !killed {
					_ = cmd.Process.Kill()
					<-done
				}
			}()
			deadline := time.Now().Add(35 * time.Second)
			for {
				if _, err = os.Stat(ready); err == nil {
					break
				}
				select {
				case err = <-done:
					killed = true
					b, _ := os.ReadFile(filepath.Join(base, "child.log"))
					t.Fatalf("child exited before boundary: %v %s", err, b)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("checkpoint timeout")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = <-done
			killed = true
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal("not an actual SIGKILL", err)
			}
			fresh, err := OpenStore(filepath.Join(base, "store"), s.Owner, false)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			ids, err := fresh.versions()
			if err != nil {
				t.Fatal(err)
			}
			if tc.action == "backup" && len(ids) == 2 {
				for _, id := range ids {
					if id != first.Version {
						versions[id] = changed
					}
				}
			}
			if tc.action == "retire" {
				delete(versions, first.Version)
			}
			if len(ids) != len(versions) {
				t.Fatalf("unexpected committed roots %d want %d", len(ids), len(versions))
			}
			for i, id := range ids {
				want, ok := versions[id]
				if !ok {
					t.Fatal("unexpected version")
				}
				mustRestore(t, fresh, id, filepath.Join(base, fmt.Sprintf("restored-%d", i)), want, false)
			}
			if err = fresh.RemoveAbandoned(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = fresh.GC(ctx); err != nil {
				t.Fatal(err)
			}
			kit, err := OpenStore(saved, s.Owner, false)
			if err != nil {
				t.Fatal(err)
			}
			defer kit.Close()
			mustRestore(t, kit, first.Version, filepath.Join(base, "independent"), old, true)
			for i, id := range ids {
				mustRestore(t, fresh, id, filepath.Join(base, fmt.Sprintf("after-gc-%d", i)), versions[id], false)
			}
			t.Logf("SIGKILL confirmed at %s/%s; %d committed versions restored before/after GC; pre-created independent kit restored", tc.action, tc.point, len(ids))
		})
	}
}

func TestCancelledEmptyRestoreAndOwnerPermissions(t *testing.T) {
	base, s, source, _ := fixture(t, 0)
	v := mustBackup(t, s, source, BackupOptions{Names: []string{"empty"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(base, "out")
	if _, err := s.RestoreVersion(ctx, v.Version, out); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("cancelled restore published output")
	}
	key := filepath.Join(base, "owner")
	if err := WriteOwner(key, s.Owner); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwner(key); err == nil {
		t.Fatal("publicly readable key accepted")
	}
}
