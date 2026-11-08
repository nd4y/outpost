package sourceagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/volume"
	"golang.org/x/sys/unix"
)

func installCandidates(t *testing.T, directory string) []string {
	t.Helper()
	entries, e := os.ReadDir(filepath.Dir(directory))
	must(t, e)
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), installPrefix) {
			names = append(names, entry.Name())
		}
	}
	return names
}

func TestSourceAtomicInstallPublishesBoundRuntimeAndCaptures(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.b
	b.Local.Directory = filepath.Join(b.Local.Volume.Root, "new source agent")
	a, e := Open(ctx, b, true)
	must(t, e)
	if len(installCandidates(t, b.Local.Directory)) != 0 || a.runtimeDirectory != b.Local.Directory {
		t.Fatal("successful install retained a candidate")
	}
	must(t, a.Next(ctx))
	must(t, a.Run(ctx))
	s, e := a.Status(ctx)
	must(t, e)
	must(t, a.Close())
	a, e = Open(ctx, b, false)
	must(t, e)
	defer a.Close()
	must(t, a.Run(ctx))
	if s.Sequence != 1 || s.Phase != "COMPLETE" {
		t.Fatal(s)
	}
	before, e := a.store.Read("agent.json")
	must(t, e)
	if duplicate, e := Open(ctx, b, true); e == nil {
		duplicate.Close()
		t.Fatal("init overwrote existing runtime")
	}
	after, e := a.store.Read("agent.json")
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("repeat init changed completed history")
	}
	want, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	must(t, os.RemoveAll(f.tree)) // Synthetic tree only, independent recovery proof.
	dest := filepath.Join(f.base, "installed-restore")
	_, e = generation.RecoverMaterialized(ctx, f.replicaPath, s.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, dest)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(dest, "private.bin"))
	must(t, e)
	if !bytes.Equal(got, want) {
		t.Fatal("installed runtime lost independent recovery")
	}
}

func TestSourceInstallSIGKILLChild(t *testing.T) {
	path := os.Getenv("OUTPOST_SOURCE_INSTALL_KILL")
	if path == "" {
		t.Skip("child only")
	}
	var input struct {
		Bootstrap Bootstrap
		Point     string
	}
	raw, e := os.ReadFile(path)
	must(t, e)
	must(t, json.Unmarshal(raw, &input))
	a, e := initializeAgent(context.Background(), input.Bootstrap, func(point string) error {
		if point == input.Point {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	})
	if a != nil {
		a.Close()
	}
	t.Fatal("installation kill boundary not reached", e)
}

func TestSourceInstallSIGKILLNeverExposesPartialFinalRuntime(t *testing.T) {
	for _, point := range []string{"source-install-directory-created", "source-install-stores-created", "source-install-state-durable", "source-install-published"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			b := f.b
			b.Local.Directory = filepath.Join(b.Local.Volume.Root, "interrupted agent")
			raw, e := json.Marshal(struct {
				Bootstrap Bootstrap
				Point     string
			}{b, point})
			must(t, e)
			input := filepath.Join(f.base, "install-child.json")
			must(t, os.WriteFile(input, raw, 0600))
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSourceInstallSIGKILLChild$")
			cmd.Env = append(os.Environ(), "OUTPOST_SOURCE_INSTALL_KILL="+input)
			output, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || ctx.Err() != nil {
				t.Fatal(e, string(output))
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal(e, string(output))
			}
			candidates := installCandidates(t, b.Local.Directory)
			published := point == "source-install-published"
			if published {
				if len(candidates) != 0 {
					t.Fatal("published runtime still staged")
				}
			} else {
				if _, e := os.Lstat(b.Local.Directory); !errors.Is(e, os.ErrNotExist) || len(candidates) != 1 {
					t.Fatal("partial final runtime visible", e, candidates)
				}
			}
			a, e := Open(ctx, b, !published)
			must(t, e)
			defer a.Close()
			s, e := a.Status(ctx)
			must(t, e)
			if s.Phase != "IDLE" || s.Sequence != 0 {
				t.Fatal(s)
			}
			remaining := installCandidates(t, b.Local.Directory)
			if strings.Join(candidates, ",") != strings.Join(remaining, ",") {
				t.Fatal("retry removed an earlier candidate")
			}
		})
	}
}

func TestSourceAtomicInstallConcurrentCandidateAndForeignDirectory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.b
	b.Local.Directory = filepath.Join(b.Local.Volume.Root, "competing")
	ready, release := make(chan struct{}, 2), make(chan struct{})
	type result struct {
		a *Agent
		e error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			a, e := initializeAgent(ctx, b, func(point string) error {
				if point == "source-install-state-durable" {
					ready <- struct{}{}
					<-release
				}
				return nil
			})
			results <- result{a, e}
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("candidate did not initialize")
		}
	}
	close(release)
	winners := 0
	for range 2 {
		r := <-results
		if r.e == nil {
			winners++
			must(t, r.a.Close())
		} else if !errors.Is(r.e, syscall.EEXIST) {
			t.Fatal("unexpected publication error", r.e)
		}
	}
	if winners != 1 || len(installCandidates(t, b.Local.Directory)) != 1 {
		t.Fatal("concurrent initializers merged or erased state", winners)
	}
	b.Local.Directory = filepath.Join(b.Local.Volume.Root, "foreign")
	must(t, os.Mkdir(b.Local.Directory, 0700))
	foreign := filepath.Join(b.Local.Directory, "untouched")
	must(t, os.WriteFile(foreign, []byte("foreign state"), 0600))
	if a, e := Open(ctx, b, true); e == nil {
		a.Close()
		t.Fatal("foreign runtime accepted")
	}
	data, e := os.ReadFile(foreign)
	must(t, e)
	if string(data) != "foreign state" || len(installCandidates(t, b.Local.Directory)) != 1 {
		t.Fatal("existing directory changed or extra candidate created")
	}
}

func TestSourceInstallVolumeLossBeforePublicationRetainsCandidate(t *testing.T) {
	f := newFixture(t)
	b := f.b
	b.Local.Directory = filepath.Join(b.Local.Volume.Root, "lost-volume")
	marker := filepath.Join(b.Local.Volume.Root, volume.Sentinel)
	_, e := initializeAgent(context.Background(), b, func(point string) error {
		if point == "source-install-state-durable" {
			return os.Rename(marker, marker+"-held")
		}
		return nil
	})
	if !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("lost volume published", e)
	}
	must(t, os.Rename(marker+"-held", marker))
	if _, e := os.Lstat(b.Local.Directory); !errors.Is(e, os.ErrNotExist) || len(installCandidates(t, b.Local.Directory)) != 1 {
		t.Fatal("failed install changed final directory", e)
	}
}

func TestSourceInstallCandidateLimitAndCancelledAdmission(t *testing.T) {
	f := newFixture(t)
	b := f.b
	b.Local.Directory = filepath.Join(b.Local.Volume.Root, "bounded-install")
	stopped := errors.New("interrupted installation")
	for range maxInstallCandidates {
		a, e := initializeAgent(context.Background(), b, func(point string) error {
			if point == "source-install-directory-created" {
				return stopped
			}
			return nil
		})
		if a != nil || !errors.Is(e, stopped) {
			t.Fatal(a, e)
		}
	}
	before := installCandidates(t, b.Local.Directory)
	if a, e := Open(context.Background(), b, true); a != nil || !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("retained candidate bound bypassed", a, e)
	}
	if strings.Join(before, ",") != strings.Join(installCandidates(t, b.Local.Directory), ",") {
		t.Fatal("capacity failure changed retained candidates")
	}
	// The bound is specific to the intended final directory. The lock itself
	// coordinates admission across processes sharing this private parent.
	b.Local.Directory = filepath.Join(b.Local.Volume.Root, "different-install")
	directory, e := os.Open(b.Local.Volume.Root)
	must(t, e)
	defer directory.Close()
	must(t, unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if a, e := Open(ctx, b, true); a != nil || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("busy admission ignored cancellation", a, e)
	}
	must(t, unix.Flock(int(directory.Fd()), unix.LOCK_UN))
	if len(installCandidates(t, b.Local.Directory)) != len(before) {
		t.Fatal("cancelled admission created a candidate")
	}
	a, e := Open(context.Background(), b, true)
	must(t, e)
	must(t, a.Close())
}
