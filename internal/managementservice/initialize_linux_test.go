package managementservice

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
	"time"

	"github.com/nd4y/outpost/internal/management"
)

func TestManagementInitializationCrashChild(t *testing.T) {
	path := os.Getenv("OUTPOST_MANAGEMENT_INITIALIZATION_TEST_PROFILE")
	if path == "" {
		t.Skip("child only")
	}
	p, e := Load(path)
	must(t, e)
	ctx := context.Background()
	point := os.Getenv("OUTPOST_MANAGEMENT_INITIALIZATION_TEST_POINT")
	s, e := open(ctx, p, true, func(s *Service, options management.Options) error {
		return s.initialize(ctx, options, func(name string) error {
			if name == point {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
				select {}
			}
			return nil
		})
	})
	must(t, e)
	must(t, s.Close())
}

func TestManagementInitializationResumesAfterSIGKILL(t *testing.T) {
	for _, point := range []string{"management-initialization-profile-durable", "management-initialization-registry-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			f.p.RegistryJournalCopy = point == "management-initialization-registry-durable"
			ctx := context.Background()
			profile := filepath.Join(f.root, "initial-profile.json")
			data, e := json.Marshal(f.p)
			must(t, e)
			must(t, os.WriteFile(profile, data, 0600))
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestManagementInitializationCrashChild$")
			child.Env = append(os.Environ(), "OUTPOST_MANAGEMENT_INITIALIZATION_TEST_PROFILE="+profile, "OUTPOST_MANAGEMENT_INITIALIZATION_TEST_POINT="+point)
			output, e := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || bounded.Err() != nil {
				t.Fatal("child did not reach the interruption boundary", e, string(output))
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("unexpected termination", e, string(output))
			}
			if s, e := Open(ctx, f.p, false); !errors.Is(e, management.ErrConflict) {
				if s != nil {
					s.Close()
				}
				t.Fatal("pending profile activated", e)
			}
			changed := f.p
			changed.ReconcileSeconds++
			if s, e := Open(ctx, changed, true); !errors.Is(e, management.ErrConflict) {
				if s != nil {
					s.Close()
				}
				t.Fatal("different profile resumed initialization", e)
			}
			registryPath := filepath.Join(f.p.Local.Directory, "registry", "registry.json")
			before, e := os.ReadFile(registryPath)
			if f.p.RegistryJournalCopy {
				must(t, e)
			} else if !errors.Is(e, os.ErrNotExist) {
				t.Fatal("registry written before the interruption boundary", e)
			}
			s, e := Open(ctx, f.p, true)
			must(t, e)
			admitted, e := s.Status(ctx)
			must(t, e)
			if admitted.ProfileDigest != f.p.digest() || admitted.ProfileRevision != f.p.Revision {
				t.Fatal(admitted)
			}
			must(t, s.Close())
			if f.p.RegistryJournalCopy {
				after, e := os.ReadFile(registryPath)
				must(t, e)
				if !bytes.Equal(before, after) {
					t.Fatal("retry replaced the original registry")
				}
			}
			s, e = Open(ctx, f.p, false)
			must(t, e)
			must(t, s.Close())
			if s, e = Open(ctx, f.p, true); !errors.Is(e, management.ErrConflict) {
				if s != nil {
					s.Close()
				}
				t.Fatal("active runtime reinitialized", e)
			}
			must(t, os.Remove(filepath.Join(f.p.Local.Directory, "service", "profile.json")))
			if s, e = Open(ctx, f.p, true); !errors.Is(e, management.ErrConflict) {
				if s != nil {
					s.Close()
				}
				t.Fatal("existing registry reinitialized without a pending profile", e)
			}
		})
	}
}
