package managementservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

func TestManagementServiceSnapshotAtomicNewFileLeaseAndOfflineRead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, e := Open(ctx, f.p, true)
	must(t, e)
	defer s.Close()
	exports := filepath.Join(f.root, "exports")
	must(t, os.Mkdir(exports, 0700))
	output := filepath.Join(exports, "checkpoint.ops")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.Snapshot(canceled, output, 8<<20); e == nil {
		t.Fatal("canceled export")
	}
	if _, e = os.Stat(output); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("canceled export published")
	}
	stop, done := start(t, s, f.client)
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_, e = s.Snapshot(short, output, 8<<20)
	cancel()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("stole execution lease", e)
	}
	stop()
	must(t, <-done)
	receipt, e := s.Snapshot(ctx, output, 8<<20)
	must(t, e)
	trust := management.SnapshotTrust{Format: management.SnapshotTrustFormat, Owner: f.p.Local.Owner, Signer: s.signer.Public().(ed25519.PublicKey), Checkpoint: receipt.Checkpoint}
	inspected, e := management.InspectSnapshotFile(ctx, output, trust, 8<<20)
	must(t, e)
	if inspected.SnapshotReceipt != receipt {
		t.Fatal(inspected)
	}
	original, e := os.ReadFile(output)
	must(t, e)
	if _, e = s.Snapshot(ctx, output, 8<<20); !errors.Is(e, management.ErrConflict) {
		t.Fatal(e)
	}
	same, e := os.ReadFile(output)
	must(t, e)
	if string(same) != string(original) {
		t.Fatal("replaced export")
	}
	entries, e := os.ReadDir(exports)
	must(t, e)
	if len(entries) != 1 {
		t.Fatal("successful export leaked temporary file", entries)
	}
	if _, e = s.Snapshot(ctx, filepath.Join(f.p.Local.Directory, "danger.ops"), 8<<20); e == nil {
		t.Fatal("live journal export path accepted")
	}
	must(t, os.Chmod(output, 0644))
	if _, e = management.InspectSnapshotFile(ctx, output, trust, 8<<20); e == nil {
		t.Fatal("public snapshot accepted")
	}
}
func TestManagementServiceSnapshotFailedPrefixNeverPublished(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, e := Open(ctx, f.p, true)
	must(t, e)
	defer s.Close()
	exports := filepath.Join(f.root, "exports")
	must(t, os.Mkdir(exports, 0700))
	output := filepath.Join(exports, "checkpoint.ops")
	if _, e = s.Snapshot(ctx, output, 1); !errors.Is(e, management.ErrCapacity) {
		t.Fatal(e)
	}
	if _, e = os.Stat(output); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("incomplete output visible")
	}
	entries, e := os.ReadDir(exports)
	must(t, e)
	if len(entries) != 1 {
		t.Fatal("failure evidence missing", entries)
	}
	receipt, e := s.Snapshot(ctx, output, 8<<20)
	must(t, e)
	if receipt.Checkpoint == "" {
		t.Fatal("retry failed")
	}
}

func TestManagementServiceSnapshotCrashChild(t *testing.T) {
	path := os.Getenv("OUTPOST_MANAGEMENT_SNAPSHOT_KILL")
	if path == "" {
		t.Skip("child only")
	}
	p, e := Load(path)
	must(t, e)
	s, e := Open(context.Background(), p, false)
	must(t, e)
	defer s.Close()
	point := os.Getenv("OUTPOST_MANAGEMENT_SNAPSHOT_POINT")
	s.SnapshotFault = func(name string) error {
		if name == point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	_, e = s.Snapshot(context.Background(), os.Getenv("OUTPOST_MANAGEMENT_SNAPSHOT_OUTPUT"), 8<<20)
	must(t, e)
}
func TestManagementServiceSnapshotSIGKILLNeverPublishesPrefixOrReplacesComplete(t *testing.T) {
	for _, point := range []string{"management-snapshot-file-durable", "management-snapshot-name-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			s, e := Open(ctx, f.p, true)
			must(t, e)
			exports := filepath.Join(f.root, "exports")
			must(t, os.Mkdir(exports, 0700))
			baseline := filepath.Join(exports, "baseline.ops")
			receipt, e := s.Snapshot(ctx, baseline, 8<<20)
			must(t, e)
			trust := management.SnapshotTrust{Format: management.SnapshotTrustFormat, Owner: f.p.Local.Owner, Signer: s.signer.Public().(ed25519.PublicKey), Checkpoint: receipt.Checkpoint}
			must(t, s.Close())
			profile := filepath.Join(f.root, "profile.json")
			raw, e := json.Marshal(f.p)
			must(t, e)
			must(t, os.WriteFile(profile, raw, 0600))
			output := filepath.Join(exports, "crash.ops")
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestManagementServiceSnapshotCrashChild$")
			child.Env = append(os.Environ(), "OUTPOST_MANAGEMENT_SNAPSHOT_KILL="+profile, "OUTPOST_MANAGEMENT_SNAPSHOT_POINT="+point, "OUTPOST_MANAGEMENT_SNAPSHOT_OUTPUT="+output)
			var log bytes.Buffer
			child.Stdout = &log
			child.Stderr = &log
			e = child.Run()
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatal("child not killed", e, log.String())
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("unexpected child exit", e, log.String())
			}
			recovered, e := Open(ctx, f.p, false)
			must(t, e)
			defer recovered.Close()
			if point == "management-snapshot-file-durable" {
				if _, e = os.Stat(output); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("prefix published")
				}
				retry, e := recovered.Snapshot(ctx, output, 8<<20)
				must(t, e)
				if retry.Checkpoint != receipt.Checkpoint {
					t.Fatal("retry refreshed source", retry)
				}
			} else if _, e = recovered.Snapshot(ctx, output, 8<<20); !errors.Is(e, management.ErrConflict) {
				t.Fatal("published export replaced", e)
			}
			historical, e := management.InspectSnapshotFile(ctx, output, trust, 8<<20)
			must(t, e)
			if historical.SnapshotReceipt != receipt {
				t.Fatal(historical)
			}
		})
	}
}
