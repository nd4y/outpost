package sourceagent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/volume"
)

func TestSourceJournalCopyReconcilesExactPredecessorAndLostActiveFile(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Second)
	defer cancel()
	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(f.b.Local.Volume.Root, "agent-journal-copy")
	copyRoot := filepath.Join(f.base, "journal-volume")
	must(t, os.Mkdir(copyRoot, 0700))
	observed, err := volume.Probe(ctx, copyRoot)
	must(t, err)
	binding, err := volume.Enroll(ctx, copyRoot, observed, f.b.Local.Node, 1)
	must(t, err)
	copyDir := filepath.Join(copyRoot, "journal")
	must(t, os.Mkdir(copyDir, 0700))
	f.b.JournalCopy = &JournalCopy{Volume: binding, Directory: copyDir}
	interrupted := errors.New("injected interruption after copy fsync")
	fault := func(point string) error {
		if point == "source-journal-copy-durable" {
			return interrupted
		}
		return nil
	}
	if agent, err := initializeAgent(ctx, f.b, fault); !errors.Is(err, interrupted) {
		if agent != nil {
			agent.Close()
		}
		t.Fatal("initial publication did not stop at the copy boundary", err)
	}
	if _, err = os.Stat(f.b.Local.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("interrupted source installation published a runtime", err)
	}
	f.a, err = Open(ctx, f.b, true)
	must(t, err)
	primary := filepath.Join(f.b.Local.Directory, "state", sourceStateFile)
	mirror := filepath.Join(copyDir, "state", sourceJournalFile)
	idle, err := os.ReadFile(primary)
	must(t, err)
	idleMirror, err := os.ReadFile(mirror)
	must(t, err)
	intent := f.intent(t, 1, "")
	f.a.Fault = fault
	if err = f.a.Prepare(ctx, intent); !errors.Is(err, interrupted) {
		t.Fatal("capture did not stop between journal writes", err)
	}
	stillIdle, err := os.ReadFile(primary)
	must(t, err)
	if !bytes.Equal(stillIdle, idle) {
		t.Fatal("the interrupted operation wrote the primary journal")
	}
	f.reopen(t)
	pending, err := f.a.Status(ctx)
	must(t, err)
	if pending.Phase != "PREPARING" || pending.Operation == "" {
		t.Fatal("exact immediate predecessor did not roll forward", pending)
	}
	must(t, f.a.Prepare(ctx, intent))
	f.a.Fault = func(point string) error {
		if point == "source-journal-anchor-durable" {
			return interrupted
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, interrupted) {
		t.Fatal("execution did not stop between the ACTIVE anchor and the primary journal", err)
	}
	f.reopen(t)
	active, err := f.a.Status(ctx)
	must(t, err)
	if active.Phase != "ACTIVE" || active.Operation != pending.Operation {
		t.Fatal("prepared operation changed", pending, active)
	}
	must(t, f.a.Close())
	f.a = nil
	must(t, os.Rename(primary, primary+".fixture-missing"))
	sentinel := filepath.Join(copyRoot, volume.Sentinel)
	must(t, os.Rename(sentinel, sentinel+".fixture-missing"))
	assertBlocked := func(want error) {
		t.Helper()
		agent, err := Open(ctx, f.b, false)
		if agent != nil {
			agent.Close()
		}
		if !errors.Is(err, want) {
			t.Fatal("unexpected recovery classification", err, want)
		}
	}
	assertBlocked(volume.ErrUnavailable)
	if _, err = os.Stat(primary); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an unadmitted volume caused a primary write", err)
	}
	must(t, os.Rename(sentinel+".fixture-missing", sentinel))
	currentMirror, err := os.ReadFile(mirror)
	must(t, err)
	must(t, os.WriteFile(mirror, idleMirror, 0600))
	assertBlocked(ErrInvalid)
	if _, err = os.Stat(primary); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a stale signed mirror caused a primary write", err)
	}
	must(t, os.WriteFile(mirror, currentMirror, 0600))
	operationDir := filepath.Join(f.b.Local.Directory, "operations", active.Operation)
	must(t, os.Rename(operationDir, operationDir+".fixture-missing"))
	assertBlocked(os.ErrNotExist)
	if _, err = os.Stat(primary); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing capture records caused a primary write", err)
	}
	must(t, os.Rename(operationDir+".fixture-missing", operationDir))
	f.a, err = Open(ctx, f.b, false)
	must(t, err)
	recovered, err := f.a.Status(ctx)
	must(t, err)
	if recovered.Phase != active.Phase || recovered.Operation != active.Operation || recovered.Sequence != active.Sequence {
		t.Fatal("missing file recovered a different operation", recovered, active)
	}
	must(t, f.a.Run(ctx))
	checkpoint, err := f.a.Checkpoint(ctx)
	must(t, err)
	complete, err := f.a.Status(ctx)
	must(t, err)
	if complete.Phase != "COMPLETE" || complete.Sequence != 1 || complete.Operation != active.Operation {
		t.Fatal("recovered operation did not complete", complete)
	}
	must(t, f.a.Close())
	f.a = nil
	latest, err := os.ReadFile(primary)
	must(t, err)
	must(t, os.WriteFile(primary, idle, 0600))
	assertBlocked(ErrInvalid)
	divergent, err := os.ReadFile(primary)
	must(t, err)
	if !bytes.Equal(divergent, idle) {
		t.Fatal("a signed divergent record was overwritten")
	}
	must(t, os.WriteFile(primary, latest, 0600))
	must(t, os.Rename(mirror, mirror+".fixture-missing"))
	assertBlocked(os.ErrNotExist)
	must(t, os.Rename(mirror+".fixture-missing", mirror))
	must(t, os.Rename(primary, primary+".fixture-complete"))
	anchor := filepath.Join(f.b.Local.Directory, "state", sourceJournalAnchor)
	must(t, os.Rename(anchor, anchor+".fixture-missing"))
	assertBlocked(os.ErrNotExist)
	must(t, os.Rename(anchor+".fixture-missing", anchor))
	f.a, err = Open(ctx, f.b, false)
	must(t, err)
	reopened, err := f.a.Checkpoint(ctx)
	must(t, err)
	if !bytes.Equal(reopened, checkpoint) {
		t.Fatal("recovery changed the signed checkpoint or its verification time")
	}
	restored := filepath.Join(f.base, "journal-restored")
	_, err = generation.RecoverMaterialized(ctx, f.replicaPath, complete.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, restored)
	must(t, err)
	want, err := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, err)
	got, err := os.ReadFile(filepath.Join(restored, "private.bin"))
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatal("recovered generation bytes differ")
	}
}
