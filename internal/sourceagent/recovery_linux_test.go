package sourceagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

func ownerExportProfile(t *testing.T, f *fixture) RecoveryExportProfile {
	t.Helper()
	ctx := context.Background()
	root := filepath.Join(f.base, "owner-volume")
	must(t, os.Mkdir(root, 0700))
	observed, e := volume.Probe(ctx, root)
	must(t, e)
	binding, e := volume.Enroll(ctx, root, observed, f.b.Local.Node, 1)
	must(t, e)
	dir := filepath.Join(root, "private-recovery")
	must(t, os.Mkdir(dir, 0700))
	return RecoveryExportProfile{Format: RecoveryExportFormat, Volume: binding, Directory: dir, ToolsDirectory: os.Getenv("OUTPOST_RECOVERY_DISTRIBUTION"), ToolManifestSHA256: os.Getenv("OUTPOST_RECOVERY_MANIFEST_SHA256")}
}

func TestSourceRecoveryExportRejectsSourceAndRuntimeDestinations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := ownerExportProfile(t, f)
	wrong := p
	wrong.Volume.Scope = storage.Hash([]byte("another-owner"))
	if _, e := f.a.ExportRecovery(ctx, wrong, "development", filepath.Join(p.Directory, "bad.tar")); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	wrong = p
	wrong.Volume = f.b.Local.Volume
	wrong.Directory = f.b.Local.Directory
	if _, e := f.a.ExportRecovery(ctx, wrong, "development", filepath.Join(wrong.Directory, "bad.tar")); !errors.Is(e, recoverybundle.ErrDenied) {
		t.Fatal("runtime overlap", e)
	}
	wrong = p
	wrong.Directory = f.tree
	if _, e := f.a.ExportRecovery(ctx, wrong, "development", filepath.Join(wrong.Directory, "bad.tar")); !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("escaped owner volume", e)
	}
	if _, e := f.a.ExportRecovery(ctx, p, "development", filepath.Join(f.base, "bad.tar")); !errors.Is(e, ErrInvalid) {
		t.Fatal("output escaped private profile", e)
	}
	items, e := os.ReadDir(p.Directory)
	must(t, e)
	if len(items) != 0 {
		t.Fatal("created secrets on denied export")
	}
}

func TestSourceRecoveryExportPreservesHistoricalCheckpointAndReleasesLease(t *testing.T) {
	if os.Getenv("OUTPOST_RECOVERY_DISTRIBUTION") == "" {
		t.Skip("selected built distribution required")
	}
	f := newFixture(t)
	ctx := context.Background()
	p := ownerExportProfile(t, f)
	raw, e := os.ReadFile(filepath.Join(p.ToolsDirectory, "manifest.json"))
	must(t, e)
	var tools struct {
		Revision string `json:"revision"`
	}
	must(t, json.Unmarshal(raw, &tools))
	initial, e := f.a.ExportRecovery(ctx, p, tools.Revision, filepath.Join(p.Directory, "before-capture.tar"))
	must(t, e)
	if initial.CheckpointPresent || initial.VerifiedUnix != 0 {
		t.Fatal("invented initial checkpoint")
	}
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	checkpoint, e := f.a.Checkpoint(ctx)
	must(t, e)
	completed, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
	must(t, e)
	must(t, f.a.Next(ctx)) // pending next capture must not replace completed evidence
	leaseChecked := false
	f.a.Fault = func(point string) error {
		if point == "recovery-export-created" {
			bounded, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			_, e := f.a.Status(bounded)
			if e != nil {
				return e
			}
			leaseChecked = true
		}
		return nil
	}
	path := filepath.Join(p.Directory, "with-checkpoint.tar")
	receipt, e := f.a.ExportRecovery(ctx, p, tools.Revision, path)
	must(t, e)
	f.a.Fault = nil
	if !leaseChecked || !receipt.CheckpointPresent || receipt.Generation != completed.Generation || receipt.Sequence != completed.Sequence || receipt.VerifiedUnix != completed.Receipt.VerifiedAt {
		t.Fatal("checkpoint age or execution lease changed")
	}
	input, e := recoverybundle.Open(path)
	must(t, e)
	defer input.Close()
	dest := filepath.Join(p.Directory, "restored-material")
	_, e = recoverybundle.Extract(ctx, input, receipt.SHA256, dest)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(dest, "checkpoint.json"))
	must(t, e)
	if !bytes.Equal(got, checkpoint) {
		t.Fatal("rewrote checkpoint")
	}
	owner, e := filekit.ReadOwner(filepath.Join(dest, "recovery-owner.json"))
	must(t, e)
	if len(owner.SigningKey) != 0 || !bytes.Equal(owner.Master, f.owner.Master) {
		t.Fatal("wrong recovery material")
	}
	if _, e = f.a.ExportRecovery(ctx, p, "0000000000000000000000000000000000000000", filepath.Join(p.Directory, "wrong-version.tar")); !errors.Is(e, recoverybundle.ErrInvalid) {
		t.Fatal("accepted unselected tool revision", e)
	}
	// A destination mount loss during copying cannot publish the new name.
	f.a.Fault = func(point string) error {
		if point == "recovery-export-file-durable" {
			return os.Rename(p.Volume.Root, p.Volume.Root+"-lost")
		}
		return nil
	}
	_, e = f.a.ExportRecovery(ctx, p, tools.Revision, filepath.Join(p.Directory, "lost-volume.tar"))
	if !errors.Is(e, volume.ErrUnavailable) {
		t.Fatal("destination loss was not rejected", e)
	}
	if _, e = os.Stat(filepath.Join(p.Volume.Root+"-lost", "private-recovery/lost-volume.tar")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("published after owner volume loss", e)
	}
	f.a.Fault = nil
}
