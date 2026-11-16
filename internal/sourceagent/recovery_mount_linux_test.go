package sourceagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/volume"
)

func TestSourceRecoveryExportAcrossMountNamespaceIDChange(t *testing.T) {
	if os.Getenv("OUTPOST_RECOVERY_DISTRIBUTION") == "" {
		t.Skip("independently selected built distribution required")
	}
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	observed, err := volume.Probe(ctx, f.tree)
	must(t, err)
	must(t, f.a.Close())
	f.a = nil
	// Namespace-local mount IDs are not durable source-root identities. Keep
	// every stable enrollment field while modelling a prior namespace's ID.
	f.b.Tree.Observed.MountID = observed.MountID + 1
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "mount-reopen-agent")
	f.a, err = Open(ctx, f.b, true)
	must(t, err)
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	f.reopen(t)
	checkpoint, err := f.a.Checkpoint(ctx)
	must(t, err)
	p := ownerExportProfile(t, f)
	raw, err := os.ReadFile(filepath.Join(p.ToolsDirectory, "manifest.json"))
	must(t, err)
	var tools struct {
		Revision string `json:"revision"`
	}
	must(t, json.Unmarshal(raw, &tools))
	t.Logf("MOUNT_EXPORT_CONTROL storedMountID=%d currentMountID=%d sameFilesystem=true sameFSID=true sameRootInode=true sameReadOnly=true", f.b.Tree.Observed.MountID, observed.MountID)
	pack := filepath.Join(p.Directory, "same-root-after-reopen.tar")
	receipt, err := f.a.ExportRecovery(ctx, p, tools.Revision, pack)
	must(t, err)
	input, err := recoverybundle.Open(pack)
	must(t, err)
	inspected, err := recoverybundle.Inspect(ctx, input, receipt.SHA256)
	input.Close()
	must(t, err)
	if !receipt.CheckpointPresent || !inspected.CheckpointPresent || receipt.VerifiedUnix == 0 {
		t.Fatal("same-root recovery export lost completed checkpoint")
	}
	retained, err := f.a.Checkpoint(ctx)
	must(t, err)
	if !bytes.Equal(retained, checkpoint) {
		t.Fatal("recovery export changed source checkpoint")
	}
	assertOnlyPublished := func() {
		t.Helper()
		entries, err := os.ReadDir(p.Directory)
		must(t, err)
		if len(entries) != 1 || entries[0].Name() != filepath.Base(pack) {
			t.Fatal("refused export left a new private artifact", entries)
		}
	}
	baseline := f.a.b.Tree.Observed
	for _, name := range []string{"filesystem", "fsid", "root-inode", "read-only"} {
		t.Run(name, func(t *testing.T) {
			bad := baseline
			switch name {
			case "filesystem":
				bad.Filesystem++
			case "fsid":
				bad.FSID[0]++
			case "root-inode":
				bad.RootInode++
			case "read-only":
				bad.ReadOnly = !bad.ReadOnly
			}
			f.a.b.Tree.Observed = bad
			defer func() { f.a.b.Tree.Observed = baseline }()
			_, err := f.a.ExportRecovery(ctx, p, tools.Revision, filepath.Join(p.Directory, name+".tar"))
			if !errors.Is(err, recoverybundle.ErrDenied) {
				t.Fatal("changed stable source identity admitted", name, err)
			}
			assertOnlyPublished()
		})
	}
	// A fresh per-export observation must still fence replacement during the
	// export, even though a historical namespace ID is allowed on enrollment.
	held := f.tree + "-held-during-export"
	moved := false
	f.a.Fault = func(point string) error {
		if point == "recovery-export-created" && !moved {
			if err := os.Rename(f.tree, held); err != nil {
				return err
			}
			moved = true
			return os.Mkdir(f.tree, 0700)
		}
		return nil
	}
	defer func() {
		f.a.Fault = nil
		if moved {
			must(t, os.Remove(f.tree)) // Only the empty replacement made above.
			must(t, os.Rename(held, f.tree))
		}
	}()
	_, err = f.a.ExportRecovery(ctx, p, tools.Revision, filepath.Join(p.Directory, "replaced-during-export.tar"))
	if !moved || !errors.Is(err, recoverybundle.ErrDenied) {
		t.Fatal("mid-export source replacement was not refused", moved, err)
	}
	if _, err := os.Lstat(filepath.Join(p.Directory, "replaced-during-export.tar")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed source published a recovery package", err)
	}
	entries, err := os.ReadDir(p.Directory)
	must(t, err)
	var retainedCandidates int
	for _, entry := range entries {
		if entry.Name() == filepath.Base(pack) {
			continue
		}
		info, err := entry.Info()
		must(t, err)
		if !strings.HasPrefix(entry.Name(), ".partial-recovery-") || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() == 0 {
			t.Fatal("refused in-progress export did not retain only a private candidate", entry.Name())
		}
		retainedCandidates++
	}
	if retainedCandidates != 1 {
		t.Fatal("lost the bounded failed-export candidate", retainedCandidates)
	}
	input, err = recoverybundle.Open(pack)
	must(t, err)
	_, err = recoverybundle.Inspect(ctx, input, receipt.SHA256)
	input.Close()
	must(t, err)
	t.Log("MOUNT_EXPORT_PASS historicalNamespaceIDAccepted=true stableIdentityRefusals=4 midExportReplacementRefused=true privateCandidateRetained=true checkpointUnchanged=true")
}
