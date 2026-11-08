package sourceagent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestPreparedSourceSIGKILLKeepsFrozenExportAndReleasedProvider(t *testing.T) {
	for _, point := range []string{"source-prepared-view-frozen", "source-agent-intent-durable", "prepared-view-released"} {
		t.Run(point, func(t *testing.T) {
			f, key, m, data := preparedSourceFixture(t)
			ctx := context.Background()
			frozen, e := os.ReadFile(f.b.Prepared.ManifestFile)
			must(t, e)
			must(t, f.a.Close())
			f.a = nil
			input := struct {
				Bootstrap Bootstrap
				Point     string
			}{f.b, point}
			raw, e := json.Marshal(input)
			must(t, e)
			file := filepath.Join(f.base, "prepared-kill-input.json")
			must(t, os.WriteFile(file, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestSourceAgentSIGKILLChild$")
			cmd.Env = append(os.Environ(), "OUTPOST_SOURCE_KILL_INPUT="+file)
			output, e := cmd.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("prepared child not killed: %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong prepared termination: %v %s", e, output)
			}
			// Before durable intent the same manifest can be retried. Once intent
			// exists, an advancing pointer cannot substitute the accepted view.
			if point != "source-prepared-view-frozen" {
				second := bytes.Clone(data)
				second[0] ^= 1
				must(t, os.Mkdir(filepath.Join(f.tree, "export-2"), 0700))
				must(t, os.WriteFile(filepath.Join(f.tree, "export-2/private.bin"), second, 0600))
				m.Root = "export-2"
				m.Sequence++
				m.SnapshotUnix++
				m.CompletedUnix++
				m.Files[0].SHA256 = storage.Hash(second)
				raw, e = capture.SignPreparedExport(m, f.b.Prepared.Trust, key, time.Now())
				must(t, e)
				must(t, os.WriteFile(f.b.Prepared.ManifestFile, raw, 0600))
			}
			if point == "prepared-view-released" {
				must(t, os.Rename(filepath.Join(f.tree, "export-1"), filepath.Join(f.tree, "retained-export-1")))
			}
			f.a, e = Open(ctx, f.b, false)
			must(t, e)
			must(t, f.a.Next(ctx))
			must(t, f.a.Run(ctx))
			complete, e := f.a.Status(ctx)
			must(t, e)
			if complete.Phase != "COMPLETE" || complete.Sequence != 1 || complete.Operation != storage.Hash(frozen) || complete.Prepared == nil || complete.Prepared.ProducerSequence != 10 {
				t.Fatal("crash replaced frozen export or duplicated generation", complete)
			}
			out := filepath.Join(f.base, "prepared-crash-restore")
			_, e = generation.RecoverMaterialized(ctx, f.replicaPath, complete.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
			must(t, e)
			restored, e := os.ReadFile(filepath.Join(out, "private.bin"))
			must(t, e)
			if !bytes.Equal(restored, data) {
				t.Fatal("crash restored pointer replacement")
			}
			t.Log("actual SIGKILL", point, "recovered original prepared export without duplicate source generation")
		})
	}
}
