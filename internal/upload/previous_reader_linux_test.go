package upload

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

// This opt-in check requires an independently acquired, checksum-pinned older
// executable. The ordinary suite never downloads or substitutes a reader.
func TestPreviousKitRestoresBothBatchUploadedGenerations(t *testing.T) {
	binary := os.Getenv("OUTPOST_TEST_PREVIOUS_KIT")
	if binary == "" {
		t.Skip("requires separately admitted previous packaged reader")
	}
	expected := os.Getenv("OUTPOST_TEST_PREVIOUS_KIT_SHA256")
	revision := os.Getenv("OUTPOST_TEST_PREVIOUS_REVISION")
	data, err := os.ReadFile(binary)
	must(t, err)
	_, revisionError := hex.DecodeString(revision)
	if !filepath.IsAbs(binary) || !storage.ID(expected) || storage.Hash(data) != expected || len(revision) != 40 || revisionError != nil {
		t.Fatal("previous executable identity is not pinned")
	}
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := fixtureBytes(t, 128<<10)
			f.childTimeout = 60 * time.Second
			target := f.server(t, kind, 0, nil)
			consumer := teststore.Root(t)
			owner, err := f.owner.RecoveryMaterial()
			must(t, err)
			ownerPath := filepath.Join(consumer, "recovery-owner.json")
			must(t, filekit.WriteOwner(ownerPath, owner))
			type version struct {
				kit, version string
				want         []byte
			}
			versions := []version{}
			for i := 0; i < 2; i++ {
				if i != 0 {
					f.data[4096] ^= 0x7f
					must(t, os.WriteFile(f.input, f.data, 0640))
					f.id, f.version = f.capture(t, 2, f.id)
				}
				raw := f.plan(t, target, 1, 5000)
				worker := f.prepare(t, target, raw, 0)
				worker.start(t)
				worker.wait(t, true)
				copyDir := filepath.Join(consumer, "recovered-"+f.id)
				must(t, os.Mkdir(copyDir, 0700))
				replica, err := generation.Open(copyDir, f.authority.Generation, true)
				must(t, err)
				backend := f.backend(t, target, 0)
				must(t, backend.Recover(t.Context(), f.id, replica))
				backend.Close()
				kit := filepath.Join(consumer, "kit-"+f.id)
				must(t, replica.ExportKit(t.Context(), f.id, f.version, kit))
				must(t, replica.Close())
				must(t, os.RemoveAll(copyDir))
				versions = append(versions, version{kit, f.version, bytes.Clone(f.data)})
			}
			for _, replica := range f.replicas {
				must(t, replica.Close())
			}
			must(t, f.store.Close())
			// Remove plaintext, all source replicas/runtime and operational child
			// configurations before either independent previous-reader process.
			must(t, os.RemoveAll(f.base))
			for _, v := range versions {
				out := filepath.Join(consumer, "restored-"+v.version)
				ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
				result, err := exec.CommandContext(ctx, binary, "restore", "--owner", ownerPath, "--store", v.kit, "--version", v.version, "--dest", out).CombinedOutput()
				stop()
				if err != nil {
					t.Fatalf("previous reader: %v %s", err, result)
				}
				var report struct {
					Revision string `json:"revision"`
				}
				must(t, json.Unmarshal(result, &report))
				if report.Revision != revision {
					t.Fatal("executed reader revision differs")
				}
				first := filepath.Join(out, "do-not-export-private-name.bin")
				got, err := os.ReadFile(first)
				must(t, err)
				if !bytes.Equal(got, v.want) {
					t.Fatal("previous reader restored different bytes")
				}
				stat, err := os.Stat(first)
				must(t, err)
				alias, err := os.Stat(filepath.Join(out, "alias.bin"))
				must(t, err)
				if stat.Mode().Perm() != 0640 || !os.SameFile(stat, alias) {
					t.Fatal("previous reader lost mode or hardlink")
				}
			}
			t.Logf("previous packaged revision %s restored both versions after source/runtime removal", revision)
		})
	}
}
