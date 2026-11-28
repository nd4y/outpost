package recoverybundle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
)

type crashConfig struct {
	Material                                       Material
	ToolsDirectory, ManifestSHA256, Revision       string
	Operation, Point, Input, Output, Anchor, Ready string
}

func TestRecoveryPackageCrashChild(t *testing.T) {
	path := os.Getenv("OUTPOST_RECOVERY_CRASH_CONFIG")
	if path == "" {
		return
	}
	raw, e := os.ReadFile(path)
	must(t, e)
	var c crashConfig
	must(t, json.Unmarshal(raw, &c))
	fault := func(point string) error {
		if point == c.Point {
			must(t, os.WriteFile(c.Ready, []byte("ready"), 0600))
			for {
				time.Sleep(time.Second)
			}
		}
		return nil
	}
	if c.Operation == "export" {
		_, e = Export(context.Background(), c.Material, Options{ToolsDirectory: c.ToolsDirectory, ManifestSHA256: c.ManifestSHA256, Revision: c.Revision, Fault: fault}, c.Output)
	} else {
		f, e := Open(c.Input)
		must(t, e)
		defer f.Close()
		_, e = extract(context.Background(), f, c.Anchor, c.Output, fault)
		must(t, e)
	}
	t.Fatalf("crash boundary not reached: %v", e)
}

func TestRecoveryPackageActualSIGKILLPreservesOnlyCompletePublishedResults(t *testing.T) {
	for _, point := range []string{"recovery-export-created", "recovery-export-file-durable", "recovery-export-published", "recovery-extract-created", "recovery-extract-files-durable", "recovery-extract-published"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			input, r := f.export(t, "input.tar")
			c := crashConfig{Material: f.material, ToolsDirectory: f.options.ToolsDirectory, ManifestSHA256: f.options.ManifestSHA256, Revision: f.options.Revision, Input: input, Anchor: r.SHA256, Ready: filepath.Join(f.base, "ready"), Point: point, Operation: "export", Output: filepath.Join(f.ownerDir, "result.tar")}
			if strings.Contains(point, "-extract-") {
				c.Operation = "extract"
				c.Output = filepath.Join(f.ownerDir, "result-directory")
			}
			config := filepath.Join(f.base, "private-child-config.json")
			must(t, os.WriteFile(config, encoded(t, c), 0600))
			cmd := exec.Command(os.Args[0], "-test.run=^TestRecoveryPackageCrashChild$")
			cmd.Env = append(os.Environ(), "OUTPOST_RECOVERY_CRASH_CONFIG="+config)
			must(t, cmd.Start())
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waited := false
			t.Cleanup(func() {
				if !waited {
					cmd.Process.Kill()
					<-done
				}
			})
			deadline := time.NewTimer(10 * time.Second)
			defer deadline.Stop()
			for {
				if _, e := os.Stat(c.Ready); e == nil {
					break
				}
				select {
				case e := <-done:
					waited = true
					t.Fatal("child stopped before boundary", e)
				case <-deadline.C:
					t.Fatal("child boundary timed out")
				case <-time.After(10 * time.Millisecond):
				}
			}
			must(t, cmd.Process.Kill())
			e := <-done
			waited = true
			if e == nil {
				t.Fatal("child was not killed")
			}
			_, e = os.Stat(c.Output)
			published := strings.HasSuffix(point, "-published")
			if published && e != nil || !published && !errors.Is(e, os.ErrNotExist) {
				t.Fatal("incorrect crash publication", e)
			}
			if c.Operation == "export" {
				if !published {
					_, e = Export(context.Background(), f.material, f.options, c.Output)
					must(t, e)
				}
				raw, e := os.ReadFile(c.Output)
				must(t, e)
				_, e = inspect(t, c.Output, storage.Hash(raw))
				must(t, e)
				// Test-only independent knowledge is the parent fixture. A real
				// lost digest is never made trusted by hashing an unknown file.
			} else {
				if !published {
					in, e := Open(input)
					must(t, e)
					_, e = Extract(context.Background(), in, r.SHA256, c.Output)
					in.Close()
					must(t, e)
				}
				owner, e := filekit.ReadOwner(filepath.Join(c.Output, "recovery-owner.json"))
				must(t, e)
				if len(owner.SigningKey) != 0 || owner.Domain != f.material.Owner.Domain {
					t.Fatal("invalid recovered secret")
				}
				archived, e := os.ReadFile(filepath.Join(c.Output, "tools/outpost-linux-arm64.tar.gz"))
				must(t, e)
				original, e := os.ReadFile(filepath.Join(f.options.ToolsDirectory, "outpost-linux-arm64.tar.gz"))
				must(t, e)
				if storage.Hash(archived) != storage.Hash(original) {
					t.Fatal("incomplete tools published")
				}
			}
			if _, e = inspect(t, input, r.SHA256); e != nil {
				t.Fatal("input package changed", e)
			}
		})
	}
}
