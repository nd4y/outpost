package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestCLIExternalRestoreReadsOnlySelectedCloudDependencies(t *testing.T) {
	for _, protocol := range []string{"s3", "webdav"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			root := teststore.Root(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			write := func(name string, value any) string {
				t.Helper()
				raw, err := json.Marshal(value)
				must(err)
				path := filepath.Join(root, name)
				must(os.WriteFile(path, raw, 0600))
				return path
			}
			owner, err := filekit.NewOwner()
			must(err)
			writer, signing, err := ed25519.GenerateKey(rand.Reader)
			must(err)
			maintenance, _, err := ed25519.GenerateKey(rand.Reader)
			must(err)
			trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("external-recovery-repository")), Epoch: 1, Writer: writer, Maintenance: maintenance}
			namespace := storage.Hash([]byte(trust.Domain + "/" + trust.Repository))
			var invalidWrite atomic.Bool
			var raceArmed atomic.Bool
			stageReady := make(chan struct{})
			resume := make(chan struct{})
			server := teststore.New(t, teststore.Options{Kind: protocol, Namespace: namespace, Logins: map[string]teststore.Login{
				"fixture-writer": {Secret: "synthetic-write-secret"},
				"fixture-reader": {Secret: "synthetic-read-secret"},
			}, Before: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
				if actor == "fixture-reader" && r.Method != http.MethodGet {
					invalidWrite.Store(true)
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				if actor == "fixture-reader" && raceArmed.Load() {
					staging, _ := filepath.Glob(filepath.Join(root, ".outpost-restore-*"))
					if len(staging) != 0 && raceArmed.CompareAndSwap(true, false) {
						close(stageReady)
						select {
						case <-resume:
						case <-r.Context().Done():
							return true
						}
					}
				}
				return false
			}})
			profile := storage.Profile{Kind: protocol, Endpoint: server.Endpoint(), Namespace: namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 1, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
			if protocol == "s3" {
				profile.Region = server.Options.Region
			}
			backend, err := storage.New(profile, storage.Credentials{Access: "fixture-writer", Secret: "synthetic-write-secret", ExpiresUnix: time.Now().Add(time.Minute).Unix()}, server.Roots)
			must(err)
			defer backend.Close()
			sourceDir, replicaDir := filepath.Join(root, "source"), filepath.Join(root, "replica")
			source, err := filekit.OpenStore(sourceDir, owner, true)
			must(err)
			must(os.Mkdir(replicaDir, 0700))
			replica, err := generation.Open(replicaDir, trust, true)
			must(err)
			defer source.Close()
			defer replica.Close()
			primary := filepath.Join(root, "original")
			unrelatedPath := filepath.Join(root, "unrelated")
			must(os.WriteFile(unrelatedPath, []byte("unrelated synthetic data"), 0600))
			unrelated, err := source.Backup(ctx, unrelatedPath, filekit.BackupOptions{Names: []string{"other/file"}})
			must(err)
			var previous, unrelatedRoot, requiredRoot string
			var checkpoints, versions []string
			var payloads [][]byte
			for seq := range 2 {
				data := make([]byte, 104<<10)
				_, err := rand.Read(data)
				must(err)
				must(os.WriteFile(primary, data, 0640))
				version, err := source.Backup(ctx, primary, filekit.BackupOptions{Names: []string{"private/данные", "outside-alias"}})
				must(err)
				checkpoint, err := generation.Seal(ctx, source, []string{version.Version, unrelated.Version}, replica, generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: uint64(seq + 1), Parent: previous, SnapshotUnix: int64(seq + 1), Policy: 1}, signing)
				must(err)
				raw, err := replica.Catalog(ctx, checkpoint)
				must(err)
				catalog, err := generation.VerifyCatalog(raw, trust)
				must(err)
				for _, kit := range catalog.Kits {
					if kit.Version == unrelated.Version {
						unrelatedRoot = kit.Root.ID
					} else if kit.Version == version.Version {
						requiredRoot = kit.Root.ID
					}
				}
				refs, err := generation.Dependencies(raw, trust)
				must(err)
				for _, ref := range refs {
					object, err := replica.ReadObject(ctx, checkpoint, ref)
					must(err)
					must(backend.PutBlob(ctx, ref, object))
				}
				must(backend.Publish(ctx, raw, trust))
				previous = checkpoint
				checkpoints, versions, payloads = append(checkpoints, checkpoint), append(versions, version.Version), append(payloads, data)
			}
			must(replica.Close())
			must(source.Close())
			must(os.Rename(sourceDir, sourceDir+"-unavailable"))
			must(os.Rename(replicaDir, replicaDir+"-unavailable"))
			must(os.Rename(primary, primary+"-unavailable"))
			must(os.Rename(unrelatedPath, unrelatedPath+"-unavailable"))
			owner.SigningKey = nil
			ownerFile := filepath.Join(root, "recovery-owner.json")
			must(filekit.WriteOwner(ownerFile, owner))
			trustFile := write("trust.json", trust)
			credentials := write("credential.json", map[string]any{"access": "fixture-reader", "secret": "synthetic-read-secret", "expiresUnix": time.Now().Add(time.Minute).Unix()})
			ca := filepath.Join(root, "ca.pem")
			must(os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.HTTP.Certificate().Raw}), 0600))
			reader := externalRecoveryProfile{Format: externalRecoveryFormat, Target: profile.ID(), Profile: profile, CredentialFile: credentials, CAFile: ca}
			readerFile := write("reader.json", reader)
			current := os.Getenv("OUTPOST_EXTERNAL_RECOVERY_CLI")
			invoke := func(id, dest string, extra ...string) (generation.RecoveryReceipt, int) {
				t.Helper()
				args := []string{"restore-external", "--bootstrap", readerFile, "--key", ownerFile, "--trust", trustFile, "--generation", id, "--output", dest}
				args = append(args, extra...)
				if current == "" {
					value, err := run(ctx, args)
					if err != nil {
						_, code := failure(err)
						return generation.RecoveryReceipt{}, code
					}
					return value.(generation.RecoveryReceipt), 0
				}
				cmd := exec.CommandContext(ctx, current, args...)
				raw, err := cmd.Output()
				if err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || len(raw) != 0 {
						t.Fatal("external recovery did not return a stable CLI failure", err)
					}
					var failure struct {
						Format string
						Error  struct {
							Code     string
							ExitCode int
						}
					}
					must(json.Unmarshal(exit.Stderr, &failure))
					if failure.Format != "outpost-cli-1" || failure.Error.Code == "" || failure.Error.ExitCode != exit.ExitCode() ||
						bytes.Contains(exit.Stderr, []byte("synthetic-read-secret")) || bytes.Contains(exit.Stderr, []byte(server.Endpoint())) {
						t.Fatal("unexpected failure envelope or disclosed recovery details")
					}
					return generation.RecoveryReceipt{}, exit.ExitCode()
				}
				var out struct {
					Format string
					Result generation.RecoveryReceipt
				}
				must(json.Unmarshal(raw, &out))
				if out.Format != "outpost-cli-1" || bytes.Contains(raw, []byte("private/")) || bytes.Contains(raw, []byte("synthetic-read-secret")) {
					t.Fatal("unexpected receipt or disclosed recovery details")
				}
				return out.Result, 0
			}
			verify := func(dir string, index int) {
				t.Helper()
				path := filepath.Join(dir, "private/данные")
				data, err := os.ReadFile(path)
				must(err)
				a, err := os.Stat(path)
				must(err)
				b, err := os.Stat(filepath.Join(dir, "outside-alias"))
				must(err)
				if !bytes.Equal(data, payloads[index]) || a.Mode().Perm() != 0640 || !os.SameFile(a, b) {
					t.Fatal("external recovery changed bytes, mode or hardlink")
				}
			}
			full := filepath.Join(root, "full")
			result, code := invoke(checkpoints[1], full)
			if code != 0 || !result.CheckpointMatch || result.Restored.Files != 2 || result.Generation != checkpoints[1] {
				t.Fatal("complete external recovery failed", code, result)
			}
			verify(full, 1)
			before := server.Snapshot().Requests
			if _, code = invoke(checkpoints[1], full); code != 5 || server.Snapshot().Requests != before {
				t.Fatal("existing destination was used", code)
			}
			verify(full, 1)
			raceDest := filepath.Join(root, "concurrent-output")
			raceArmed.Store(true)
			completed := make(chan int, 1)
			go func() {
				defer close(completed)
				_, code := invoke(checkpoints[1], raceDest, "--version", versions[1])
				completed <- code
			}()
			select {
			case <-stageReady:
			case <-ctx.Done():
				t.Fatal("restore did not reach its staged payload read")
			}
			must(os.Mkdir(raceDest, 0700))
			sentinel := filepath.Join(raceDest, "concurrent-owner")
			must(os.WriteFile(sentinel, []byte("retain"), 0600))
			close(resume)
			if code := <-completed; code != 5 {
				t.Fatal("concurrent output did not prevent publication", code)
			}
			got, err := os.ReadFile(sentinel)
			must(err)
			entries, err := os.ReadDir(raceDest)
			must(err)
			staging, err := filepath.Glob(filepath.Join(root, ".outpost-restore-*"))
			must(err)
			if string(got) != "retain" || len(entries) != 1 || len(staging) != 0 {
				t.Fatal("concurrent owner output or staging lifecycle changed")
			}
			selection := write("directory-selection.json", generation.RecoverySelection{Directory: "private"})
			directory := filepath.Join(root, "directory")
			result, code = invoke(checkpoints[1], directory, "--input", selection)
			if code != 0 || result.Restored.Files != 1 || result.Restored.Aliases != 0 {
				t.Fatal("directory recovery failed", code, result)
			}
			selected, err := os.ReadFile(filepath.Join(directory, "private/данные"))
			must(err)
			if !bytes.Equal(selected, payloads[1]) {
				t.Fatal("directory selection returned another version")
			}
			if _, err = os.Stat(filepath.Join(directory, "outside-alias")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("directory selection escaped into another alias", err)
			}
			must(os.Remove(server.Path("blob-" + unrelatedRoot)))
			for i, id := range checkpoints {
				dest := filepath.Join(root, "selected-"+id)
				result, code = invoke(id, dest, "--version", versions[i])
				if code != 0 || !result.CheckpointMatch || result.Restored.Files != 1 || result.Generation != id {
					t.Fatal("selected recovery needed unrelated object", code, result)
				}
				verify(dest, i)
			}
			failed := filepath.Join(root, "unpublished")
			if _, code = invoke(storage.Hash([]byte("unknown checkpoint")), failed); code != 4 {
				t.Fatal("unknown checkpoint did not fail closed", code)
			}
			raw, err := os.ReadFile(server.Path("blob-" + requiredRoot))
			must(err)
			var descriptor storage.Blob
			must(json.Unmarshal(raw, &descriptor))
			if len(descriptor.Parts) == 0 {
				t.Fatal("missing fixture descriptor parts")
			}
			part := server.Path("part-" + descriptor.Parts[0].ID)
			original, err := os.ReadFile(part)
			must(err)
			changed := bytes.Clone(original)
			changed[0] ^= 1
			must(os.WriteFile(part, changed, 0600))
			if _, code = invoke(checkpoints[1], failed, "--version", versions[1]); code != 4 {
				t.Fatal("corrupt required part did not fail closed", code)
			}
			must(os.WriteFile(part, original, 0600))
			must(os.Remove(server.Path("blob-" + requiredRoot)))
			if _, code = invoke(checkpoints[1], failed, "--version", versions[1]); code != 4 {
				t.Fatal("missing required object did not fail closed", code)
			}
			if _, err = os.Lstat(failed); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("incomplete output was published", err)
			}
			write("credential.json", map[string]any{"access": "fixture-reader", "secret": "synthetic-wrong-secret", "expiresUnix": time.Now().Add(time.Minute).Unix()})
			if _, code = invoke(checkpoints[0], failed, "--version", versions[0]); code != 3 {
				t.Fatal("wrong credentials did not fail closed", code)
			}
			reader.Profile.Namespace = storage.Hash([]byte("wrong-external-domain"))
			reader.Target = reader.Profile.ID()
			write("reader.json", reader)
			before = server.Snapshot().Requests
			if _, code = invoke(checkpoints[1], failed); code != 3 || server.Snapshot().Requests != before {
				t.Fatal("foreign namespace reached storage", code)
			}
			if invalidWrite.Load() {
				t.Fatal("read-only recovery attempted a remote write")
			}
			if current != "" {
				t.Log("EXTERNAL_RESTORE_CLI_PASS: native read-only CLI restored whole and selected old/new versions without the source or a temporary replica")
			}
		})
	}
}
