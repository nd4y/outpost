package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestCLIUploadPlanBuildRepairsMissingExternalParts(t *testing.T) {
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
			makeKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
				t.Helper()
				pub, key, err := ed25519.GenerateKey(rand.Reader)
				must(err)
				return pub, key
			}
			owner, err := filekit.NewOwner()
			must(err)
			writer, signing := makeKey()
			maintenance, _ := makeKey()
			planner, plannerKey := makeKey()
			executor, executorKey := makeKey()
			node := upload.Identity(executor)
			trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("plan-repair")), Epoch: 1, Writer: writer, Maintenance: maintenance}
			source, err := filekit.OpenStore(filepath.Join(root, "source"), owner, true)
			must(err)
			defer source.Close()
			data := make([]byte, 112<<10)
			_, err = rand.Read(data)
			must(err)
			input := filepath.Join(root, "input")
			must(os.WriteFile(input, data, 0600))
			version, err := source.Backup(ctx, input, filekit.BackupOptions{Names: []string{"dataset/private.bin"}})
			must(err)
			replicaDir := filepath.Join(root, "replica")
			must(os.Mkdir(replicaDir, 0700))
			replica, err := generation.Open(replicaDir, trust, true)
			must(err)
			defer replica.Close()
			id, err := generation.Seal(ctx, source, []string{version.Version}, replica, generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1}, signing)
			must(err)
			materialized := filepath.Join(root, "materialized")
			must(os.Mkdir(materialized, 0700))
			for _, name := range []string{"catalogs", "objects"} {
				dst := filepath.Join(materialized, name)
				src := filepath.Join(replicaDir, name)
				must(os.Mkdir(dst, 0700))
				entries, err := os.ReadDir(src)
				must(err)
				for _, entry := range entries {
					must(os.Link(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())))
				}
			}
			target := teststore.New(t, teststore.Options{Kind: protocol, Namespace: storage.Hash([]byte(trust.Domain + "/" + trust.Repository))})
			profile := storage.Profile{Kind: protocol, Endpoint: target.Endpoint(), Namespace: target.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
			if protocol == "s3" {
				profile.Region = target.Options.Region
			}
			timing := time.Now()
			template := upload.Plan{Format: upload.Format, Operation: storage.Hash([]byte("original")), Profile: profile, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: node, Class: "trusted", PublicKey: executor}}, StartMillis: timing.Add(-time.Second).UnixMilli(), ExpiresUnix: timing.Add(time.Minute).Unix(), SlotMillis: 5000}
			trustFile := write("trust.json", trust)
			keyFile := write("planner.json", map[string]ed25519.PrivateKey{"privateKey": plannerKey})
			wrongKey := write("writer.json", map[string]ed25519.PrivateKey{"privateKey": signing})
			current := os.Getenv("OUTPOST_EXTERNAL_RECOVERY_CLI")
			invoke := func(request uploadPlanRequest, key, checkpoint, output string) int {
				t.Helper()
				requestFile := write("plan-request.json", request)
				args := []string{"upload-plan-build", "--key", key, "--trust", trustFile, "--store", materialized, "--generation", checkpoint, "--input", requestFile, "--output", output}
				if current == "" {
					if _, err := run(ctx, args); err != nil {
						_, code := failure(err)
						return code
					}
					return 0
				}
				raw, err := exec.CommandContext(ctx, current, args...).Output()
				if err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || len(raw) != 0 {
						t.Fatal("unexpected CLI outcome", err)
					}
					return exit.ExitCode()
				}
				if !json.Valid(raw) || bytes.Contains(raw, []byte(profile.Endpoint)) || bytes.Contains(raw, []byte("private.bin")) {
					t.Fatal("plan receipt disclosed private fields")
				}
				return 0
			}
			request := uploadPlanRequest{Format: uploadPlanRequestFormat, Planner: planner, Plan: template}
			out := filepath.Join(root, "signed.json")
			if code := invoke(request, keyFile, id, out); code != 0 {
				t.Fatal("valid plan refused", code)
			}
			originalPlan, err := os.ReadFile(out)
			must(err)
			expectedPlan, err := upload.Build(ctx, replica, id, template, plannerKey)
			must(err)
			if !bytes.Equal(originalPlan, expectedPlan) || target.Snapshot().Requests != 0 {
				t.Fatal("offline CLI changed canonical plan or reached storage")
			}
			if code := invoke(request, keyFile, id, out); code != 5 {
				t.Fatal("output collision accepted", code)
			}
			if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, originalPlan) {
				t.Fatal("output collision changed plan", err)
			}
			denied := filepath.Join(root, "denied.json")
			if code := invoke(request, wrongKey, id, denied); code != 3 {
				t.Fatal("wrong planner accepted", code)
			}
			expired := request
			expired.Plan.ExpiresUnix = time.Now().Unix() - 1
			if code := invoke(expired, keyFile, id, denied); code != 3 {
				t.Fatal("expired plan accepted", code)
			}
			injected := request
			injected.Plan.Catalog = json.RawMessage(`{"data":"forged"}`)
			if code := invoke(injected, keyFile, id, denied); code != 2 {
				t.Fatal("template supplied generated catalog", code)
			}
			if code := invoke(request, keyFile, storage.Hash([]byte("absent")), denied); code != 4 {
				t.Fatal("unknown local checkpoint accepted", code)
			}
			if _, err := os.Stat(denied); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed plan was published", err)
			}
			if entries, err := os.ReadDir(materialized); err != nil || len(entries) != 2 {
				t.Fatal("offline builder changed replica", err)
			}

			a := upload.Authority{Generation: trust, Planner: planner}
			verified, err := upload.Verify(originalPlan, a)
			must(err)
			part := verified.Blobs[0].Parts[0]
			backend, err := storage.New(profile, storage.Credentials{Access: "test-worker", Secret: "ephemeral-test-secret", ExpiresUnix: timing.Add(time.Minute).Unix()}, target.Roots)
			must(err)
			defer backend.Close()
			open := func(name string, raw []byte) *upload.Journal {
				t.Helper()
				dir := filepath.Join(root, name)
				must(os.Mkdir(dir, 0700))
				j, err := upload.Open(dir, raw, node, a, true)
				must(err)
				t.Cleanup(func() { j.Close() })
				return j
			}
			original := open("journal-original", originalPlan)
			first, err := original.Run(ctx, replica, backend, executorKey)
			must(err)
			partPath := target.Path("part-" + part.ID)
			saved, err := os.ReadFile(partPath)
			must(err)
			must(os.Remove(partPath))
			report, err := backend.AuditGeneration(ctx, id, trust)
			if !storage.Missing(err) || report.State != "MISSING" {
				t.Fatal("audit did not detect the missing immutable part", report, err)
			}
			next := func(name string) *upload.Journal {
				t.Helper()
				newRequest := request
				newRequest.Plan.Operation = storage.Hash([]byte(name))
				path := filepath.Join(root, name+".json")
				if code := invoke(newRequest, keyFile, id, path); code != 0 {
					t.Fatal("fresh plan refused", code)
				}
				raw, err := os.ReadFile(path)
				must(err)
				return open("journal-"+name, raw)
			}
			repaired, err := next("repair").Run(ctx, replica, backend, executorKey)
			must(err)
			if repaired.Receipt.Generation != id || repaired.Receipt.Operation == first.Receipt.Operation || repaired.Receipt.Verification != "full-target-readback" {
				t.Fatal("repair did not earn a fresh exact receipt", repaired.Receipt)
			}
			if got, err := os.ReadFile(partPath); err != nil || !bytes.Equal(saved, got) {
				t.Fatal("repair did not re-add exact ciphertext", err)
			}
			report, err = backend.AuditGeneration(ctx, id, trust)
			must(err)
			if report.State != "VERIFIED_CIPHERTEXT" {
				t.Fatal("repaired closure remained incomplete", report)
			}
			corrupt := bytes.Clone(saved)
			corrupt[0] ^= 1
			must(os.WriteFile(partPath, corrupt, 0600))
			if _, err := next("refuse-corrupt").Run(ctx, replica, backend, executorKey); !errors.Is(err, storage.ErrIntegrity) {
				t.Fatal("create-only repair overwrote or certified a corrupt object", err)
			}
			if got, err := os.ReadFile(partPath); err != nil || !bytes.Equal(corrupt, got) {
				t.Fatal("corrupt canonical bytes were modified", err)
			}
			state, err := original.Status(ctx)
			must(err)
			if state.Receipt == nil || *state.Receipt != first.Receipt {
				t.Fatal("original evidence changed")
			}
			if current != "" {
				t.Log("EXTERNAL_REPAIR_PLAN_CLI_PASS: offline plan matches existing format, missing immutable part repaired and conflicting corrupt bytes retained")
			}
		})
	}
}
