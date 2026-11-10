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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestCLIArchiveRetrievalRestartsExpiresAndRestoresSelectedVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	root := teststore.Root(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		must(os.WriteFile(path, raw, 0600))
		return path
	}
	writeJSON := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		must(err)
		return write(name, raw)
	}
	owner, err := filekit.NewOwner()
	must(err)
	writer, writerKey, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	maintenance, _, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	planner, plannerKey, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte(t.Name())), Epoch: 1, Writer: writer, Maintenance: maintenance}
	namespace := storage.Hash([]byte(trust.Domain + "/" + trust.Repository))
	secret := "fixture-" + storage.Hash([]byte(t.Name()))
	const class = "ARCHIVE_TEST"
	const pending = `ongoing-request="true"`
	var server *teststore.Server
	var lock sync.Mutex
	states := map[string]string{}
	posts := map[string]int{}
	dropNext := true
	server = teststore.New(t, teststore.Options{
		Kind: "s3", Namespace: namespace, Logins: map[string]teststore.Login{"fixture": {Secret: secret}},
		Before: func(w http.ResponseWriter, r *http.Request, _, key string, body []byte) bool {
			lock.Lock()
			defer lock.Unlock()
			state, cold := states[key]
			switch r.Method {
			case http.MethodHead:
				if !cold {
					return false
				}
				info, err := os.Stat(server.Path(key))
				if err != nil {
					w.WriteHeader(http.StatusNotFound)
					return true
				}
				w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
				w.Header().Set("X-Amz-Storage-Class", class)
				if state != "" {
					w.Header().Set("X-Amz-Restore", state)
				}
				w.WriteHeader(http.StatusOK)
				return true
			case http.MethodPost:
				if !cold || r.URL.RawQuery != "restore=" || !bytes.Contains(body, []byte("<Days>2</Days>")) ||
					!bytes.Contains(body, []byte("<Tier>Bulk</Tier>")) {
					w.WriteHeader(http.StatusBadRequest)
					return true
				}
				posts[key]++
				states[key] = pending
				if dropNext {
					dropNext = false
					connection, _, err := http.NewResponseController(w).Hijack()
					if err == nil {
						_ = connection.Close()
						return true
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					return true
				}
				w.WriteHeader(http.StatusAccepted)
				return true
			case http.MethodGet:
				rawExpiry := strings.TrimSuffix(strings.TrimPrefix(state, `ongoing-request="false", expiry-date="`), `"`)
				expires, err := http.ParseTime(rawExpiry)
				if cold && (err != nil || !expires.After(time.Now())) {
					w.WriteHeader(http.StatusForbidden)
					return true
				}
			}
			return false
		},
	})
	profile := storage.Profile{Kind: "s3", Endpoint: server.Endpoint(), Namespace: namespace, Region: server.Options.Region, MaxObjectBytes: 64 << 10,
		Concurrency: 1, RequestsPerSecond: 1000, Attempts: 3, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
	expires := time.Now().Add(5 * time.Minute).Unix()
	backend, err := storage.New(profile, storage.Credentials{Access: "fixture", Secret: secret, ExpiresUnix: expires}, server.Roots)
	must(err)
	defer backend.Close()
	sourcePath, replicaPath := filepath.Join(root, "source"), filepath.Join(root, "replica")
	source, err := filekit.OpenStore(sourcePath, owner, true)
	must(err)
	defer source.Close()
	must(os.Mkdir(replicaPath, 0700))
	replica, err := generation.Open(replicaPath, trust, true)
	must(err)
	defer replica.Close()
	content := make([]byte, 116<<10)
	_, err = rand.Read(content)
	must(err)
	primary, err := source.Backup(ctx, write("original", content), filekit.BackupOptions{Names: []string{"private/selected"}})
	must(err)
	otherContent := make([]byte, len(content))
	_, err = rand.Read(otherContent)
	must(err)
	other, err := source.Backup(ctx, write("other", otherContent), filekit.BackupOptions{Names: []string{"unrelated"}})
	must(err)
	checkpoint, err := generation.Seal(ctx, source, []string{primary.Version, other.Version}, replica,
		generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1}, writerKey)
	must(err)
	raw, err := replica.Catalog(ctx, checkpoint)
	must(err)
	planBytes, err := upload.Build(ctx, replica, checkpoint, upload.Plan{Format: upload.Format, Operation: storage.Hash([]byte("archive-upload")), Profile: profile,
		AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: upload.Identity(writer), Class: "trusted", PublicKey: writer}},
		StartMillis: time.Now().Add(-10 * time.Minute).UnixMilli(), ExpiresUnix: time.Now().Add(-5 * time.Minute).Unix(), SlotMillis: 1000}, plannerKey)
	must(err)
	plan, err := upload.Verify(planBytes, upload.Authority{Generation: trust, Planner: planner})
	must(err)
	catalog, err := generation.VerifyCatalog(raw, trust)
	must(err)
	var payloadParts []string
	var unrelatedParts []string
	var selectedRoot string
	for _, blob := range plan.Blobs {
		data, err := replica.ReadObject(ctx, checkpoint, blob.Object)
		must(err)
		must(backend.PutBlob(ctx, blob.Object, data))
		for _, kit := range catalog.Kits {
			if kit.Version == primary.Version && kit.Root == blob.Object {
				selectedRoot = "part-" + blob.Parts[0].ID
			}
			for _, object := range kit.Objects {
				if object != blob.Object || len(blob.Parts) < 2 {
					continue
				}
				for _, part := range blob.Parts {
					key := "part-" + part.ID
					if kit.Version == primary.Version {
						payloadParts = append(payloadParts, key)
					} else {
						unrelatedParts = append(unrelatedParts, key)
					}
				}
			}
		}
	}
	must(backend.Publish(ctx, raw, trust))
	if len(payloadParts) < 2 || len(unrelatedParts) < 2 || selectedRoot == "" {
		t.Fatal("fixture needs split ciphertext and separate metadata")
	}
	must(replica.Close())
	must(source.Close())
	must(os.Rename(replicaPath, replicaPath+"-unavailable"))
	must(os.Rename(sourcePath, sourcePath+"-unavailable"))
	owner.SigningKey = nil
	ownerFile := filepath.Join(root, "owner.json")
	must(filekit.WriteOwner(ownerFile, owner))
	trustFile := writeJSON("trust.json", trust)
	credentialFile := writeJSON("credentials.json", map[string]any{"access": "fixture", "secret": secret, "expiresUnix": expires})
	ca := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.HTTP.Certificate().Raw}))
	readerProfile := externalRecoveryProfile{Format: externalRecoveryFormat, Target: profile.ID(), Profile: profile,
		CredentialFile: credentialFile, CAFile: ca, Archive: &archiveReader{Planner: planner, Policy: storage.ArchivePolicy{Class: class, Tier: "Bulk", Days: 2,
			MinimumWindowSeconds: 60, MaxParts: 50, MaxBytes: 2 << 20, Quote: storage.ArchiveQuote{
				Currency: "XTS", RequestMicros: 30, GiBMicros: 1000, MaxBatchMicros: 5000}}}}
	reader := writeJSON("archive-reader.json", readerProfile)
	planFile := write("plan.json", planBytes)
	base := []string{"--bootstrap", reader, "--trust", trustFile, "--key", ownerFile, "--generation", checkpoint, "--version", primary.Version}
	call := func(command string, args ...string) (any, error) {
		return run(ctx, append(append([]string{command}, base...), args...))
	}
	archive := func(command string, maxRequests int, wantErr error) storage.ArchiveProgress {
		t.Helper()
		args := []string{"--input", planFile, "--sha256", storage.Hash(planBytes)}
		if maxRequests > 0 {
			args = append(args, "--max-requests", strconv.Itoa(maxRequests))
		}
		got, err := call(command, args...)
		if wantErr != nil {
			if !errors.Is(err, wantErr) {
				t.Fatal("archive operation returned wrong error", err, wantErr)
			}
			return storage.ArchiveProgress{}
		}
		must(err)
		return got.(archiveResult).Progress
	}
	setState := func(parts []string, state string) {
		lock.Lock()
		defer lock.Unlock()
		for _, part := range parts {
			states[part] = state
		}
	}
	countPosts := func(want int) {
		t.Helper()
		lock.Lock()
		defer lock.Unlock()
		total := 0
		for key, count := range posts {
			for _, unrelated := range unrelatedParts {
				if key == unrelated {
					t.Fatal("unrelated version was requested")
				}
			}
			total += count
		}
		if total != want {
			t.Fatal("incorrect number of retrieval requests", total, want)
		}
	}
	status, request := "archive-external-status", "archive-external-request"
	setState(payloadParts, "")
	setState(unrelatedParts, "")
	initial := archive(status, 0, nil)
	if initial.Ready || initial.NeedsRequest != len(payloadParts) || initial.Currency != "XTS" ||
		initial.RemainingEstimateMicros <= int64(len(payloadParts))*30 || initial.BatchEstimateMicros != 0 {
		t.Fatal("cold payload was classified as ready", initial)
	}
	onlineMetadata := 0
	for _, part := range initial.Parts {
		if part.Metadata && part.State == "ONLINE" {
			onlineMetadata++
		}
	}
	if onlineMetadata < 2 {
		t.Fatal("status did not identify protected catalog and kit metadata")
	}
	countPosts(0)
	before := server.Snapshot().Requests
	if _, err = call(request, "--input", planFile, "--sha256", storage.Hash([]byte("changed plan")), "--max-requests", "1"); !errors.Is(err, storage.ErrDenied) ||
		server.Snapshot().Requests != before {
		t.Fatal("changed plan digest reached the target", err)
	}
	readerProfile.Archive.Policy.Quote.MaxBatchMicros = 29
	writeJSON("archive-reader.json", readerProfile)
	archive(request, 1, storage.ErrCapacity)
	countPosts(0)
	readerProfile.Archive.Policy.Quote.MaxBatchMicros = 5000
	writeJSON("archive-reader.json", readerProfile)
	expiry := func(at time.Time) string {
		return `ongoing-request="false", expiry-date="` + at.UTC().Format(http.TimeFormat) + `"`
	}
	setState([]string{selectedRoot}, expiry(time.Now().Add(time.Hour)))
	archive(request, 1, storage.ErrUnsupported)
	countPosts(0)
	lock.Lock()
	delete(states, selectedRoot)
	lock.Unlock()
	archive(request, 1, storage.ErrUnavailable)
	countPosts(1)
	var restarted storage.ArchiveProgress
	if executable := os.Getenv("OUTPOST_EXTERNAL_RECOVERY_CLI"); executable != "" {
		args := append(append([]string{status}, base...), "--input", planFile, "--sha256", storage.Hash(planBytes))
		raw, err := exec.CommandContext(ctx, executable, args...).Output()
		must(err)
		var envelope struct {
			Format string        `json:"format"`
			Result archiveResult `json:"result"`
		}
		must(json.Unmarshal(raw, &envelope))
		if envelope.Format != "outpost-cli-1" || envelope.Result.Generation != checkpoint || envelope.Result.Version != primary.Version {
			t.Fatal("new CLI process lost the exact selection")
		}
		restarted = envelope.Result.Progress
	} else {
		restarted = archive(status, 0, nil)
	}
	if restarted.NeedsRequest != len(payloadParts)-1 || restarted.Ready {
		t.Fatal("status failed to reconcile the lost accepted request", restarted)
	}
	archive(request, len(payloadParts), nil)
	countPosts(len(payloadParts))
	archive(request, len(payloadParts), nil)
	countPosts(len(payloadParts))
	setState(payloadParts, expiry(time.Now().Add(30*time.Second)))
	if archive(status, 0, nil).Ready {
		t.Fatal("short temporary window was classified as sufficient")
	}
	setState(payloadParts, expiry(time.Now().Add(time.Hour)))
	restore := func(name string) {
		t.Helper()
		dest := filepath.Join(root, name)
		_, err := call("restore-external", "--output", dest)
		must(err)
		got, err := os.ReadFile(filepath.Join(dest, "private/selected"))
		must(err)
		if !bytes.Equal(got, content) {
			t.Fatal("restored archive bytes differ")
		}
		if _, err = os.Stat(filepath.Join(dest, "unrelated")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("restore included an unrelated version", err)
		}
	}
	if !archive(status, 0, nil).Ready {
		t.Fatal("restored archive window was not visible")
	}
	restore("restore-first")
	setState(payloadParts, expiry(time.Now().Add(-time.Minute)))
	expiredDest := filepath.Join(root, "expired-restore")
	if _, err = call("restore-external", "--output", expiredDest); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("expired payload was read", err)
	}
	if _, err = os.Stat(expiredDest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restore published incomplete plaintext", err)
	}
	if progress := archive(status, 0, nil); progress.Ready || progress.NeedsRequest != len(payloadParts) {
		t.Fatal("expired window was not classified", progress)
	}
	archive(request, len(payloadParts), nil)
	countPosts(len(payloadParts) * 2)
	setState(payloadParts, expiry(time.Now().Add(time.Hour)))
	restore("restore-after-expiry")
}
