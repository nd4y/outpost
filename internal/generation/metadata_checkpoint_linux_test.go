package generation

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
	"syscall"
	"testing"

	"github.com/nd4y/outpost/internal/statefile"
)

type metadataCheckpointFixture struct {
	r                                           *Replica
	directory, operation, latest, orphan        string
	key                                         ed25519.PrivateKey
	checkpoint, permission, index, ledger, plan []byte
}

func pendingReplicaMetadata(t *testing.T) metadataCheckpointFixture {
	t.Helper()
	trust, writer, maintenance := trust(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	ok(t, err)
	dir := filepath.Join(temp(t), "replica")
	ok(t, os.Mkdir(dir, 0700))
	r, err := OpenWorkerAt(nil, dir, trust, true, key)
	ok(t, err)
	t.Cleanup(func() { r.Close() })
	first, objects := synthetic(t, trust, writer, 1, "metadata-old")
	old, err := r.Receive(ctx, first, fetch(objects))
	ok(t, err)
	second, objects := synthetic(t, trust, writer, 2, "metadata-retained")
	latest, err := r.Receive(ctx, second, fetch(objects))
	ok(t, err)
	ok(t, r.Pin(ctx, Hash([]byte("retained kit")), latest, "kit"))
	ok(t, r.EnableIndexCopy(ctx))
	permission := permit(t, r, maintenance, old)
	p, err := VerifyPermit(permission, trust)
	ok(t, err)
	r.Fault = func(point string) error {
		if point == "retirement-durable" {
			return ioFailure
		}
		return nil
	}
	if _, err = r.Maintain(ctx, permission); !errors.Is(err, ioFailure) {
		t.Fatal("pending cleanup not reached", err)
	}
	r.Fault = nil
	checkpoint, err := r.MetadataCheckpoint(ctx)
	ok(t, err)
	index, err := os.ReadFile(filepath.Join(dir, "state.json"))
	ok(t, err)
	ledger, err := os.ReadFile(filepath.Join(dir, "retention.json"))
	ok(t, err)
	plan, err := os.ReadFile(filepath.Join(dir, gcName(p.Operation)))
	ok(t, err)
	orphan := []byte("unknown later object outside original frozen candidates")
	orphanPath := filepath.Join(dir, "objects", Hash(orphan))
	ok(t, os.WriteFile(orphanPath, orphan, 0600))
	return metadataCheckpointFixture{r, dir, p.Operation, latest, orphanPath, key, checkpoint, permission, index, ledger, plan}
}

func (f metadataCheckpointFixture) removeMetadata(t *testing.T) {
	t.Helper()
	for name := range f.files() {
		ok(t, os.Remove(filepath.Join(f.directory, name)))
	}
}

func (f metadataCheckpointFixture) files() map[string][]byte {
	return map[string][]byte{"state.json": f.index, "retention.json": f.ledger, gcName(f.operation): f.plan}
}

func (f metadataCheckpointFixture) assertExact(t *testing.T) {
	t.Helper()
	for name, expected := range f.files() {
		actual, err := os.ReadFile(filepath.Join(f.directory, name))
		ok(t, err)
		if !bytes.Equal(actual, expected) {
			t.Fatal("restoration changed original metadata", name)
		}
	}
}

func TestReplicaMetadataCheckpointRecoversCombinedLossAndFrozenScope(t *testing.T) {
	f := pendingReplicaMetadata(t)
	f.removeMetadata(t)
	if _, err := OpenWorkerAt(nil, f.directory, f.r.trust, false, f.key); !errors.Is(err, ErrIndexRecovery) {
		t.Fatal("missing metadata opened normally", err)
	}
	if _, err := RecoverIndexCopyAt(nil, ctx, f.directory, f.r.trust, f.key, nil); err == nil {
		t.Fatal("old index-only recovery inferred missing sidecars")
	}
	changed, err := RestoreMetadataCheckpointAt(nil, ctx, f.directory, f.r.trust, f.key, nil, f.checkpoint, Hash(f.checkpoint))
	ok(t, err)
	if !changed {
		t.Fatal("combined missing files not restored")
	}
	f.assertExact(t)
	changed, err = RestoreMetadataCheckpointAt(nil, ctx, f.directory, f.r.trust, f.key, nil, f.checkpoint, Hash(f.checkpoint))
	ok(t, err)
	if changed {
		t.Fatal("identical replay rewrote metadata")
	}
	_, err = f.r.Maintain(ctx, f.permission)
	ok(t, err)
	ok(t, f.r.VerifyComplete(ctx, f.latest))
	if _, err := os.Stat(f.orphan); err != nil {
		t.Fatal("recovery expanded original deletion scope", err)
	}
	t.Log("exact state/ledger/plan recovered together; pin, receipt, original candidates and later orphan preserved")
}

func TestReplicaMetadataCheckpointRejectsUnprovenRecovery(t *testing.T) {
	for _, kind := range []string{"hash", "index-digest", "missing-anchor", "missing-copy", "foreign-key", "ledger", "plan", "extra-plan", "existing", "symlink", "missing-object", "quota", "cancel", "stale", "admission-collision"} {
		t.Run(kind, func(t *testing.T) {
			f := pendingReplicaMetadata(t)
			raw, expected, key := bytes.Clone(f.checkpoint), Hash(f.checkpoint), f.key
			var checkpoint metadataCheckpoint
			ok(t, json.Unmarshal(raw, &checkpoint))
			if kind == "stale" {
				ok(t, f.r.Pin(ctx, Hash([]byte("later pin")), f.latest, "restore"))
			}
			f.removeMetadata(t)
			operationCtx := ctx
			var admit statefile.Admission
			switch kind {
			case "hash":
				expected = Hash([]byte("other checkpoint"))
			case "index-digest":
				checkpoint.Index = Hash([]byte("other index"))
			case "missing-anchor":
				ok(t, os.Remove(filepath.Join(f.directory, indexAnchorName)))
			case "missing-copy":
				ok(t, os.Remove(filepath.Join(f.directory, indexCopyName)))
			case "foreign-key":
				_, key, _ = ed25519.GenerateKey(rand.Reader)
			case "ledger":
				checkpoint.Retention = json.RawMessage(`{"format":"outpost-retention-ledger-1","records":{}}`)
			case "plan":
				delete(checkpoint.Plans, f.operation)
			case "extra-plan":
				checkpoint.Plans[Hash([]byte("extra operation"))] = json.RawMessage(`{}`)
			case "existing":
				ok(t, os.WriteFile(filepath.Join(f.directory, "retention.json"), []byte("foreign"), 0600))
			case "symlink":
				ok(t, os.Symlink("index-anchor", filepath.Join(f.directory, "state.json")))
			case "missing-object":
				_, refs, err := f.r.catalogEntry(f.latest, entryFromMetadata(t, f.index, f.latest), true)
				ok(t, err)
				for id := range refs {
					ok(t, os.Remove(filepath.Join(f.directory, "objects", id)))
					break
				}
			case "quota":
				admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
			case "cancel":
				var cancel context.CancelFunc
				operationCtx, cancel = context.WithCancel(ctx)
				cancel()
			case "admission-collision":
				admit = func(name string, _ int) (func(bool) error, error) {
					ok(t, os.WriteFile(filepath.Join(f.directory, name), []byte("foreign"), 0600))
					return func(bool) error { return nil }, nil
				}
			}
			if kind == "index-digest" || kind == "ledger" || kind == "plan" || kind == "extra-plan" {
				var err error
				raw, err = json.Marshal(checkpoint)
				ok(t, err)
				expected = Hash(raw)
			}
			if changed, err := RestoreMetadataCheckpointAt(nil, operationCtx, f.directory, f.r.trust, key, admit, raw, expected); changed || err == nil {
				t.Fatal("unproven recovery admitted", changed, err)
			}
			if kind != "symlink" {
				if _, err := os.Lstat(filepath.Join(f.directory, "state.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected recovery published primary index", err)
				}
			}
		})
	}
}

func entryFromMetadata(t *testing.T, raw []byte, id string) entry {
	t.Helper()
	var s state
	ok(t, json.Unmarshal(raw, &s))
	return s.Generations[id]
}

type metadataCheckpointChild struct {
	Directory  string
	Trust      Trust
	Key        ed25519.PrivateKey
	Checkpoint []byte
}

func TestReplicaMetadataCheckpointSIGKILLPartialReplay(t *testing.T) {
	f := pendingReplicaMetadata(t)
	f.removeMetadata(t)
	config, err := json.Marshal(metadataCheckpointChild{f.directory, f.r.trust, f.key, f.checkpoint})
	ok(t, err)
	name := filepath.Join(temp(t), "child.json")
	ok(t, os.WriteFile(name, config, 0600))
	binary, err := os.Executable()
	ok(t, err)
	child := exec.Command(binary, "-test.run=^TestReplicaMetadataCheckpointSIGKILLChild$", "-test.timeout=30s")
	child.Env = append(os.Environ(), "OUTPOST_METADATA_CHECKPOINT_CHILD="+name)
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("expected real SIGKILL, got %v: %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(f.directory, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial supporting recovery published primary", err)
	}
	// The first sorted supporting file must actually survive SIGKILL, and its
	// inode must survive continuation rather than being silently replaced.
	survivor := filepath.Join(f.directory, gcName(f.operation))
	before, err := os.Stat(survivor)
	ok(t, err)
	plan, err := os.ReadFile(survivor)
	ok(t, err)
	if !bytes.Equal(plan, f.plan) {
		t.Fatal("durable supporting plan did not survive SIGKILL")
	}
	changed, err := RestoreMetadataCheckpointAt(nil, ctx, f.directory, f.r.trust, f.key, nil, f.checkpoint, Hash(f.checkpoint))
	ok(t, err)
	if !changed {
		t.Fatal("partial restore not continued")
	}
	f.assertExact(t)
	after, err := os.Stat(survivor)
	ok(t, err)
	if !os.SameFile(before, after) {
		t.Fatal("replay replaced an already durable matching supporting file")
	}
	_, err = f.r.Maintain(ctx, f.permission)
	ok(t, err)
	ok(t, f.r.VerifyComplete(ctx, f.latest))
	if _, err := os.Stat(f.orphan); err != nil {
		t.Fatal("partial replay expanded scope", err)
	}
	t.Log("real SIGKILL after supporting file fsync, index remained absent, exact replay completed original maintenance")
}

func TestReplicaMetadataCheckpointPartialQuotaAndCancellation(t *testing.T) {
	for _, kind := range []string{"quota-before-primary", "cancel-after-support"} {
		t.Run(kind, func(t *testing.T) {
			f := pendingReplicaMetadata(t)
			f.removeMetadata(t)
			request, cancel := context.WithCancel(ctx)
			defer cancel()
			if kind == "quota-before-primary" {
				f.r.Admit = func(name string, _ int) (func(bool) error, error) {
					if name == "state.json" {
						return nil, statefile.ErrCapacity
					}
					return func(bool) error { return nil }, nil
				}
			} else {
				f.r.Fault = func(point string) error {
					if point == "replica-metadata-file-restored" {
						cancel()
					}
					return nil
				}
			}
			_, err := f.r.restoreMetadataCheckpoint(request, f.checkpoint, Hash(f.checkpoint))
			expected := statefile.ErrCapacity
			if kind == "cancel-after-support" {
				expected = context.Canceled
			}
			if !errors.Is(err, expected) {
				t.Fatal("partial failure not observed", err)
			}
			if _, err := os.Stat(filepath.Join(f.directory, "state.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("partial failure published primary", err)
			}
			path := filepath.Join(f.directory, gcName(f.operation))
			before, err := os.Stat(path)
			ok(t, err)
			f.r.Admit, f.r.Fault = nil, nil
			changed, err := f.r.restoreMetadataCheckpoint(ctx, f.checkpoint, Hash(f.checkpoint))
			ok(t, err)
			if !changed {
				t.Fatal("partial recovery was not continued")
			}
			f.assertExact(t)
			after, err := os.Stat(path)
			ok(t, err)
			if !os.SameFile(before, after) {
				t.Fatal("partial replay rewrote durable support")
			}
			_, err = f.r.Maintain(ctx, f.permission)
			ok(t, err)
			ok(t, f.r.VerifyComplete(ctx, f.latest))
		})
	}
}

func TestReplicaMetadataCheckpointSIGKILLChild(t *testing.T) {
	name := os.Getenv("OUTPOST_METADATA_CHECKPOINT_CHILD")
	if name == "" {
		t.Skip("child only")
	}
	raw, err := os.ReadFile(name)
	ok(t, err)
	var config metadataCheckpointChild
	ok(t, json.Unmarshal(raw, &config))
	root, err := os.OpenRoot(config.Directory)
	ok(t, err)
	defer root.Close()
	r := &Replica{root: root, trust: config.Trust}
	r.setIndexKey(config.Key)
	r.Fault = func(point string) error {
		if point == "replica-metadata-file-restored" {
			ok(t, syscall.Kill(os.Getpid(), syscall.SIGKILL))
		}
		return nil
	}
	_, err = r.restoreMetadataCheckpoint(ctx, config.Checkpoint, Hash(config.Checkpoint))
	t.Fatal("child missed durable boundary", err)
}
