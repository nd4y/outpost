package volume

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
)

func TestFencedVolumePermitAndCopyRefusals(t *testing.T) {
	owner, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	request := MoveRequest{Format: MoveFormat, Operation: storage.Hash([]byte("example")),
		Current:   Binding{Format: FencedFormat, Root: "/original", Epoch: 1, FSID: [2]int32{4, 5}},
		Directory: "/original/replica", NextRoot: "/target", Probe: Observation{FSID: [2]int32{6, 7}}}
	permit, e := SignMove(request, signer)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := VerifyMove(permit, owner)
	if e != nil || decoded.Request != request {
		t.Fatalf("valid authorization: %v", e)
	}
	decoded.Request.NextRoot = "/unrelated"
	tampered, _ := json.Marshal(decoded)
	if _, e = VerifyMove(tampered, owner); !errors.Is(e, ErrUnavailable) {
		t.Fatal("changed target accepted", e)
	}
	request.Probe.FSID = request.Current.FSID
	if _, e = SignMove(request, signer); !errors.Is(e, ErrUnavailable) {
		t.Fatal("same-filesystem copy accepted", e)
	}
	old, fresh := t.TempDir(), t.TempDir()
	setCopyMode := func(mode os.FileMode) {
		t.Helper()
		for _, dir := range []string{old, fresh} {
			if e := os.Chmod(dir, mode); e != nil {
				t.Fatal(e)
			}
		}
	}
	setCopyMode(0700)
	data := []byte("protected version bytes")
	write := func(dir, name string, data []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(old, "record", data)
	write(fresh, "record", data)
	a, e := localfs.OpenRoot(old)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := localfs.OpenRoot(fresh)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if e = compareCopy(t.Context(), a, b); e != nil {
		t.Fatal("identical private copy:", e)
	}
	setCopyMode(0750)
	if e = compareCopy(t.Context(), a, b); !errors.Is(e, ErrUnavailable) {
		t.Fatal("group-readable copy accepted", e)
	}
	setCopyMode(0700)
	write(fresh, "extra", data)
	if e = compareCopy(t.Context(), a, b); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unknown candidate files accepted", e)
	}
	if e = os.Remove(filepath.Join(fresh, "extra")); e != nil {
		t.Fatal(e)
	}
	write(fresh, "record", append([]byte("z"), data[1:]...))
	if e = compareCopy(t.Context(), a, b); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wrong bytes accepted", e)
	}
	if e = os.Remove(filepath.Join(fresh, "record")); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(old, "record"), filepath.Join(fresh, "record")); e != nil {
		t.Fatal(e)
	}
	if e = compareCopy(t.Context(), a, b); e == nil {
		t.Fatal("symbolic link accepted")
	}
}

func fencedFixture(t *testing.T) (string, string, string) {
	t.Helper()
	base := os.Getenv("OUTPOST_FENCED_VOLUME_FIXTURE")
	if base == "" {
		t.Skip("requires three isolated filesystem mounts")
	}
	create := func(name string) string {
		dir, e := os.MkdirTemp(filepath.Join(base, name), "outpost-test-")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		return dir
	}
	return create("original"), create("candidate"), create("authority")
}

func TestFencedVolumeRetiresBeforeActivationAndPreservesCopy(t *testing.T) {
	ctx := t.Context()
	old, fresh, authorityPath := fencedFixture(t)
	probe := func(path string) Observation {
		t.Helper()
		result, e := Probe(ctx, path)
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	owner, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	stateDir := filepath.Join(old, "worker")
	active, e := EnrollFenced(ctx, old, stateDir, probe(old), storage.Hash([]byte("example-node")), authorityPath, owner)
	if e != nil {
		t.Fatal(e)
	}
	root, check, closeCurrent, e := OpenFenced(ctx, active, stateDir, authorityPath, owner, true)
	if e != nil {
		t.Fatal(e)
	}
	defer closeCurrent()
	record := []byte("unchanged state including older versions")
	file, e := localfs.OpenFile(root, "file", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write(record); e != nil {
		t.Fatal(e)
	}
	if e = errors.Join(file.Sync(), file.Close()); e != nil {
		t.Fatal(e)
	}
	if e = check(ctx); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = OpenFenced(ctx, active, stateDir, fresh, owner, false); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wrong authority accepted", e)
	}
	legacy := active
	legacy.Format = Format
	if e = legacy.Check(ctx, stateDir, false); !errors.Is(e, ErrUnavailable) {
		t.Fatal("legacy profile opened protected marker", e)
	}
	restoreOffline := coldVolumeSeed(t, stateDir)
	newStateDir := filepath.Join(fresh, "worker")
	copyColdVolumeFixture(t, stateDir, newStateDir)
	dest := filepath.Join(newStateDir, "file")
	request := MoveRequest{Format: MoveFormat, Operation: storage.Hash([]byte("exact")), Current: active,
		Directory: stateDir, NextRoot: fresh, Probe: probe(fresh)}
	permit, e := SignMove(request, signer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = MoveFenced(ctx, active, stateDir, authorityPath, owner, permit); !errors.Is(e, ErrUnavailable) {
		t.Fatal("move admitted while a worker still held the authority", e)
	}
	closeCurrent()
	if e = os.WriteFile(dest, []byte("wrong"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = MoveFenced(ctx, active, stateDir, authorityPath, owner, permit); e == nil {
		t.Fatal("move admitted incomplete candidate")
	}
	_, _, stoppedUnchanged, e := OpenFenced(ctx, active, stateDir, authorityPath, owner, false)
	if e != nil {
		t.Fatal("failed copy retired the active original", e)
	}
	stoppedUnchanged()
	if e = os.WriteFile(dest, record, 0600); e != nil {
		t.Fatal(e)
	}
	interrupted := errors.New("synthetic interruption after durable retirement")
	if _, e = moveFenced(ctx, active, stateDir, authorityPath, owner, permit, func(point string) error {
		if point == "retirement-fsynced" {
			return interrupted
		}
		return nil
	}); !errors.Is(e, interrupted) {
		t.Fatal("failed to stop before target marker", e)
	}
	if _, e = os.Lstat(filepath.Join(fresh, Sentinel)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("target became eligible before recovery", e)
	}
	if _, _, _, e = OpenFenced(ctx, active, stateDir, authorityPath, owner, false); !errors.Is(e, ErrUnavailable) {
		t.Fatal("retired original opened during interrupted cutover", e)
	}
	if e = os.Rename(fresh, fresh+"-off"); e != nil {
		t.Fatal(e)
	}
	defer os.Rename(fresh+"-off", fresh)
	if _, e = MoveFenced(ctx, active, stateDir, authorityPath, owner, permit); !errors.Is(e, ErrUnavailable) {
		t.Fatal("missing replacement was admitted", e)
	}
	if e = os.Rename(fresh+"-off", fresh); e != nil {
		t.Fatal(e)
	}
	next, e := MoveFenced(ctx, active, stateDir, authorityPath, owner, permit)
	if e != nil || next.Epoch != active.Epoch+1 || next.Scope != active.Scope {
		t.Fatalf("activation: %v", e)
	}
	if _, _, _, e = OpenFenced(ctx, active, stateDir, authorityPath, owner, false); !errors.Is(e, ErrUnavailable) {
		t.Fatal("old epoch accepted after activation", e)
	}
	raw, e := os.ReadFile(filepath.Join(old, Sentinel))
	if e != nil || storage.Hash(raw) == active.SentinelDigest {
		t.Fatal("original marker was not retired", e)
	}
	if picked, e := MoveFenced(ctx, active, stateDir, authorityPath, owner, permit); e != nil || picked != next {
		t.Fatal("same transition did not replay", e)
	}
	renamed := old + "-off"
	if e = os.Rename(old, renamed); e != nil {
		t.Fatal(e)
	}
	defer os.Rename(renamed, old)
	_, _, closeNext, e := OpenFenced(context.Background(), next, newStateDir, authorityPath, owner, false)
	if e != nil {
		t.Fatal("new active epoch requires retired disk", e)
	}
	defer closeNext()
	closeNext()
	restoreOffline(newStateDir)
	current, e := os.ReadFile(dest)
	if e != nil || string(current) != string(record) {
		t.Fatal("copied state was not preserved", e)
	}
}

func coldVolumeSeed(t *testing.T, directory string) func(string) {
	t.Helper()
	ctx := t.Context()
	fixture := t.TempDir()
	owner, err := filekit.NewOwner()
	if err != nil {
		t.Fatal(err)
	}
	writer, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	maintenance, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("cold-volume-fixture")),
		Epoch: 1, Writer: writer, Maintenance: maintenance}
	input := filepath.Join(fixture, "input")
	cache := filepath.Join(fixture, "cache")
	source, err := filekit.OpenStore(cache, owner, true)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := generation.Open(filepath.Join(directory, "replica"), trust, true)
	if err != nil {
		t.Fatal(err)
	}
	versions := []string{"before volume move", "latest before volume move"}
	var prior string
	var file string
	checkpoints := make([]string, len(versions))
	for i, contents := range versions {
		if err = os.WriteFile(input, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		d, e := source.Backup(ctx, input, filekit.BackupOptions{File: file, Previous: prior, Names: []string{"original.txt"}})
		if e != nil {
			t.Fatal(e)
		}
		checkpoints[i], e = generation.Seal(ctx, source, []string{d.Version}, replica,
			generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository,
				Epoch: 1, Sequence: uint64(i + 1), Parent: func() string {
					if i == 0 {
						return ""
					}
					return checkpoints[i-1]
				}(), SnapshotUnix: int64(i + 1), Policy: 1, KitFormat: generation.KitFormat}, signing)
		if e != nil {
			t.Fatal(e)
		}
		prior, file = d.Version, d.File
	}
	if err = errors.Join(source.Close(), replica.Close()); err != nil {
		t.Fatal(err)
	}
	if err = errors.Join(os.RemoveAll(cache), os.Remove(input)); err != nil {
		t.Fatal(err)
	}
	owner.SigningKey = nil
	return func(next string) {
		t.Helper()
		for i, id := range checkpoints {
			output := filepath.Join(t.TempDir(), "restored")
			if _, e := generation.RecoverMaterialized(ctx, filepath.Join(next, "replica"),
				id, trust, owner, generation.RecoverySelection{}, output); e != nil {
				t.Fatal(e)
			}
			data, e := os.ReadFile(filepath.Join(output, "original.txt"))
			if e != nil || string(data) != versions[i] {
				t.Fatal("independent generation content differs", e)
			}
		}
	}
}

func copyColdVolumeFixture(t *testing.T, old, next string) {
	t.Helper()
	if e := filepath.WalkDir(old, func(path string, item os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(old, path)
		if e != nil {
			return e
		}
		target := filepath.Join(next, rel)
		info, e := item.Info()
		if e != nil {
			return e
		}
		if info.IsDir() {
			return os.Mkdir(target, info.Mode().Perm())
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	}); e != nil {
		t.Fatal(e)
	}
}
