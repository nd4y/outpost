package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
)

type executorFixture struct {
	executor         *Executor
	profile          Profile
	request          Request
	source           *generation.Replica
	original         []byte
	replicaDirectory string
}

func newExecutorFixture(t *testing.T) executorFixture {
	t.Helper()
	ctx := context.Background()
	base := teststore.Root(t)
	vol := filepath.Join(base, "volume")
	must(t, os.Mkdir(vol, 0700))
	node := storage.Hash([]byte("trusted executor"))
	observed, e := volume.Probe(ctx, vol)
	must(t, e)
	binding, e := volume.Enroll(ctx, vol, observed, node, 1)
	must(t, e)
	owner, e := filekit.NewOwner()
	must(t, e)
	writer, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	maintenance, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("recovery repository")), Epoch: 1, Writer: writer, Maintenance: maintenance}
	cache := filepath.Join(base, "source-cache")
	s, e := filekit.OpenStore(cache, owner, true)
	must(t, e)
	input := filepath.Join(base, "source")
	original := bytes.Repeat([]byte("old retained plaintext\n"), 4096)
	put(t, base, "source", original)
	first, e := s.Backup(ctx, input, filekit.BackupOptions{Names: []string{"private/data", "alias"}})
	must(t, e)
	must(t, os.WriteFile(input, []byte("new retained plaintext"), 0600))
	second, e := s.Backup(ctx, input, filekit.BackupOptions{File: first.File, Previous: first.Version, Names: []string{"private/data", "alias"}})
	must(t, e)
	replicaDir := filepath.Join(base, "replica")
	must(t, os.Mkdir(replicaDir, 0700))
	replica, e := generation.Open(replicaDir, trust, true)
	must(t, e)
	t.Cleanup(func() { replica.Close() })
	id, e := generation.Seal(ctx, s, []string{first.Version, second.Version}, replica, generation.Catalog{Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: time.Now().Unix(), Policy: 1}, key)
	must(t, e)
	must(t, s.Close())
	must(t, os.RemoveAll(cache))
	must(t, os.Remove(input))
	owner.SigningKey = nil
	ownerFile := filepath.Join(base, "recovery-key.json")
	must(t, filekit.WriteOwner(ownerFile, owner))
	p := Profile{Format: ProfileFormat, Node: node, Directory: filepath.Join(vol, "output"), Volume: binding, Limits: smallLimits, Presets: []Preset{{ID: storage.Hash([]byte("preset")), Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, OwnerFile: ownerFile}}}
	x, e := OpenExecutor(ctx, p, true)
	must(t, e)
	t.Cleanup(func() { x.Close() })
	r := Request{Operation: storage.Hash([]byte("restore old version")), Binding: storage.Hash([]byte("signed command envelope")), Preset: p.Presets[0].ID, Generation: id, Versions: []string{first.Version}}
	return executorFixture{x, p, r, replica, original, replicaDir}
}
func allowed(ctx context.Context) error { return ctx.Err() }

func TestRecoveryExecutorPublishesBoundBundleAndReplaysWithoutKeys(t *testing.T) {
	f := newExecutorFixture(t)
	ctx := context.Background()
	result, e := f.executor.Restore(ctx, f.request, f.source, allowed)
	must(t, e)
	if result.Format != ReceiptFormat || result.Operation != f.request.Operation || result.Restored.Restored.Files != 1 || result.Restored.Restored.Aliases != 1 || result.VerifiedUnix < 1 {
		t.Fatal(result)
	}
	path := filepath.Join(f.profile.Directory, "results", f.request.Operation, "data")
	body, e := os.ReadFile(filepath.Join(path, "private/data"))
	must(t, e)
	if !bytes.Equal(body, f.original) {
		t.Fatal("wrong retained version")
	}
	one, e := os.Stat(filepath.Join(path, "private/data"))
	must(t, e)
	two, e := os.Stat(filepath.Join(path, "alias"))
	must(t, e)
	if !os.SameFile(one, two) {
		t.Fatal("hardlink lost")
	}
	s, e := f.source.Status(ctx)
	must(t, e)
	if len(s.Pins) != 0 {
		t.Fatal("completed source pin retained", s.Pins)
	}
	encoded, e := json.Marshal(result)
	must(t, e)
	for _, private := range []string{"private", "plaintext", f.profile.Directory, f.profile.Presets[0].OwnerFile} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("private report data")
		}
	}
	must(t, os.Remove(f.profile.Presets[0].OwnerFile))
	reopened, e := OpenExecutor(ctx, f.profile, false)
	must(t, e)
	defer reopened.Close()
	again, e := reopened.Restore(ctx, f.request, f.source, func(context.Context) error { t.Error("completed replay consulted active policy"); return ErrInvalid })
	must(t, e)
	if digest(again) != digest(result) {
		t.Fatal("replay changed original receipt")
	}
	state, e := reopened.admission.Status(ctx)
	must(t, e)
	if len(state.Pending) != 0 {
		t.Fatal("terminal replay leaked reservation", state)
	}
	staging, e := os.ReadDir(filepath.Join(f.profile.Directory, "staging"))
	must(t, e)
	if len(staging) != 0 {
		t.Fatal("completed replay repeated restore")
	}
	wrong := f.request
	wrong.Binding = storage.Hash([]byte("changed command"))
	if _, e = reopened.Restore(ctx, wrong, f.source, allowed); !errors.Is(e, ErrConflict) {
		t.Fatal("operation rebound", e)
	}
}

func TestRecoveryExecutorScopeQuotaAndPublicationWithdrawal(t *testing.T) {
	f := newExecutorFixture(t)
	ctx := context.Background()
	bad := f.request
	bad.Preset = storage.Hash([]byte("not enrolled"))
	if _, e := f.executor.Restore(ctx, bad, f.source, allowed); !errors.Is(e, ErrInvalid) {
		t.Fatal("unknown preset accepted", e)
	}
	active := true
	denied := errors.New("owner withdrew restore")
	check := func(ctx context.Context) error {
		if !active {
			return denied
		}
		return ctx.Err()
	}
	f.executor.Fault = func(point string) error {
		if point == "recovery-before-publish" {
			active = false
		}
		return nil
	}
	if _, e := f.executor.Restore(ctx, f.request, f.source, check); !errors.Is(e, denied) {
		t.Fatal("withdrawn publication accepted", e)
	}
	if _, e := os.Lstat(filepath.Join(f.profile.Directory, "results", f.request.Operation)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("withdrawn bundle published", e)
	}
	state, e := f.source.Status(ctx)
	must(t, e)
	if len(state.Pins) != 1 {
		t.Fatal("pending restore lost source protection")
	}
	staging, e := os.ReadDir(filepath.Join(f.profile.Directory, "staging"))
	must(t, e)
	if len(staging) != 1 {
		t.Fatal("failed attempt discarded")
	}
	f.executor.Fault = nil
	active = true
	_, e = f.executor.Restore(ctx, f.request, f.source, check)
	must(t, e)
	staging, e = os.ReadDir(filepath.Join(f.profile.Directory, "staging"))
	must(t, e)
	if len(staging) != 1 {
		t.Fatal("old attempt erased or replayed in place")
	}
	state, e = f.source.Status(ctx)
	must(t, e)
	if len(state.Pins) != 0 {
		t.Fatal("completed retry retained pin")
	}
	quota := newExecutorFixture(t)
	put(t, quota.profile.Directory, "retained-unrelated", bytes.Repeat([]byte{4}, 12<<20))
	if _, e = quota.executor.Restore(ctx, quota.request, quota.source, allowed); !errors.Is(e, ErrCapacity) {
		t.Fatal("output capacity ignored", e)
	}
	state, e = quota.source.Status(ctx)
	must(t, e)
	if len(state.Pins) != 0 {
		t.Fatal("output denial leaked an unrecorded pin")
	}
	results, e := os.ReadDir(filepath.Join(quota.profile.Directory, "results"))
	must(t, e)
	if len(results) != 0 {
		t.Fatal("quota denial published output")
	}
}

func TestRecoveryExecutorExistingUnknownOutputAndProfileChangeFailClosed(t *testing.T) {
	f := newExecutorFixture(t)
	ctx := context.Background()
	existing := filepath.Join(f.profile.Directory, "results", f.request.Operation)
	must(t, os.Mkdir(existing, 0700))
	put(t, existing, "unrelated", []byte("keep"))
	if _, e := f.executor.Restore(ctx, f.request, f.source, allowed); !errors.Is(e, ErrConflict) {
		t.Fatal("unknown output accepted", e)
	}
	staging, e := os.ReadDir(filepath.Join(f.profile.Directory, "staging"))
	must(t, e)
	if len(staging) != 0 {
		t.Fatal("unknown output caused writes")
	}
	changed := f.profile
	changed.Presets = append([]Preset(nil), changed.Presets...)
	changed.Presets[0].OwnerFile = filepath.Join(filepath.Dir(changed.Presets[0].OwnerFile), "other-key")
	if x, e := OpenExecutor(ctx, changed, false); !errors.Is(e, ErrConflict) {
		if x != nil {
			x.Close()
		}
		t.Fatal("local profile replaced without migration", e)
	}
	b, e := os.ReadFile(filepath.Join(existing, "unrelated"))
	must(t, e)
	if string(b) != "keep" {
		t.Fatal("unknown output modified")
	}
}

func TestRecoveryExecutorCommitGateWithdrawalAndTerminalCleanup(t *testing.T) {
	f := newExecutorFixture(t)
	ctx := context.Background()
	denied := errors.New("withdrawn")
	_, e := f.executor.RestoreCommitted(ctx, f.request, f.source, allowed, func(context.Context, func() error) error { return denied })
	if !errors.Is(e, denied) {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(f.profile.Directory, "results", f.request.Operation)); !os.IsNotExist(e) {
		t.Fatal("denied publication exposed output", e)
	}
	state, e := f.source.Status(ctx)
	must(t, e)
	if len(state.Pins) != 1 {
		t.Fatal("interrupted source pin lost")
	}
	must(t, f.executor.Stop(ctx, f.request, f.source))
	must(t, f.executor.Stop(ctx, f.request, f.source))
	state, e = f.source.Status(ctx)
	must(t, e)
	if len(state.Pins) != 0 {
		t.Fatal("stopped source pin retained")
	}
	if _, e = f.executor.Restore(ctx, f.request, f.source, allowed); !errors.Is(e, ErrStopped) {
		t.Fatal("terminal restore restarted", e)
	}
	retained, e := os.ReadDir(filepath.Join(f.profile.Directory, "staging"))
	must(t, e)
	if len(retained) != 1 {
		t.Fatal("cleanup deleted data")
	}
}
