package sourceagent

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

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWriterFencePreservesOldCheckpointAndBlocksNewCaptureAfterRestart(t *testing.T) {
	ctx := context.Background()
	old := newFixture(t)
	must(t, old.a.Next(ctx))
	must(t, old.a.Run(ctx))
	oldCheckpoint, e := old.a.Checkpoint(ctx)
	must(t, e)
	previous, e := capture.VerifyCheckpoint(oldCheckpoint, old.grant.Trust)
	must(t, e)
	owner, e := filekit.NewOwner()
	must(t, e)
	writer, writerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	maintenance, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("new repository")), Epoch: 2, Writer: writer, Maintenance: maintenance}
	preparation := recoverybundle.EpochPreparation{
		Format: recoverybundle.EpochPreparationFormat, State: "PREPARED", Actor: storage.Hash(old.b.Local.Owner),
		Operation: storage.Hash([]byte("new epoch")), Reason: "scheduled-rotation", CreatedUnix: time.Now().Unix(), Trust: trust,
		Prior: &recoverybundle.PriorEpoch{Domain: previous.Domain, Repository: previous.Repository, Epoch: previous.Epoch, Generation: previous.Generation,
			VerifiedUnix: previous.Copies[0].ObservedUnix, PackageSHA256: storage.Hash([]byte("prior synthetic package"))},
	}
	unsigned, e := json.Marshal(preparation)
	must(t, e)
	preparation.Signature = ed25519.Sign(old.ownerSigner, append([]byte(recoverybundle.EpochPreparationFormat+"\x00"), unsigned...))
	prepared, e := json.Marshal(preparation)
	must(t, e)
	newSource := newFixtureWithKeys(t, 1800, nil, &fixtureEpoch{owner: owner, trust: trust, writer: writerKey})
	newContent := bytes.Repeat([]byte("successor"), 8192)
	must(t, os.WriteFile(filepath.Join(newSource.tree, "private.bin"), newContent, 0640))
	must(t, newSource.a.Next(ctx))
	must(t, newSource.a.Run(ctx))
	successor, e := newSource.a.Checkpoint(ctx)
	must(t, e)
	current, e := capture.VerifyCheckpoint(successor, trust)
	must(t, e)
	newSource.server.Close()
	must(t, newSource.a.Close())
	newSource.a = nil
	out := filepath.Join(newSource.base, "successor-restore")
	_, e = generation.RecoverMaterialized(ctx, newSource.replicaPath, current.Generation, trust, owner, generation.RecoverySelection{}, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "private.bin"))
	must(t, e)
	if !bytes.Equal(got, newContent) {
		t.Fatal("successor restore changed bytes")
	}
	now := time.Now()
	fence := WriterFence{Format: WriterFenceFormat, Operation: storage.Hash([]byte("fence old writer")), Source: old.grant.Source,
		Profile: old.grant.Profile, PreviousCheckpoint: storage.Hash(oldCheckpoint), Preparation: prepared,
		SuccessorCheckpoint: successor, RestoreEvidence: storage.Hash(got), NotBefore: now.Unix() - 1, ExpiresUnix: now.Add(time.Hour).Unix()}
	invalid := fence
	invalid.SuccessorCheckpoint = oldCheckpoint
	if _, e = SignWriterFence(invalid, old.ownerSigner, now); !errors.Is(e, ErrInvalid) {
		t.Fatal("old checkpoint was accepted as successor evidence", e)
	}
	invalid = fence
	invalid.PreviousCheckpoint = storage.Hash([]byte("stale prior head"))
	stale, e := SignWriterFence(invalid, old.ownerSigner, now)
	must(t, e)
	if _, e = old.a.FenceWriter(ctx, stale); !errors.Is(e, ErrInvalid) {
		t.Fatal("fence for another head was accepted", e)
	}
	signed, e := SignWriterFence(fence, old.ownerSigner, now)
	must(t, e)
	old.server.Close()
	receipt, e := old.a.FenceWriter(ctx, signed)
	must(t, e)
	old.reopen(t)
	status, e := old.a.Status(ctx)
	must(t, e)
	if status.WriterFence == nil || *status.WriterFence != receipt {
		t.Fatal("writer fence was lost on reopen", status)
	}
	repeated, e := old.a.FenceWriter(ctx, signed)
	must(t, e)
	if repeated != receipt {
		t.Fatal("replayed fence changed the original receipt")
	}
	for _, action := range []func() error{
		func() error { return old.a.Next(ctx) },
		func() error { return old.a.Prepare(ctx, old.intent(t, previous.Sequence+1, previous.Generation)) },
		func() error { return old.a.Run(ctx) },
		func() error { return old.a.RunSchedule(ctx) },
		func() error { _, err := old.a.Renew(ctx, old.authority, nil); return err },
	} {
		if e = action(); !errors.Is(e, ErrWriterFenced) {
			t.Fatal("retired writer can still start or run work", e)
		}
	}
	again, e := old.a.Checkpoint(ctx)
	must(t, e)
	if !bytes.Equal(again, oldCheckpoint) {
		t.Fatal("fence rewrote historical recovery proof")
	}
	_, e = generation.RecoverMaterialized(ctx, old.replicaPath, previous.Generation, old.grant.Trust, old.owner, generation.RecoverySelection{}, filepath.Join(old.base, "old-restore"))
	must(t, e)
}
