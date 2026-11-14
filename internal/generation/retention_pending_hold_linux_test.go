package generation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionReleaseFencesUndeliveredHoldAcrossRestart(t *testing.T) {
	trust, writer, maintenance := trust(t)
	base := temp(t)
	path := filepath.Join(base, "holder")
	holder := openTest(t, path, trust)
	retiring := openTest(t, filepath.Join(base, "retiring"), trust)
	_, holderKey, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	_, retiringKey, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	holder.setIndexKey(holderKey)
	retiring.setIndexKey(retiringKey)
	raw, objects := synthetic(t, trust, writer, 1, "late hold")
	id, e := holder.Receive(ctx, raw, fetch(objects))
	ok(t, e)
	now := time.Now().Unix()
	protection := RetentionProtection{
		Format: RetentionProtectionFormat, Domain: trust.Domain, Repository: trust.Repository,
		Epoch: trust.Epoch, NotBefore: now - 60, ExpiresUnix: now + 300,
	}
	sign := func(g RetentionProtection) []byte {
		t.Helper()
		raw, e := SignRetentionProtection(g, maintenance)
		ok(t, e)
		return raw
	}
	expect := func(e, want error) {
		t.Helper()
		if !errors.Is(e, want) {
			t.Fatalf("got %v, want %v", e, want)
		}
	}

	closeGrant := protection
	closeGrant.Node, closeGrant.Operation, closeGrant.Action = retiring.indexNode, Hash([]byte("retire")), "CLOSE"
	closure, e := retiring.ApplyRetentionProtection(ctx, sign(closeGrant), nil)
	ok(t, e)
	hold := protection
	hold.Node, hold.Operation, hold.Generation, hold.Action = holder.indexNode, Hash([]byte("pending")), id, "HOLD"
	hold.Retirement = &RetirementBinding{Node: retiring.indexNode, Operation: closeGrant.Operation}
	holdRaw := sign(hold)
	release := hold
	release.Action, release.HoldDigest, release.Closure = "RELEASE", Hash(holdRaw), &closure
	_, e = holder.ApplyRetentionProtection(ctx, sign(release), nil)
	expect(e, ErrConflict)

	forged := release
	forged.PendingHold, e = SignRetentionProtection(hold, writer)
	ok(t, e)
	forged.HoldDigest = Hash(forged.PendingHold)
	_, e = SignRetentionProtection(forged, maintenance)
	expect(e, ErrInvalid)
	// Validate an independently encoded outer signature, not just the signer.
	unsigned, e := json.Marshal(forged)
	ok(t, e)
	forged.Signature = ed25519.Sign(maintenance, append([]byte(RetentionProtectionFormat+"\x00"), unsigned...))
	forgedRaw, e := json.Marshal(forged)
	ok(t, e)
	_, e = holder.ApplyRetentionProtection(ctx, forgedRaw, nil)
	expect(e, ErrInvalid)
	mismatched := release
	mismatched.PendingHold = holdRaw
	mismatched.Operation = Hash([]byte("unrelated hold"))
	_, e = SignRetentionProtection(mismatched, maintenance)
	expect(e, ErrInvalid)

	// A release-only record must never remove an ordinary pin.
	pin := retentionPin(hold.Operation)
	ok(t, holder.Pin(ctx, pin, id, "restore"))
	ok(t, holder.EnableIndexCopy(ctx))
	release.PendingHold = holdRaw
	releaseRaw := sign(release)
	holder.Fault = func(point string) error {
		if point == "state-durable" {
			return ioFailure
		}
		return nil
	}
	_, e = holder.ApplyRetentionProtection(ctx, releaseRaw, nil)
	expect(e, ioFailure)
	ok(t, holder.Close())
	holder, e = OpenWorkerAt(nil, path, trust, false, holderKey)
	ok(t, e)
	defer holder.Close()

	first, e := holder.ApplyRetentionProtection(ctx, releaseRaw, nil)
	ok(t, e)
	replay, e := holder.ApplyRetentionProtection(ctx, releaseRaw, nil)
	ok(t, e)
	firstRaw, e := json.Marshal(first)
	ok(t, e)
	replayRaw, e := json.Marshal(replay)
	ok(t, e)
	if !bytes.Equal(firstRaw, replayRaw) || first.State != "RELEASED" || first.HoldDigest != Hash(holdRaw) {
		t.Fatal("release-only receipt changed", first, replay)
	}
	_, e = VerifyRetentionProtectionReceipt(replayRaw, holder.indexNode)
	ok(t, e)
	_, e = holder.ApplyRetentionProtection(ctx, holdRaw, nil)
	expect(e, ErrConflict)
	s, e := holder.Status(ctx)
	ok(t, e)
	if s.Revision != first.Revision || s.Pins[pin] != (Pin{Generation: id, Kind: "restore"}) || len(s.Pins) != 1 {
		t.Fatal("fence changed the original receipt or removed an ordinary pin", s)
	}
	ok(t, holder.VerifyComplete(ctx, id))
	ok(t, holder.ReleasePin(ctx, pin))
	_, e = holder.ApplyRetentionProtection(ctx, holdRaw, nil)
	expect(e, ErrConflict)

	ok(t, holder.Close())
	ok(t, os.Remove(filepath.Join(path, "state.json")))
	recovered, e := RecoverIndexCopyAt(nil, ctx, path, trust, holderKey, nil)
	ok(t, e)
	if !recovered {
		t.Fatal("missing index was not recovered")
	}
	holder, e = OpenWorkerAt(nil, path, trust, false, holderKey)
	ok(t, e)
	defer holder.Close()
	_, e = holder.ApplyRetentionProtection(ctx, holdRaw, nil)
	expect(e, ErrConflict)

	// A delayed release with the original grant also works if HOLD won first.
	hold.Operation = Hash([]byte("already held"))
	holdRaw = sign(hold)
	_, e = holder.ApplyRetentionProtection(ctx, holdRaw, nil)
	ok(t, e)
	release.Operation, release.HoldDigest, release.PendingHold = hold.Operation, Hash(holdRaw), holdRaw
	_, e = holder.ApplyRetentionProtection(ctx, sign(release), nil)
	ok(t, e)
	s, e = holder.Status(ctx)
	ok(t, e)
	if _, pinned := s.Pins[retentionPin(hold.Operation)]; pinned {
		t.Fatal("release did not clear the previously committed hold")
	}
	_, e = holder.ApplyRetentionProtection(ctx, holdRaw, nil)
	expect(e, ErrConflict)
}
