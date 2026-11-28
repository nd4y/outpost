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

func TestRetentionProtectionSurvivesLostReplyAndBlocksRetirement(t *testing.T) {
	trust, writer, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, trust)
	_, nodeKey, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	r.setIndexKey(nodeKey)
	one, objects := synthetic(t, trust, writer, 1, "held")
	id, e := r.Receive(ctx, one, fetch(objects))
	ok(t, e)
	two, newer := synthetic(t, trust, writer, 2, "new")
	_, e = r.Receive(ctx, two, fetch(newer))
	ok(t, e)

	grant := RetentionProtection{
		Format: RetentionProtectionFormat, Node: r.indexNode, Domain: trust.Domain, Repository: trust.Repository,
		Epoch: trust.Epoch, Operation: Hash([]byte("retention operation")), Generation: id, Action: "HOLD",
		NotBefore: time.Now().Add(-time.Minute).Unix(), ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}
	sign := func(p RetentionProtection, key ed25519.PrivateKey) []byte {
		t.Helper()
		raw, e := SignRetentionProtection(p, key)
		ok(t, e)
		return raw
	}
	requireError := func(e, want error) {
		t.Helper()
		if !errors.Is(e, want) {
			t.Fatalf("got %v, want %v", e, want)
		}
	}
	checkReceipt := func(receipt RetentionProtectionReceipt, state string, raw []byte) []byte {
		t.Helper()
		if receipt.State != state || receipt.Generation != id || receipt.HoldDigest != Hash(sign(grant, maintenance)) ||
			receipt.GrantDigest != Hash(raw) {
			t.Fatalf("unexpected receipt %+v", receipt)
		}
		encoded, e := json.Marshal(receipt)
		ok(t, e)
		_, e = VerifyRetentionProtectionReceipt(encoded, grant.Node)
		ok(t, e)
		_, e = VerifyRetentionProtectionReceipt(encoded, Hash([]byte("different node")))
		requireError(e, ErrInvalid)
		return encoded
	}

	stalePermit := permit(t, r, maintenance, id)
	hold := sign(grant, maintenance)
	wrongNode := grant
	wrongNode.Node = Hash([]byte("different node"))
	_, e = r.ApplyRetentionProtection(ctx, sign(wrongNode, maintenance), nil)
	requireError(e, ErrInvalid)
	expired := grant
	expired.NotBefore, expired.ExpiresUnix = grant.NotBefore-60, grant.NotBefore
	_, e = r.ApplyRetentionProtection(ctx, sign(expired, maintenance), nil)
	requireError(e, ErrMaintenanceWindow)
	_, e = r.ApplyRetentionProtection(ctx, hold, func(func() error) error { return ioFailure })
	requireError(e, ioFailure)
	r.Fault = func(point string) error {
		if point == "state-durable" {
			return ioFailure
		}
		return nil
	}
	_, e = r.ApplyRetentionProtection(ctx, hold, nil)
	requireError(e, ioFailure)
	ok(t, r.Close())
	r, e = Open(dir, trust, false)
	ok(t, e)
	defer r.Close()
	r.setIndexKey(nodeKey)

	receipt, e := r.ApplyRetentionProtection(ctx, hold, nil)
	ok(t, e)
	held := checkReceipt(receipt, "HELD", hold)
	receipt, e = r.ApplyRetentionProtection(ctx, hold, nil)
	ok(t, e)
	if !bytes.Equal(held, checkReceipt(receipt, "HELD", hold)) {
		t.Fatal("hold replay changed its receipt")
	}
	requireError(r.ReleasePin(ctx, retentionPin(grant.Operation)), ErrProtected)
	_, e = r.Maintain(ctx, stalePermit)
	requireError(e, ErrRollback)
	_, e = r.Maintain(ctx, permit(t, r, maintenance, id))
	requireError(e, ErrProtected)

	release := grant
	release.Action, release.HoldDigest = "RELEASE", Hash([]byte("wrong hold"))
	_, e = r.ApplyRetentionProtection(ctx, sign(release, maintenance), nil)
	requireError(e, ErrConflict)
	release.HoldDigest = Hash(hold)
	_, e = r.ApplyRetentionProtection(ctx, sign(release, writer), nil)
	requireError(e, ErrInvalid)
	releaseRaw := sign(release, maintenance)
	receipt, e = r.ApplyRetentionProtection(ctx, releaseRaw, nil)
	ok(t, e)
	released := checkReceipt(receipt, "RELEASED", releaseRaw)
	receipt, e = r.ApplyRetentionProtection(ctx, releaseRaw, nil)
	ok(t, e)
	if !bytes.Equal(released, checkReceipt(receipt, "RELEASED", releaseRaw)) {
		t.Fatal("release replay changed its receipt")
	}
	_, e = r.ApplyRetentionProtection(ctx, hold, nil)
	requireError(e, ErrConflict)
	removed, e := r.Maintain(ctx, permit(t, r, maintenance, id))
	ok(t, e)
	if removed == 0 {
		t.Fatal("released generation remained protected")
	}
}

func TestRetentionProtectionRejectsDamagedGeneration(t *testing.T) {
	trust, writer, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, trust)
	_, nodeKey, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	r.setIndexKey(nodeKey)
	catalog, objects := synthetic(t, trust, writer, 1, "damaged")
	id, e := r.Receive(ctx, catalog, fetch(objects))
	ok(t, e)
	for key := range objects {
		ok(t, os.WriteFile(filepath.Join(dir, "objects", key), []byte("corrupted"), 0600))
		break
	}
	now := time.Now().Unix()
	raw, e := SignRetentionProtection(RetentionProtection{
		Format: RetentionProtectionFormat, Node: r.indexNode, Domain: trust.Domain, Repository: trust.Repository,
		Epoch: trust.Epoch, Operation: Hash([]byte("retention operation")), Generation: id, Action: "HOLD",
		NotBefore: now - 60, ExpiresUnix: now + 60,
	}, maintenance)
	ok(t, e)
	before, e := r.Status(ctx)
	ok(t, e)
	if _, e = r.ApplyRetentionProtection(ctx, raw, nil); !errors.Is(e, ErrIncomplete) {
		t.Fatalf("damaged generation: %v", e)
	}
	after, e := r.Status(ctx)
	ok(t, e)
	if after.Revision != before.Revision {
		t.Fatal("failed hold changed the index")
	}
}
