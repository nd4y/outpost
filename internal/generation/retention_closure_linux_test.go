package generation

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRetentionClosureFencesPendingCleanupAndUnlocksSurvivor(t *testing.T) {
	trust, writer, maintenance := trust(t)
	base := temp(t)
	one, objects := synthetic(t, trust, writer, 1, "old")
	two, newer := synthetic(t, trust, writer, 2, "new")
	init := func(path string) (*Replica, ed25519.PrivateKey, string) {
		t.Helper()
		r := openTest(t, path, trust)
		_, key, e := ed25519.GenerateKey(rand.Reader)
		ok(t, e)
		r.setIndexKey(key)
		id, e := r.Receive(ctx, one, fetch(objects))
		ok(t, e)
		_, e = r.Receive(ctx, two, fetch(newer))
		ok(t, e)
		return r, key, id
	}
	path := filepath.Join(base, "retiring")
	retiring, retiringKey, id := init(path)
	holder, _, _ := init(filepath.Join(base, "holder"))
	neverStarted := permit(t, retiring, maintenance)
	notStarted, e := VerifyPermit(neverStarted, trust)
	ok(t, e)

	start := time.Now().Unix()
	grant := RetentionProtection{
		Format: RetentionProtectionFormat, Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch,
		NotBefore: start - 60, ExpiresUnix: start + 300,
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
	closeGrant := grant
	closeGrant.Action, closeGrant.Node, closeGrant.Operation = "CLOSE", retiring.indexNode, notStarted.Operation
	unrelatedClosure, e := retiring.ApplyRetentionProtection(ctx, sign(closeGrant), nil)
	ok(t, e)
	_, e = retiring.Maintain(ctx, neverStarted)
	expect(e, ErrRetirementClosed)
	retire := permit(t, retiring, maintenance, id)
	p, e := VerifyPermit(retire, trust)
	ok(t, e)

	hold := grant
	hold.Action, hold.Node, hold.Generation, hold.Operation = "HOLD", holder.indexNode, id, Hash([]byte("holder operation"))
	hold.Retirement = &RetirementBinding{Node: retiring.indexNode, Operation: p.Operation}
	receipt, e := holder.ApplyRetentionProtection(ctx, sign(hold), nil)
	ok(t, e)
	release := hold
	release.Action, release.HoldDigest = "RELEASE", receipt.HoldDigest
	_, e = SignRetentionProtection(release, maintenance)
	expect(e, ErrInvalid)
	unbound := release
	unbound.Retirement = nil
	_, e = holder.ApplyRetentionProtection(ctx, sign(unbound), nil)
	expect(e, ErrConflict)

	release.Closure = &unrelatedClosure
	_, e = SignRetentionProtection(release, maintenance)
	expect(e, ErrInvalid)

	retiring.Fault = func(point string) error {
		if point == "retirement-durable" {
			return ioFailure
		}
		return nil
	}
	_, e = retiring.Maintain(ctx, retire)
	expect(e, ioFailure)
	retiring.Fault = func(point string) error {
		if point == "state-durable" {
			return ioFailure
		}
		return nil
	}
	closeGrant.Operation = p.Operation
	closeRaw := sign(closeGrant)
	_, e = retiring.ApplyRetentionProtection(ctx, closeRaw, nil)
	expect(e, ioFailure)
	ok(t, retiring.Close())
	retiring, e = Open(path, trust, false)
	ok(t, e)
	defer retiring.Close()
	retiring.setIndexKey(retiringKey)

	closure, e := retiring.ApplyRetentionProtection(ctx, closeRaw, nil)
	ok(t, e)
	again, e := retiring.ApplyRetentionProtection(ctx, closeRaw, nil)
	ok(t, e)
	if closure.State != "CLOSED" || closure.Operation != p.Operation || !reflect.DeepEqual(closure, again) {
		t.Fatal("closure replay changed signed evidence")
	}
	_, e = retiring.Maintain(ctx, retire)
	expect(e, ErrRetirementClosed)
	_, e = retiring.Maintain(ctx, neverStarted)
	expect(e, ErrRetirementClosed)
	removed, e := retiring.Maintain(ctx, permit(t, retiring, maintenance))
	ok(t, e)
	if removed == 0 {
		t.Fatal("new authority did not collect the remaining unreferenced objects")
	}

	forged := closure
	forged.ObservedUnix++
	release.Closure = &forged
	_, e = SignRetentionProtection(release, maintenance)
	expect(e, ErrInvalid)
	_, e = holder.Maintain(ctx, permit(t, holder, maintenance, id))
	expect(e, ErrProtected)
	release.Closure = &closure
	final, e := holder.ApplyRetentionProtection(ctx, sign(release), nil)
	ok(t, e)
	if final.State != "RELEASED" || final.Retirement == nil || *final.Retirement != *hold.Retirement {
		t.Fatal("release lost retirement binding")
	}
	_, e = holder.Maintain(ctx, permit(t, holder, maintenance, id))
	ok(t, e)
}
