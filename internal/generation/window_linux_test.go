package generation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerificationWindowRestartsFreshPerOperationAndKeepsOriginalAge(t *testing.T) {
	base := temp(t)
	tt, key, _ := trust(t)
	dir := filepath.Join(base, "replica")
	r := openTest(t, dir, tt)
	raw, objects := synthetic(t, tt, key, 1, "window")
	id, e := r.Begin(ctx, raw)
	ok(t, e)
	for name, b := range objects {
		ok(t, r.Put(ctx, id, name, b))
	}
	window := Hash([]byte("first operation"))
	first, e := r.VerifyWindow(ctx, id, window, 1, MaxObject)
	ok(t, e)
	if first.Complete || first.VerifiedObjects != 1 || first.ReadBytes == 0 {
		t.Fatal("wrong bounded result", first)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != "" {
		t.Fatal("partial window published")
	}
	firstAt := time.Now().Unix()
	time.Sleep(1100 * time.Millisecond)
	ok(t, r.Close())
	r, e = Open(dir, tt, false)
	ok(t, e)
	defer r.Close()
	second, e := r.VerifyWindow(ctx, id, window, 1, MaxObject)
	ok(t, e)
	var bytes int64
	for _, b := range objects {
		bytes += int64(len(b))
	}
	if !second.Complete || first.ReadBytes+second.ReadBytes != bytes || second.VerifiedAt > firstAt {
		t.Fatal("resume reread or replaced observation", first, second)
	}
	replay, e := r.VerifyWindow(ctx, id, window, 1, MaxObject)
	ok(t, e)
	if !replay.Complete || replay.ReadBytes != 0 || replay.VerifiedAt != second.VerifiedAt {
		t.Fatal("replay invented fresh proof", replay)
	}
	fresh, e := r.VerifyWindow(ctx, id, Hash([]byte("new operation")), 2, MaxObject)
	ok(t, e)
	if !fresh.Complete || fresh.ReadBytes != bytes || fresh.VerifiedAt <= second.VerifiedAt {
		t.Fatal("new operation borrowed old evidence", fresh)
	}
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = r.VerifyWindow(stopped, id, window, 1, MaxObject); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel ignored", e)
	}
}

func TestVerificationWindowCannotAdmitHistoryOrResurrectRetiredGeneration(t *testing.T) {
	tt, key, maintenance := trust(t)
	r := openTest(t, filepath.Join(temp(t), "replica"), tt)
	latest, objects := synthetic(t, tt, key, 7, "latest")
	head, e := r.Receive(ctx, latest, fetch(objects))
	ok(t, e)
	old, prior := synthetic(t, tt, key, 2, "prior")
	id := Hash(old)
	window := Hash([]byte("history operation"))
	if _, e = r.VerifyWindow(ctx, id, window, 2, MaxObject); e == nil {
		t.Fatal("unadmitted history verified")
	}
	_, e = r.BeginHistorical(ctx, old)
	ok(t, e)
	for name, b := range prior {
		ok(t, r.Put(ctx, id, name, b))
	}
	result, e := r.VerifyWindow(ctx, id, window, 2, MaxObject)
	ok(t, e)
	if !result.Complete {
		t.Fatal(result)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != head || status.HighestSequence != 7 {
		t.Fatal("history changed head")
	}
	_, e = r.Maintain(ctx, permit(t, r, maintenance, id))
	ok(t, e)
	if _, e = r.VerifyWindow(ctx, id, window, 2, MaxObject); e == nil {
		t.Fatal("retired generation resurrected")
	}
	ok(t, r.VerifyComplete(ctx, head))
}

func TestVerificationWindowMetadataPresenceNeverCertifiesCorruption(t *testing.T) {
	tt, key, _ := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	raw, objects := synthetic(t, tt, key, 1, "corrupt")
	id, e := r.Receive(ctx, raw, fetch(objects))
	ok(t, e)
	window := Hash([]byte("check"))
	_, e = r.VerifyWindow(ctx, id, window, 2, MaxObject)
	ok(t, e)
	refs, e := Dependencies(raw, tt)
	ok(t, e)
	victim := refs[0]
	bad := append([]byte(nil), objects[victim.ID]...)
	bad[0] ^= 1
	ok(t, os.WriteFile(filepath.Join(dir, "objects", victim.ID), bad, 0600))
	missing, e := r.MissingMetadata(ctx, id)
	ok(t, e)
	if len(missing) != 0 {
		t.Fatal("same-size object was absent")
	}
	if _, e = r.VerifyWindow(ctx, id, window, 2, MaxObject); !errors.Is(e, ErrIncomplete) {
		t.Fatal("stamp change hid corruption", e)
	}
	if _, e = r.Missing(ctx, id); e == nil {
		t.Fatal("legacy full check weakened")
	}
	ok(t, os.WriteFile(filepath.Join(dir, "objects", victim.ID), bad[:1], 0600))
	if _, e = r.MissingMetadata(ctx, id); e == nil {
		t.Fatal("wrong size accepted")
	}
	checkpoint := filepath.Join(dir, "verification", verificationName(id, window))
	ok(t, os.WriteFile(checkpoint, []byte("{}"), 0600))
	if _, e = r.VerifyWindow(ctx, id, window, 2, MaxObject); !errors.Is(e, ErrInvalid) {
		t.Fatal("malformed window ignored", e)
	}
	kept, e := os.ReadFile(checkpoint)
	ok(t, e)
	if string(kept) != "{}" {
		t.Fatal("malformed checkpoint replaced")
	}
}
