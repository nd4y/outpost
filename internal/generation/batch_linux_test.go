package generation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBatchedReceptionRestartsWithoutRepeatingVerifiedPayload(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	raw, objects := synthetic(t, trust, key, 1, "batch")
	first, e := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
	ok(t, e)
	if first.Complete || first.VerifiedObjects != 1 || first.TotalObjects != 2 || first.WrittenBytes == 0 {
		t.Fatal("unbounded/early first batch", first)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != "" {
		t.Fatal("partial batch published")
	}
	ok(t, r.Close())
	r, e = Open(filepath.Join(base, "replica"), trust, false)
	ok(t, e)
	defer r.Close()
	second, e := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
	ok(t, e)
	if !second.Complete || second.VerifiedObjects != 2 {
		t.Fatal("not complete", second)
	}
	var total int64
	for _, b := range objects {
		total += int64(len(b))
	}
	if first.ReadBytes+second.ReadBytes != total || first.WrittenBytes+second.WrittenBytes != total {
		t.Fatal("repeated verified payload", first, second, total)
	}
	ok(t, r.VerifyComplete(ctx, Hash(raw)))
}
func TestBatchedReceptionInvalidatesChangedObjectAndPreservesPreviousComplete(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	old, oldObjects := synthetic(t, trust, key, 1, "old")
	oldID, e := r.Receive(ctx, old, fetch(oldObjects))
	ok(t, e)
	raw, objects := synthetic(t, trust, key, 2, "new")
	first, e := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
	ok(t, e)
	if first.Complete {
		t.Fatal("first batch complete")
	}
	refs, e := Dependencies(raw, trust)
	ok(t, e)
	victim := refs[0]
	name := filepath.Join(base, "replica/objects", victim.ID)
	info, e := os.Stat(name)
	ok(t, e)
	time.Sleep(20 * time.Millisecond)
	bad := append([]byte(nil), objects[victim.ID]...)
	bad[0] ^= 1
	ok(t, os.WriteFile(name, bad, 0600))
	ok(t, os.Chtimes(name, info.ModTime(), info.ModTime()))
	if _, e = r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects)); !errors.Is(e, ErrIncomplete) {
		t.Fatal("changed stamp hid corruption", e)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != oldID {
		t.Fatal("lost previous good generation")
	}
	ok(t, r.VerifyComplete(ctx, oldID))
}
func TestBatchedReceptionDurableProgressFaultAndCancellation(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	raw, objects := synthetic(t, trust, key, 1, "fault")
	r.Fault = func(point string) error {
		if point == "verification-batch-durable" {
			return errors.New("lost batch reply")
		}
		return nil
	}
	if _, e := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects)); e == nil {
		t.Fatal("fault absent")
	}
	ok(t, r.Close())
	r, e := Open(filepath.Join(base, "replica"), trust, false)
	ok(t, e)
	defer r.Close()
	result, e := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
	ok(t, e)
	if !result.Complete {
		t.Fatal("durable batch was lost")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = r.ReceiveBatch(cancelled, raw, 1, MaxObject, fetch(objects)); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation ignored", e)
	}
}

func TestBatchedReplayKeepsRecordedVerificationTimeAndChecksChangedStamps(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	raw, objects := synthetic(t, trust, key, 1, "time")
	first, e := r.ReceiveBatch(ctx, raw, 2, MaxObject, fetch(objects))
	ok(t, e)
	if !first.Complete || first.VerifiedAt <= 0 {
		t.Fatal("missing verification time")
	}
	time.Sleep(1100 * time.Millisecond)
	second, e := r.ReceiveBatch(ctx, raw, 2, MaxObject, fetch(objects))
	ok(t, e)
	if !second.Complete || second.VerifiedAt != first.VerifiedAt || second.ReadBytes != 0 {
		t.Fatal("replay invented fresh verification", first, second)
	}
	refs, e := Dependencies(raw, trust)
	ok(t, e)
	victim := refs[0]
	bad := append([]byte(nil), objects[victim.ID]...)
	bad[0] ^= 1
	ok(t, os.WriteFile(filepath.Join(base, "replica/objects", victim.ID), bad, 0600))
	if _, e = r.ReceiveBatch(ctx, raw, 2, MaxObject, fetch(objects)); !errors.Is(e, ErrIncomplete) {
		t.Fatal("complete replay ignored changed object", e)
	}
}
