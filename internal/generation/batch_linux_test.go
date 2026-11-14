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

func TestBatchedReceptionSyncsParentUntilFirstCheckpointIsDurable(t *testing.T) {
	dir := filepath.Join(temp(t), "replica")
	trust, key, _ := trust(t)
	r := openTest(t, dir, trust)
	raw, objects := synthetic(t, trust, key, 1, "parent")
	interrupted := errors.New("stop before first verification checkpoint")
	parentSyncs := 0
	fault := func(point string) error {
		if point == "verification-directory-durable" {
			parentSyncs++
			if parentSyncs == 1 {
				return interrupted
			}
		}
		return nil
	}
	r.Fault = fault
	if _, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects)); !errors.Is(err, interrupted) {
		t.Fatalf("first checkpoint boundary not reached: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "verification", Hash(raw))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkpoint exists before its first write: %v", err)
	}
	ok(t, r.Close())

	r, err := Open(dir, trust, false)
	ok(t, err)
	r.Fault = fault
	first, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
	ok(t, err)
	if first.Complete || first.VerifiedObjects != 1 || parentSyncs != 2 {
		t.Fatalf("missing checkpoint did not repeat parent sync: %+v, syncs=%d", first, parentSyncs)
	}
	ok(t, r.Close())

	r, err = Open(dir, trust, false)
	ok(t, err)
	defer r.Close()
	r.Fault = fault
	final, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
	ok(t, err)
	if !final.Complete || final.VerifiedObjects != 2 || parentSyncs != 2 {
		t.Fatalf("durable checkpoint repeated parent sync or failed to publish: %+v, syncs=%d", final, parentSyncs)
	}
	ok(t, r.VerifyComplete(ctx, Hash(raw)))
}

func TestPublicationEstimateCreditsOnlyCurrentCompleteVerification(t *testing.T) {
	dir := filepath.Join(temp(t), "replica")
	trust, key, _ := trust(t)
	r := openTest(t, dir, trust)
	raw, objects := synthetic(t, trust, key, 1, "capacity-proof")
	refs, err := Dependencies(raw, trust)
	ok(t, err)

	interrupted := errors.New("stop before index publication")
	r.Fault = func(point string) error {
		if point == "before-complete" {
			return interrupted
		}
		return nil
	}
	if _, err = r.ReceiveBatch(ctx, raw, 2, MaxObject, fetch(objects)); !errors.Is(err, interrupted) {
		t.Fatalf("did not stop after the durable verification checkpoint: %v", err)
	}
	estimate, err := r.EstimatePublication(ctx, raw, refs)
	ok(t, err)
	if len(estimate.MetadataSizes) != 1 || estimate.MetadataSizes[0] <= 0 || len(estimate.ObjectSizes) != 0 {
		t.Fatalf("expected only the remaining index allocation: %+v", estimate)
	}
	stale := time.Unix(42, 0)
	ok(t, os.Chtimes(filepath.Join(dir, "objects", refs[0].ID), stale, stale))
	estimate, err = r.EstimatePublication(ctx, raw, refs)
	ok(t, err)
	if len(estimate.MetadataSizes) != 3 || len(estimate.ObjectSizes) != 0 {
		t.Fatalf("changed stamp did not restore the verification allocation: %+v", estimate)
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
