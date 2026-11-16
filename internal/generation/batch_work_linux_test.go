package generation

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func batchWorkCatalog(t *testing.T, tt Trust, key ed25519.PrivateKey, seq uint64, marker string, count int) ([]byte, map[string][]byte) {
	t.Helper()
	root := []byte("opaque batch-work kit " + marker)
	objects := map[string][]byte{Hash(root): root}
	kit := Kit{File: Hash([]byte("batch-work file")), Version: Hash([]byte(marker)), Root: Object{Hash(root), len(root)}}
	for i := 0; i < count; i++ {
		data := []byte(fmt.Sprintf("ciphertext %s %04d", marker, i))
		objects[Hash(data)] = data
		kit.Objects = append(kit.Objects, Object{Hash(data), len(data)})
	}
	sort.Slice(kit.Objects, func(i, j int) bool { return kit.Objects[i].ID < kit.Objects[j].ID })
	c := Catalog{Format: Format, Domain: tt.Domain, Repository: tt.Repository, Epoch: tt.Epoch, Sequence: seq,
		SnapshotUnix: 1, Policy: 1, KitFormat: KitFormat, Kits: []Kit{kit}}
	if seq > 1 {
		c.Parent = Hash([]byte("trusted prior checkpoint"))
	}
	raw, err := SignCatalog(c, key)
	ok(t, err)
	return raw, objects
}

func TestBatchedVerificationStampWorkIsLinear(t *testing.T) {
	tt, key, _ := trust(t)
	r := openTest(t, filepath.Join(temp(t), "replica"), tt)
	raw, objects := batchWorkCatalog(t, tt, key, 1, "linear", 64)
	id, err := r.Begin(ctx, raw)
	ok(t, err)
	var total int64
	for object, data := range objects {
		ok(t, r.Put(ctx, id, object, data))
		total += int64(len(data))
	}
	checks := 0
	r.Fault = func(point string) error {
		if point == "verification-object-stamp" {
			checks++
		}
		return nil
	}
	var read int64
	var final BatchResult
	steps := 0
	for ; steps <= len(objects); steps++ {
		step, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, func(Object) ([]byte, error) {
			t.Fatal("prepopulated ciphertext was fetched again")
			return nil, ErrIncomplete
		})
		ok(t, err)
		read += step.ReadBytes
		if step.WrittenBytes != 0 || (steps+1 < len(objects) && step.Complete) {
			t.Fatal("unexpected copy or early completion", steps, step)
		}
		if step.Complete {
			final = step
			steps++
			break
		}
	}
	if !final.Complete || steps != len(objects) || read != total {
		t.Fatal("bounded batches did not verify every payload exactly once", steps, read, total, final)
	}
	replay, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
	ok(t, err)
	if !replay.Complete || replay.ReadBytes != 0 || replay.VerifiedAt != final.VerifiedAt {
		t.Fatal("completed replay lost its original proof", replay, final)
	}
	r.Fault = nil
	ok(t, r.VerifyComplete(ctx, id))
	t.Logf("BATCH_STAMP_WORK objects=%d steps=%d stampChecks=%d readBytes=%d fullScrub=PASS", len(objects), steps, checks, read)
	if checks > 3*len(objects) {
		t.Fatalf("verified prefix stamp work is not linear: got %d checks for %d objects", checks, len(objects))
	}
}

func TestBatchedFinalStampInvalidationIsDurableBeforePublication(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt=%t", corrupt), func(t *testing.T) {
			tt, key, _ := trust(t)
			dir := filepath.Join(temp(t), "replica")
			r := openTest(t, dir, tt)
			old, oldObjects := synthetic(t, tt, key, 1, "prior-good")
			oldID, err := r.Receive(ctx, old, fetch(oldObjects))
			ok(t, err)
			raw, objects := batchWorkCatalog(t, tt, key, 2, "changed-during-final-batch", 3)
			id, err := r.Begin(ctx, raw)
			ok(t, err)
			refs, err := Dependencies(raw, tt)
			ok(t, err)
			victim, missing := refs[0], refs[len(refs)-1]
			for _, ref := range refs[:len(refs)-1] {
				ok(t, r.Put(ctx, id, ref.ID, objects[ref.ID]))
				step, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
				ok(t, err)
				if step.Complete {
					t.Fatal("unfinished fixture completed", step)
				}
			}
			step, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, func(ref Object) ([]byte, error) {
				if ref != missing {
					t.Fatal("unexpected final fetch", ref)
				}
				data := append([]byte(nil), objects[victim.ID]...)
				if corrupt {
					data[0] ^= 1
				}
				// A new inode invalidates the old proof even when bytes are equal.
				replacement := filepath.Join(dir, "replacement")
				ok(t, os.WriteFile(replacement, data, 0600))
				ok(t, os.Rename(replacement, filepath.Join(dir, "objects", victim.ID)))
				return objects[ref.ID], nil
			})
			if !errors.Is(err, ErrIncomplete) || step.Complete {
				t.Fatal("final stamp change was not rejected", step, err)
			}
			stored, err := os.ReadFile(filepath.Join(dir, "verification", id))
			ok(t, err)
			var proof verificationState
			ok(t, json.Unmarshal(stored, &proof))
			if _, exists := proof.Objects[victim.ID]; exists || proof.CompletedAt != 0 {
				t.Fatal("invalidated proof remained durable", proof.CompletedAt, exists)
			}
			status, err := r.Status(ctx)
			ok(t, err)
			if status.LatestComplete != oldID {
				t.Fatal("invalidated candidate changed the previous complete head", status)
			}
			ok(t, r.Close())
			r, err = Open(dir, tt, false)
			ok(t, err)
			defer r.Close()
			retry, err := r.ReceiveBatch(ctx, raw, 1, MaxObject, fetch(objects))
			if corrupt {
				if !errors.Is(err, ErrIncomplete) || retry.Complete {
					t.Fatal("reopened progress trusted changed ciphertext", retry, err)
				}
			} else {
				ok(t, err)
				if !retry.Complete || retry.ReadBytes != int64(victim.Bytes) || retry.WrittenBytes != 0 {
					t.Fatal("unchanged replacement was not reverified without refetch", retry)
				}
				ok(t, r.VerifyComplete(ctx, id))
			}
			ok(t, r.VerifyComplete(ctx, oldID))
		})
	}
}
