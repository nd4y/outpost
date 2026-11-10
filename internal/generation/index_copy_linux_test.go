package generation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedReplicaIndexCopyRecoversExactPinsAndReceivingAfterLoss(t *testing.T) {
	tt, writer, _ := trust(t)
	_, node, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	_, foreign, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	dir := filepath.Join(temp(t), "replica")
	ok(t, os.Mkdir(dir, 0700))
	r, e := OpenWorkerAt(nil, dir, tt, true, node)
	ok(t, e)
	defer r.Close()
	first, data := synthetic(t, tt, writer, 1, "pinned history")
	old, e := r.Receive(ctx, first, fetch(data))
	ok(t, e)
	second, latestData := synthetic(t, tt, writer, 2, "latest")
	latest, e := r.Receive(ctx, second, fetch(latestData))
	ok(t, e)
	oldPin, latestPin := Hash([]byte("old restore pin")), Hash([]byte("current kit pin"))
	ok(t, r.Pin(ctx, oldPin, old, "restore"))
	indexPath := filepath.Join(dir, "state.json")
	legacy, e := os.ReadFile(indexPath)
	ok(t, e)
	ok(t, r.EnableIndexCopy(ctx))
	copyPath := filepath.Join(dir, indexCopyName)
	stale, e := os.ReadFile(copyPath)
	ok(t, e)
	if older, e := Open(dir, tt, false); !errors.Is(e, ErrIndexRecovery) {
		if older != nil {
			older.Close()
		}
		t.Fatal("reader without the enrolled key accepted the index", e)
	}
	r.Fault = func(point string) error {
		if point == "replica-index-copy-durable" {
			return ioFailure
		}
		return nil
	}
	third, _ := synthetic(t, tt, writer, 3, "receiving")
	if _, e = r.Begin(ctx, third); !errors.Is(e, ioFailure) {
		t.Fatal("write-ahead interruption not reached", e)
	}
	if _, e = r.Status(ctx); !errors.Is(e, ErrIndexRecovery) {
		t.Fatal("divergent index admitted more work", e)
	}
	predecessor, e := os.ReadFile(indexPath)
	ok(t, e)
	ok(t, os.Remove(indexPath))
	if changed, e := RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil); changed || !errors.Is(e, ErrIndexRecovery) {
		t.Fatal("unanchored index was accepted without its live predecessor", changed, e)
	}
	ok(t, os.WriteFile(indexPath, predecessor, 0600))
	if changed, e := RecoverIndexCopyAt(nil, ctx, dir, tt, foreign, nil); changed || !errors.Is(e, ErrIndexRecovery) {
		t.Fatal("foreign node reconstructed index", changed, e)
	}
	changed, e := RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil)
	ok(t, e)
	if !changed {
		t.Fatal("copy before anchor was not recovered")
	}
	r.Fault = func(point string) error {
		if point == "replica-index-anchor-durable" {
			return ioFailure
		}
		return nil
	}
	if e = r.Pin(ctx, latestPin, latest, "kit"); !errors.Is(e, ioFailure) {
		t.Fatal("anchor interruption not reached", e)
	}
	r.Fault = nil
	ok(t, os.Remove(indexPath))
	currentCopy, e := os.ReadFile(copyPath)
	ok(t, e)
	ok(t, os.WriteFile(copyPath, stale, 0600))
	if changed, e = RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil); changed || !errors.Is(e, ErrIndexRecovery) {
		t.Fatal("stale signed copy bypassed the anchor", changed, e)
	}
	ok(t, os.WriteFile(copyPath, currentCopy, 0600))
	for id, body := range latestData {
		path := filepath.Join(dir, "objects", id)
		ok(t, os.Remove(path))
		if changed, e = RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil); changed || !errors.Is(e, ErrIncomplete) {
			t.Fatal("missing dependency was accepted", changed, e)
		}
		ok(t, os.WriteFile(path, body, 0600))
		break
	}
	changed, e = RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil)
	ok(t, e)
	if !changed {
		t.Fatal("missing index was not restored")
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != latest || status.HighestSequence != 3 || status.Pins[oldPin].Generation != old || status.Pins[latestPin].Generation != latest || len(status.Receiving) != 1 || status.Receiving[0] != Hash(third) {
		t.Fatal("protection or partial reception changed", status)
	}
	current, e := os.ReadFile(indexPath)
	ok(t, e)
	changed, e = RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil)
	ok(t, e)
	again, e := os.ReadFile(indexPath)
	ok(t, e)
	if changed || !bytes.Equal(current, again) {
		t.Fatal("duplicate recovery changed the restored index")
	}
	ok(t, r.VerifyComplete(ctx, old))
	ok(t, r.VerifyComplete(ctx, latest))
	ok(t, os.WriteFile(indexPath, legacy, 0600))
	ok(t, os.Remove(copyPath))
	if _, e = r.Status(ctx); !errors.Is(e, ErrIndexRecovery) {
		t.Fatal("surviving anchor did not reject pre-mirror index", e)
	}
}

func TestSignedReplicaIndexRecoveryRequiresFrozenMaintenancePlan(t *testing.T) {
	tt, writer, maintenance := trust(t)
	_, node, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	dir := filepath.Join(temp(t), "replica")
	ok(t, os.Mkdir(dir, 0700))
	r, e := OpenWorkerAt(nil, dir, tt, true, node)
	ok(t, e)
	defer r.Close()
	a, oldObjects := synthetic(t, tt, writer, 1, "retiring")
	old, e := r.Receive(ctx, a, fetch(oldObjects))
	ok(t, e)
	b, newObjects := synthetic(t, tt, writer, 2, "protected")
	head, e := r.Receive(ctx, b, fetch(newObjects))
	ok(t, e)
	ok(t, r.EnableIndexCopy(ctx))
	signed := permit(t, r, maintenance, old)
	p, e := VerifyPermit(signed, tt)
	ok(t, e)
	r.Fault = func(point string) error {
		if point == "retirement-durable" {
			return ioFailure
		}
		return nil
	}
	if _, e = r.Maintain(ctx, signed); !errors.Is(e, ioFailure) {
		t.Fatal("interruption did not stop pending cleanup", e)
	}
	r.Fault = nil
	ok(t, os.Remove(filepath.Join(dir, "state.json")))
	path := filepath.Join(dir, gcName(p.Operation))
	plan, e := os.ReadFile(path)
	ok(t, e)
	ok(t, os.Remove(path))
	if changed, e := RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil); changed || !errors.Is(e, ErrMigrationRequired) {
		t.Fatal("missing frozen plan was inferred", changed, e)
	}
	ok(t, os.WriteFile(path, plan, 0600))
	changed, e := RecoverIndexCopyAt(nil, ctx, dir, tt, node, nil)
	ok(t, e)
	if !changed {
		t.Fatal("index with exact frozen plan was not recovered")
	}
	removed, e := r.Maintain(ctx, signed)
	ok(t, e)
	if removed != len(oldObjects) {
		t.Fatal("original candidate set did not survive index loss", removed)
	}
	ok(t, r.VerifyComplete(ctx, head))
}
