package generation

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestRetentionPreviewProtectsPinsReceivingAndCurrentRevision(t *testing.T) {
	tt, writer, maintenance := trust(t)
	dir := filepath.Join(temp(t), "replica")
	r := openTest(t, dir, tt)
	now := time.Now().Unix()
	ids := make([]string, 0, 5)
	for seq := uint64(1); seq <= 5; seq++ {
		raw, objects := synthetic(t, tt, writer, seq, strconv.FormatUint(seq, 10))
		if seq == 3 {
			c, e := VerifyCatalog(raw, tt)
			ok(t, e)
			c.SnapshotUnix = now - 10
			raw, e = SignCatalog(c, writer)
			ok(t, e)
		}
		id, e := r.Receive(ctx, raw, fetch(objects))
		ok(t, e)
		ids = append(ids, id)
	}
	partial, _ := synthetic(t, tt, writer, 6, "receiving")
	_, e := r.Begin(ctx, partial)
	ok(t, e)
	ok(t, r.Pin(ctx, Hash([]byte("restoring older kit")), ids[1], "restore"))
	statePath := filepath.Join(dir, "state.json")
	before, e := os.ReadFile(statePath)
	ok(t, e)
	status, e := r.Status(ctx)
	ok(t, e)
	node := Hash([]byte("worker"))
	selection := RetentionSelection{Format: RetentionSelectionFormat, Operation: Hash([]byte("maintenance preview")), KeepLatest: 1, OlderThanUnix: now - 30, MaxRetire: 2, StartUnix: now, ExpiresUnix: now + 600}
	p, e := r.PreviewRetention(ctx, node, selection)
	ok(t, e)
	want := []string{ids[0], ids[3]}
	slices.Sort(want)
	if p == nil || len(p.Signature) != 0 || p.Revision != status.Revision || p.Window.Node != node || !slices.Equal(p.Retire, want) {
		t.Fatal("unexpected retirement preview", p)
	}
	selection.MaxRetire = 1
	bounded, e := r.PreviewRetention(ctx, node, selection)
	ok(t, e)
	if bounded == nil || !slices.Equal(bounded.Retire, []string{ids[0]}) {
		t.Fatal("bound did not select the oldest eligible generation", bounded)
	}
	selection.KeepLatest = 5
	if empty, e := r.PreviewRetention(ctx, node, selection); empty != nil || e != nil {
		t.Fatal("empty selection produced a destructive permit", empty, e)
	}
	after, e := os.ReadFile(statePath)
	ok(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("preview modified the index")
	}
	ok(t, r.Pin(ctx, Hash([]byte("new restore")), ids[0], "restore"))
	signed, e := SignPermit(*p, maintenance)
	ok(t, e)
	if removed, e := r.MaintainOnNode(ctx, signed, node, nil); removed != 0 || !errors.Is(e, ErrRollback) {
		t.Fatal("draft ignored a newer pin and index revision", removed, e)
	}
	for _, id := range ids {
		ok(t, r.VerifyComplete(ctx, id))
	}
}
