package upload

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestCloudEvidenceEpochFencesOtherOperationAndSurvivesPartialInvalidation(t *testing.T) {
	f := fixtureBytes(t, 128<<10)
	s := f.server(t, "webdav", 0, nil)
	b := f.backend(t, s, 0)
	ctx := context.Background()
	cache, e := statefile.Open(filepath.Join(f.base, "shared-evidence"), readback.MaxPage, true)
	must(t, e)
	defer cache.Close()
	raw := f.plan(t, s, 1, 500)
	open := func(name string) *Journal {
		dir := filepath.Join(f.base, name)
		must(t, os.Mkdir(dir, 0700))
		plan := changePlan(t, f, raw, func(p *Plan) { p.Operation = storage.Hash([]byte(name)) })
		j, e := Open(dir, plan, f.workers[0].ID, f.authority, true)
		must(t, e)
		t.Cleanup(func() { j.Close() })
		j.Readback = ReadbackOptions{MaxAgeSeconds: 3600, Store: cache}
		return j
	}
	first, second := open("first-operation"), open("second-operation")
	blob := first.plan.Blobs[0]
	data, e := f.replicas[0].ReadObject(ctx, f.id, blob.Object)
	must(t, e)
	must(t, b.PutBlob(ctx, blob.Object, data))
	a, e := first.newAudit(ctx, b)
	must(t, e)
	defer a.close()
	other, e := second.newAudit(ctx, b)
	must(t, e)
	defer other.close()
	progress, _, e := a.readParts(ctx, blob.Object.ID, true)
	must(t, e)
	staleKey := a.keys[blob.Object.ID]
	stale := readback.Record{Bytes: progress.Bytes, ObservedUnix: progress.ObservedUnix}
	must(t, os.Remove(s.Path("part-"+blob.Parts[0].ID)))
	if e = other.verify(ctx, blob.Object.ID, false); !storage.Missing(e) {
		t.Fatal("actual missing part not observed", e)
	}
	if e = a.cache.RememberChecked(ctx, map[string]readback.Record{staleKey.ID: stale}, time.Now(), func() error {
		if e := a.checkEpoch(blob.Object.ID); e != nil {
			return e
		}
		return a.hashWindow(blob.Object.ID).sealLocked(progress)
	}); !errors.Is(e, storage.ErrUnavailable) {
		t.Fatal("other operation saved stale evidence", e)
	}
	if e = a.verify(ctx, blob.Object.ID, false); !errors.Is(e, storage.ErrUnavailable) {
		t.Fatal("stale audit remained usable", e)
	}
	// Simulate a crash after the epoch became durable but before the old page
	// was removed. A newly opened audit must not consume that old cache entry.
	must(t, a.cache.Remember(ctx, map[string]readback.Record{staleKey.ID: stale}, time.Now()))
	reopened, e := first.newAudit(ctx, b)
	must(t, e)
	defer reopened.close()
	if reopened.keys[blob.Object.ID] == staleKey || reopened.usable(blob.Object.ID) {
		t.Fatal("old epoch resurrected after reopen")
	}
	if e = reopened.verify(ctx, blob.Object.ID, false); !storage.Missing(e) {
		t.Fatal("reopened audit hid missing part", e)
	}
	old, e := a.cache.Lookup(ctx, []generation.Object{staleKey}, time.Now(), 3600)
	must(t, e)
	if len(old) != 1 {
		t.Fatal("crash fixture did not retain old page")
	}
	epochName := "readback-epoch-" + a.epochScope(blob.Object.ID) + ".json"
	must(t, cache.Write(epochName, []byte("{}")))
	if _, e = first.newAudit(ctx, b); !errors.Is(e, readback.ErrInvalid) {
		t.Fatal("malformed epoch ignored", e)
	}
	kept, e := cache.Read(epochName)
	must(t, e)
	if !bytes.Equal(kept, []byte("{}")) {
		t.Fatal("malformed epoch replaced")
	}
}

func TestCloudHashProgressLosingKnownDescriptorInvalidatesUnsealedPrefix(t *testing.T) {
	f := fixtureBytes(t, 128<<10)
	s := f.server(t, "s3", 0, nil)
	b := f.backend(t, s, 0)
	ctx := context.Background()
	dir := filepath.Join(f.base, "known-descriptor")
	must(t, os.Mkdir(dir, 0700))
	j, e := Open(dir, f.plan(t, s, 1, 500), f.workers[0].ID, f.authority, true)
	must(t, e)
	defer j.Close()
	j.Readback.MaxAgeSeconds = 3600
	blob := j.plan.Blobs[0]
	for _, v := range j.plan.Blobs {
		if len(v.Parts) > len(blob.Parts) {
			blob = v
		}
	}
	if len(blob.Parts) < 2 {
		t.Fatal("fixture not split")
	}
	data, e := f.replicas[0].ReadObject(ctx, f.id, blob.Object)
	must(t, e)
	must(t, b.PutBlob(ctx, blob.Object, data))
	a, e := j.newAudit(ctx, b)
	must(t, e)
	a.afterPart = func() error { return context.Canceled }
	if e = a.verify(ctx, blob.Object.ID, false); !errors.Is(e, context.Canceled) {
		t.Fatal("fault absent", e)
	}
	p, e := a.hashWindow(blob.Object.ID).load()
	must(t, e)
	if !p.DescriptorSeen || p.Sealed || p.Next != 1 {
		t.Fatal("descriptor observation not durable")
	}
	a.close()
	must(t, os.Remove(s.Path("blob-"+blob.Object.ID)))
	must(t, os.Remove(s.Path("part-"+blob.Parts[0].ID)))
	a, e = j.newAudit(ctx, b)
	must(t, e)
	defer a.close()
	if e = a.verify(ctx, blob.Object.ID, true); !storage.Missing(e) {
		t.Fatal("known loss reused unsealed prefix", e)
	}
	if _, e = os.Stat(s.Path("blob-" + blob.Object.ID)); !os.IsNotExist(e) {
		t.Fatal("missing data resealed")
	}
}
