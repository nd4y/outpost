package upload

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestUnsplitPlansUseSignedReferencesAndMissingPayloadCannotPublish(t *testing.T) {
	f := fixtureBytes(t, 512<<10)
	target := f.server(t, "webdav", 0, nil)
	target.Options.MaxObject = storage.MaxPhysical
	p := profile(target)
	p.MaxObjectBytes = storage.MaxPhysical
	ctx := context.Background()
	catalog, e := f.replicas[0].Catalog(ctx, f.id)
	must(t, e)
	refs, e := generation.Dependencies(catalog, f.authority.Generation)
	must(t, e)
	largest := refs[0]
	for _, ref := range refs {
		if ref.Bytes > largest.Bytes {
			largest = ref
		}
	}
	must(t, os.Remove(filepath.Join(f.dirs[0], "objects", largest.ID)))
	template := Plan{Format: Format, Operation: storage.Hash([]byte("unsplit-metadata")), Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: f.workers[:1], StartMillis: time.Now().Add(-time.Second).UnixMilli(), ExpiresUnix: time.Now().Add(time.Minute).Unix(), SlotMillis: 1000}
	legacy, e := Build(ctx, f.replicas[0], f.id, template, f.planner)
	must(t, e)
	delegation, e := SignDelegation(Delegation{Format: DelegationFormat, Trust: f.authority.Generation, Epoch: 1, Profile: p, AllowedClasses: template.AllowedClasses, Workers: template.Workers, StartMillis: template.StartMillis, ExpiresUnix: template.ExpiresUnix, SlotMillis: template.SlotMillis}, f.planner)
	must(t, e)
	derived, e := BuildDerived(ctx, f.replicas[0], f.id, delegation, f.authority)
	must(t, e)
	for label, raw := range map[string][]byte{"legacy": legacy, "delegated": derived} {
		plan, e := Verify(raw, f.authority)
		must(t, e)
		for _, blob := range plan.Blobs {
			if len(blob.Parts) != 1 || blob.Parts[0] != blob.Object {
				t.Fatal("single-part reference changed")
			}
		}
		dir := filepath.Join(f.base, label)
		must(t, os.Mkdir(dir, 0700))
		j, e := Open(dir, raw, f.workers[0].ID, f.authority, true)
		must(t, e)
		backend, e := f.resolve(t, target)(ctx, p)
		must(t, e)
		run, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, e = j.Run(run, f.replicas[0], backend, f.keys[0])
		cancel()
		if e == nil {
			t.Fatal("metadata-only plan certified absent source bytes")
		}
		if _, e = backend.Catalog(ctx, f.id, f.authority.Generation); !storage.Missing(e) {
			t.Fatal("incomplete target published", e)
		}
		backend.Close()
		j.Close()
	}
	split := template
	split.Profile.MaxObjectBytes = 64 << 10
	if _, e = Build(ctx, f.replicas[0], f.id, split, f.planner); e == nil {
		t.Fatal("multipart map derived without actual payload")
	}
}

func TestTargetReadbackDoesNotRequireUnneededSourcePayload(t *testing.T) {
	f := fixtureBytes(t, 512<<10)
	target := f.server(t, "s3", 0, nil)
	raw := f.plan(t, target, 1, 1000)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	run := func(name string, source *generation.Replica) Receipt {
		dir := filepath.Join(f.base, name)
		must(t, os.Mkdir(dir, 0700))
		j, e := Open(dir, raw, f.workers[0].ID, f.authority, true)
		must(t, e)
		defer j.Close()
		b := f.backend(t, target, 0)
		defer b.Close()
		result, e := j.Run(ctx, source, b, f.keys[0])
		must(t, e)
		return result.Receipt
	}
	run("initial-target", f.replicas[1])
	catalog, e := f.replicas[0].Catalog(ctx, f.id)
	must(t, e)
	refs, e := generation.Dependencies(catalog, f.authority.Generation)
	must(t, e)
	must(t, os.Remove(filepath.Join(f.dirs[0], "objects", refs[0].ID)))
	if e = f.replicas[0].VerifyComplete(ctx, f.id); e == nil {
		t.Fatal("fixture source loss not exercised")
	}
	receipt := run("independent-target-audit", f.replicas[0])
	if receipt.Verification != "full-target-readback" {
		t.Fatal("wrong actual verification level", receipt)
	}
	recoverBytes(t, f, target, f.id, f.version, f.data)
}
