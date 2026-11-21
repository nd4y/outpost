package upload

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
)

func TestSourceObjectCacheCancelledReplacementPreservesReadableBytes(t *testing.T) {
	f := fixtureBytes(t, 4096)
	ctx := context.Background()
	raw, err := f.replicas[0].Catalog(ctx, f.id)
	must(t, err)
	catalog, err := generation.VerifyCatalog(raw, f.authority.Generation)
	must(t, err)
	refs := []generation.Object{catalog.Kits[0].Root, catalog.Kits[0].Objects[0]}
	if refs[0] == refs[1] {
		t.Fatal("fixture needs two distinct objects")
	}
	var cache sourceObjectCache
	first, err := cache.read(ctx, f.replicas[0], f.id, refs[0])
	must(t, err)
	want := append([]byte(nil), first...)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err = cache.read(cancelled, f.replicas[0], f.id, refs[1]); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled replacement read succeeded", err)
	}
	// A later assignment can return to the previous object. Its old identity
	// must never refer to the failed replacement's empty or partial byte slice.
	got, err := cache.read(ctx, f.replicas[0], f.id, refs[0])
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatal("cancelled replacement poisoned previous object cache")
	}
	second, err := cache.read(ctx, f.replicas[0], f.id, refs[1])
	must(t, err)
	if len(second) != refs[1].Bytes {
		t.Fatal("replacement could not resume")
	}
}
