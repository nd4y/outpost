package upload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func TestCompleteTargetCannotCertifyDifferentPlannedParts(t *testing.T) {
	f := fixtureBytes(t, 512<<10)
	s := f.server(t, "webdav", 0, nil)
	raw := f.plan(t, s, 1, 1000)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	run := func(name string, plan []byte) error {
		dir := filepath.Join(f.base, name)
		must(t, os.Mkdir(dir, 0700))
		j, e := Open(dir, plan, f.workers[0].ID, f.authority, true)
		must(t, e)
		defer j.Close()
		b := f.backend(t, s, 0)
		defer b.Close()
		_, e = j.Run(ctx, f.replicas[0], b, f.keys[0])
		return e
	}
	must(t, run("valid-target", raw))
	wrong := changePlan(t, f, raw, func(p *Plan) {
		p.Operation = storage.Hash([]byte("different planned part map"))
		p.Blobs[0].Parts[0].ID = storage.Hash([]byte("part absent from actual descriptor"))
	})
	if e := run("wrong-part-map", wrong); !errors.Is(e, storage.ErrConflict) {
		t.Fatal("complete object certified different planned parts", e)
	}
}
