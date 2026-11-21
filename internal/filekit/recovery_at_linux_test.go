package filekit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryPlanMetadataOnlyAndHeldDestination(t *testing.T) {
	base, s, source, original := fixture(t, 1)
	ctx := context.Background()
	v, e := s.Backup(ctx, source, BackupOptions{Names: []string{"private/data", "alias"}})
	entryOK(t, e)
	kits, objects := recoveryMaterial(t, s, []string{v.Version})
	envelope, _, e := s.LoadVersionContext(ctx, v.Version)
	entryOK(t, e)
	metadata := map[string]bool{}
	for _, ref := range envelope.Parts {
		metadata[ref.ID] = true
	}
	reads := 0
	plan, e := PlanRecovery(ctx, s.Owner, kits, func(ctx context.Context, o Object) ([]byte, error) {
		reads++
		if !metadata[o.ID] {
			t.Error("plan read plaintext payload ciphertext")
			return nil, ErrInvalid
		}
		return recoveryRead(objects)(ctx, o)
	}, "")
	entryOK(t, e)
	if reads == 0 || plan.Files != 1 || plan.Bytes != int64(len(original)) || plan.Aliases != 1 || plan.ImplicitDirectories != 1 {
		t.Fatal(plan, reads)
	}
	if _, e = PlanRecovery(ctx, s.Owner, kits, recoveryRead(objects), "../escape"); !errors.Is(e, ErrInvalid) {
		t.Fatal("invalid scope accepted", e)
	}
	dir := filepath.Join(base, "destination")
	entryOK(t, os.Mkdir(dir, 0700))
	parent, e := os.OpenRoot(dir)
	entryOK(t, e)
	defer parent.Close()
	moved := filepath.Join(base, "held-destination")
	outside := filepath.Join(base, "outside")
	entryOK(t, os.Mkdir(outside, 0700))
	entryOK(t, os.Rename(dir, moved))
	entryOK(t, os.Symlink(outside, dir))
	got, e := RecoverSetAt(ctx, s.Owner, kits, recoveryRead(objects), "", parent, "result")
	entryOK(t, e)
	if got != plan {
		t.Fatal("restore differs from admitted plan", got, plan)
	}
	b, e := os.ReadFile(filepath.Join(moved, "result/private/data"))
	entryOK(t, e)
	if !bytes.Equal(b, original) {
		t.Fatal("wrong payload")
	}
	entries, e := os.ReadDir(outside)
	entryOK(t, e)
	if len(entries) != 0 {
		t.Fatal("destination replacement escaped held descriptor")
	}
	if _, e = RecoverSetAt(ctx, s.Owner, kits, recoveryRead(objects), "", parent, "result"); !errors.Is(e, os.ErrExist) {
		t.Fatal("existing output replaced", e)
	}
	if _, e = RecoverSetAt(ctx, s.Owner, kits, recoveryRead(objects), "", parent, "../escape"); !errors.Is(e, ErrInvalid) {
		t.Fatal("relative destination escaped", e)
	}
}
