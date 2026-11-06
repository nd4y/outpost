package filekit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSealedViewExcludesMaintenance(t *testing.T) {
	base, s, source, _ := fixture(t, 1<<20)
	v := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
	other, e := OpenStore(filepath.Join(base, "store"), s.Owner, false)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	e = s.WithSealedKits(context.Background(), []string{v.Version}, func(kits []SealedKit, read func(Object) ([]byte, error)) error {
		if len(kits) != 1 || kits[0].Version != v.Version || len(kits[0].Root) == 0 {
			t.Fatal("incomplete view")
		}
		for _, ref := range kits[0].Objects {
			b, e := read(ref)
			if e != nil || digest(b) != ref.ID {
				t.Fatal("unverified closure", e)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		if _, e := other.Retire(ctx, []string{v.Version}); !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal("maintenance crossed sealed view", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Retire(context.Background(), []string{v.Version}); e != nil {
		t.Fatal(e)
	}
}
