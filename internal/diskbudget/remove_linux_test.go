package diskbudget

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOwnedRemovalReturnsMeasuredQuotaWithoutDoubleDebit(t *testing.T) {
	b, root := newBudget(t)
	ctx := context.Background()
	finish, e := b.Reserve(ctx, "objects/accepted", 2<<20)
	must(t, e)
	must(t, os.WriteFile(filepath.Join(root, "objects/accepted"), make([]byte, 2<<20), 0600))
	must(t, finish(true))
	must(t, b.Reconcile(ctx, testLimits))
	before, e := b.Status(ctx)
	must(t, e)
	if e = b.Remove(ctx, "objects/accepted", 1); !errors.Is(e, ErrInvalid) {
		t.Fatal("wrong size deleted", e)
	}
	lease, e := b.Reserve(ctx, "objects/concurrent", 4096)
	must(t, e)
	bounded, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if e = b.Remove(bounded, "objects/accepted", 2<<20); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("removal crossed active writer", e)
	}
	must(t, lease(false))
	must(t, b.Reconcile(ctx, testLimits))
	must(t, b.Remove(ctx, "objects/accepted", 2<<20))
	after, e := b.Status(ctx)
	must(t, e)
	if before.Used["data"]-after.Used["data"] != 2<<20 {
		t.Fatal("wrong debit", before.Used, after.Used)
	}
	must(t, b.Remove(ctx, "objects/accepted", 2<<20))
	replayed, e := b.Status(ctx)
	must(t, e)
	if replayed.Used["data"] != after.Used["data"] {
		t.Fatal("duplicate debit")
	}
	lease, e = b.Reserve(ctx, "objects/reused", 2<<20)
	must(t, e)
	must(t, lease(false))
}
func TestOwnedRemovalRejectsSymlinkAndTraversal(t *testing.T) {
	b, root := newBudget(t)
	ctx := context.Background()
	must(t, os.WriteFile(filepath.Join(root, "outside"), []byte("private"), 0600))
	must(t, os.Symlink("../outside", filepath.Join(root, "objects/link")))
	if e := b.Remove(ctx, "objects/link", 7); !errors.Is(e, ErrInvalid) {
		t.Fatal("link accepted", e)
	}
	if e := b.Remove(ctx, "../outside", 7); !errors.Is(e, ErrInvalid) {
		t.Fatal("escape accepted", e)
	}
	got, e := os.ReadFile(filepath.Join(root, "outside"))
	must(t, e)
	if string(got) != "private" {
		t.Fatal("outside modified")
	}
}
