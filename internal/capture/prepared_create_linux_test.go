package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPreparedExportCreateMeasuresClosedInventoryAndRejectsUnsafeInputs(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-key", "capacity", "file-limit", "symlink", "hardlink", "empty-directory", "empty-export", "escape", "future", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			base, parent, trust, expected, key, signed := preparedFixture(t)
			claim := PreparedClaim{Sequence: expected.Sequence, SnapshotUnix: expected.SnapshotUnix, CompletedUnix: expected.CompletedUnix, Root: expected.Root}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "wrong-key":
				_, other, e := ed25519.GenerateKey(rand.Reader)
				must(t, e)
				key = other
			case "capacity":
				trust.MaxBytes = 1
			case "file-limit":
				trust.MaxFiles = 1
				must(t, os.WriteFile(filepath.Join(base, "export/second"), []byte("extra"), 0600))
			case "symlink":
				must(t, os.Symlink("nested/private.dump", filepath.Join(base, "export/link")))
			case "hardlink":
				must(t, os.Link(filepath.Join(base, "export/nested/private.dump"), filepath.Join(base, "outside-alias")))
			case "empty-directory":
				must(t, os.Mkdir(filepath.Join(base, "export/empty"), 0700))
			case "empty-export":
				must(t, os.Mkdir(filepath.Join(base, "empty"), 0700))
				claim.Root = "empty"
			case "escape":
				claim.Root = "../export"
			case "future":
				claim.CompletedUnix = time.Now().Unix() + 3600
			case "cancelled":
				cancel()
			}
			got, e := CreatePreparedExport(ctx, parent, trust, claim, key, time.Now())
			if kind == "valid" {
				must(t, e)
				if !bytes.Equal(got, signed) {
					t.Fatal("producer manifest changed claims or measured bytes")
				}
				return
			}
			if e == nil || got != nil {
				t.Fatal("unsafe producer input signed", kind)
			}
		})
	}
}
