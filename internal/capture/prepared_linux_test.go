package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func preparedFixture(t *testing.T) (string, *os.Root, PreparedTrust, PreparedExport, ed25519.PrivateKey, []byte) {
	t.Helper()
	base := teststore.Root(t)
	must(t, os.Mkdir(filepath.Join(base, "export"), 0700))
	must(t, os.Mkdir(filepath.Join(base, "export", "nested"), 0700))
	data := bytes.Repeat([]byte("native export bytes\n"), 4096)
	must(t, os.WriteFile(filepath.Join(base, "export", "nested", "private.dump"), data, 0600))
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	b := PreparedTrust{Profile: storage.Hash([]byte("profile")), Origin: storage.Hash([]byte("origin")), Method: "prepared-native-test-v1", Producer: pub, MaxBytes: 1 << 20, MaxFiles: 10}
	m := PreparedExport{Format: PreparedExportFormat, Profile: b.Profile, Origin: b.Origin, Method: b.Method, Sequence: 7, SnapshotUnix: time.Now().Unix() - 3600, CompletedUnix: time.Now().Unix() - 3500, Root: "export", Files: []PreparedFile{{Name: "nested/private.dump", Bytes: int64(len(data)), SHA256: storage.Hash(data)}}}
	raw, e := SignPreparedExport(m, b, key, time.Now())
	must(t, e)
	root, e := localfs.OpenRoot(base)
	must(t, e)
	t.Cleanup(func() { root.Close() })
	return base, root, b, m, key, raw
}

func TestPreparedExportVerifiesClosedBytesAndPreservesProducerAge(t *testing.T) {
	base, parent, b, m, _, raw := preparedFixture(t)
	ctx := context.Background()
	// Another export outside the selected view is not part of this admission.
	must(t, os.WriteFile(filepath.Join(base, "unselected"), []byte("other producer data"), 0600))
	got, e := VerifyPreparedExport(raw, b, time.Now())
	must(t, e)
	if got.SnapshotUnix != m.SnapshotUnix || got.CompletedUnix != m.CompletedUnix || got.Sequence != 7 {
		t.Fatal("producer history changed")
	}
	root, plan, e := OpenPreparedExport(ctx, parent, raw, b, time.Now())
	must(t, e)
	defer root.Close()
	if plan.SourceBytes != m.Files[0].Bytes || plan.Excluded != 0 {
		t.Fatal("wrong closed inventory", plan.SourceBytes, plan.Excluded)
	}
	must(t, plan.Recheck(ctx, root))
	entries, e := os.ReadDir(filepath.Join(base, "export", "nested"))
	must(t, e)
	if len(entries) != 1 || entries[0].Name() != "private.dump" {
		t.Fatal("verification wrote producer files")
	}
	unchanged, e := VerifyPreparedExport(raw, b, time.Now().Add(time.Hour))
	must(t, e)
	if unchanged.SnapshotUnix != m.SnapshotUnix {
		t.Fatal("verification refreshed snapshot age")
	}
}

func TestPreparedExportRejectsAmbiguousClaimsAndTrustSubstitution(t *testing.T) {
	_, _, b, m, key, raw := preparedFixture(t)
	for _, kind := range []string{"profile", "origin", "method", "producer", "capacity", "file-limit", "future", "reversed-time", "sequence", "escape", "file-escape", "duplicate", "order", "ancestor", "oversize", "checksum"} {
		t.Run(kind, func(t *testing.T) {
			claim := m
			claim.Files = append([]PreparedFile(nil), m.Files...)
			trust := b
			switch kind {
			case "profile":
				claim.Profile = storage.Hash([]byte("other"))
			case "origin":
				claim.Origin = storage.Hash([]byte("other"))
			case "method":
				claim.Method = "different-native-method"
			case "producer":
				pub, _, e := ed25519.GenerateKey(rand.Reader)
				must(t, e)
				trust.Producer = pub
			case "capacity":
				trust.MaxBytes = 1
			case "file-limit":
				trust.MaxFiles = 0
			case "future":
				claim.CompletedUnix = time.Now().Unix() + 100
			case "reversed-time":
				claim.CompletedUnix = claim.SnapshotUnix - 1
			case "sequence":
				claim.Sequence = 0
			case "escape":
				claim.Root = "../elsewhere"
			case "file-escape":
				claim.Files[0].Name = "../outside"
			case "duplicate":
				claim.Files = append(claim.Files, claim.Files[0])
			case "order":
				second := claim.Files[0]
				second.Name = "a"
				claim.Files = append(claim.Files, second)
			case "ancestor":
				second := claim.Files[0]
				second.Name = "nested"
				claim.Files = append([]PreparedFile{second}, claim.Files...)
			case "oversize":
				claim.Files[0].Bytes = b.MaxBytes + 1
			case "checksum":
				claim.Files[0].SHA256 = "unknown"
			}
			if _, e := SignPreparedExport(claim, trust, key, time.Now()); e == nil {
				t.Fatal("invalid attestation signed", kind)
			}
		})
	}
	for _, kind := range []string{"whitespace", "unknown", "duplicate-key", "signature", "too-large"} {
		t.Run(kind, func(t *testing.T) {
			changed := bytes.Clone(raw)
			switch kind {
			case "whitespace":
				changed = append(changed, '\n')
			case "unknown":
				changed = append([]byte(`{"unknown":1,`), raw[1:]...)
			case "duplicate-key":
				changed = append([]byte(`{"sequence":7,`), raw[1:]...)
			case "signature":
				var v PreparedExport
				must(t, json.Unmarshal(raw, &v))
				v.Signature[0] ^= 1
				changed, _ = json.Marshal(v)
			case "too-large":
				changed = bytes.Repeat([]byte("x"), MaxPreparedExport+1)
			}
			if _, e := VerifyPreparedExport(changed, b, time.Now()); e == nil {
				t.Fatal("ambiguous signed input accepted", kind)
			}
		})
	}
}

func TestPreparedExportRefusesChangedUnknownAliasedAndCanceledViews(t *testing.T) {
	for _, kind := range []string{"changed", "missing", "unknown-file", "empty-directory", "symlink", "hardlink", "root-alias", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			base, parent, b, m, key, raw := preparedFixture(t)
			file := filepath.Join(base, "export", "nested", "private.dump")
			ctx := context.Background()
			switch kind {
			case "changed":
				info, e := os.Stat(file)
				must(t, e)
				data, e := os.ReadFile(file)
				must(t, e)
				data[0] ^= 1
				must(t, os.WriteFile(file, data, 0600))
				must(t, os.Chtimes(file, info.ModTime(), info.ModTime()))
			case "missing":
				must(t, os.Remove(file))
			case "unknown-file":
				must(t, os.WriteFile(filepath.Join(base, "export", "unknown"), []byte("extra"), 0600))
			case "empty-directory":
				must(t, os.Mkdir(filepath.Join(base, "export", "unknown-dir"), 0700))
			case "symlink":
				must(t, os.Remove(file))
				must(t, os.Symlink("../../elsewhere", file))
			case "hardlink":
				must(t, os.Link(file, filepath.Join(base, "alias-outside-export")))
			case "root-alias":
				must(t, os.Symlink("export", filepath.Join(base, "alias")))
				m.Root = "alias"
				var e error
				raw, e = SignPreparedExport(m, b, key, time.Now())
				must(t, e)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			root, _, e := OpenPreparedExport(ctx, parent, raw, b, time.Now())
			if root != nil {
				root.Close()
			}
			if e == nil {
				t.Fatal("unsafe view admitted", kind)
			}
		})
	}
}
