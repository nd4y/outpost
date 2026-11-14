package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/generation"
)

func TestPreparedBtrfsSnapshotRestoresIndependentVersions(t *testing.T) {
	producer := os.Getenv("OUTPOST_BTRFS_TEST_ROOT")
	origin := os.Getenv("OUTPOST_BTRFS_TEST_ORIGIN")
	if producer == "" || origin == "" {
		t.Skip("requires an isolated native Btrfs fixture")
	}
	ctx := context.Background()
	f := newFixture(t)
	must(t, f.a.Close())
	f.a = nil
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	f.b.Format = PreparedAgentFormat
	f.b.Local.Directory += "-btrfs"
	f.b.Profile.Consistency = "filesystem"
	f.b.Tree, err = capture.ProbeTree(ctx, producer, f.b.Profile.Origin)
	must(t, err)
	trust := capture.PreparedTrust{Profile: f.b.Profile.ID, Origin: f.b.Profile.Origin,
		Method: capture.BtrfsSnapshotMethod, Producer: pub, MaxBytes: f.b.Profile.MaxSourceBytes,
		MaxFiles: 16, SnapshotOrigin: origin}
	f.b.Prepared = &PreparedSource{Trust: trust, ManifestFile: filepath.Join(f.base, "snapshot-current.json")}

	for _, name := range []string{"live", "writable", "foreign", "mutated"} {
		claim := capture.PreparedClaim{Sequence: 1, Root: name, CompletedUnix: time.Now().Unix()}
		if _, err = CreatePreparedManifest(ctx, f.b, claim, key); !errors.Is(err, capture.ErrInvalid) {
			t.Fatal("non-selected snapshot was accepted", name, err)
		}
	}
	type saved struct {
		id      string
		content []byte
	}
	var versions []saved
	for index, name := range []string{"frozen-1", "frozen-2"} {
		claim := capture.PreparedClaim{Sequence: uint64(index + 1), Root: name, CompletedUnix: time.Now().Unix()}
		content, err := os.ReadFile(filepath.Join(producer, name, "private.bin"))
		must(t, err)
		raw, err := CreatePreparedManifest(ctx, f.b, claim, key)
		must(t, err)
		manifest, err := capture.VerifyPreparedExport(raw, trust, time.Now())
		must(t, err)
		if manifest.SnapshotID == "" || manifest.SnapshotUnix < 1 {
			t.Fatal("manifest lost kernel snapshot identity or creation time")
		}
		claim.SnapshotUnix = manifest.SnapshotUnix - 1
		if _, err = CreatePreparedManifest(ctx, f.b, claim, key); !errors.Is(err, capture.ErrInvalid) {
			t.Fatal("forged snapshot age accepted", err)
		}
		must(t, os.WriteFile(f.b.Prepared.ManifestFile, raw, 0600))
		if index == 0 {
			f.a, err = Open(ctx, f.b, true)
			must(t, err)
		}
		must(t, f.a.Next(ctx))
		status, err := f.a.Status(ctx)
		must(t, err)
		if status.Prepared == nil || status.Prepared.Method != capture.BtrfsSnapshotMethod ||
			status.Prepared.SnapshotUnix != manifest.SnapshotUnix {
			t.Fatal("source status lost filesystem snapshot evidence")
		}
		must(t, f.a.Run(ctx))
		status, err = f.a.Status(ctx)
		must(t, err)
		if status.Phase != "COMPLETE" || status.Sequence != claim.Sequence {
			t.Fatal("wrong committed snapshot generation", status.Phase, status.Sequence)
		}
		versions = append(versions, saved{status.Generation, content})
	}
	must(t, f.a.Close())
	f.a = nil
	// The caller owns this private synthetic producer. Deny source access
	// while independently reading the receiver's materialized generations.
	must(t, os.Chmod(producer, 0000))
	defer func() { must(t, os.Chmod(producer, 0700)) }()
	if _, err := os.Stat(filepath.Join(producer, "frozen-1/private.bin")); !errors.Is(err, os.ErrPermission) {
		t.Fatal("snapshot source is still accessible", err)
	}
	for index, version := range versions {
		target := filepath.Join(f.base, []string{"restore-snapshot-one", "restore-snapshot-two"}[index])
		_, err := generation.RecoverMaterialized(ctx, f.replicaPath, version.id, f.grant.Trust, f.owner, generation.RecoverySelection{}, target)
		must(t, err)
		path := filepath.Join(target, "private.bin")
		data, err := os.ReadFile(path)
		must(t, err)
		info, err := os.Stat(path)
		must(t, err)
		if !bytes.Equal(data, version.content) || info.Mode().Perm() != 0640 {
			t.Fatal("snapshot restored different bytes or permissions", index)
		}
	}
	t.Log("native readonly snapshots, parent identity and original creation time verified; two offline versions restored")
}
