package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

func TestNativeReleaseTicketFollowsDurableCheckpointWithoutExecutionLease(t *testing.T) {
	base, origin, binary := os.Getenv("OUTPOST_BTRFS_RELEASE_ROOT"), os.Getenv("OUTPOST_BTRFS_RELEASE_ORIGIN"), os.Getenv("OUTPOST_BTRFS_CLI")
	if base == "" || origin == "" || binary == "" {
		t.Skip("requires the isolated native Btrfs CLI fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	f := newFixture(t)
	must(t, f.a.Close())
	f.a = nil
	source, staging := filepath.Join(base, "live"), filepath.Join(base, "staging")
	must(t, os.WriteFile(filepath.Join(source, "sample"), []byte("captured before native release"), 0600))
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	sourceTree, err := capture.ProbeTree(ctx, source, f.b.Profile.Origin)
	must(t, err)
	stagingTree, err := capture.ProbeTree(ctx, staging, f.b.Profile.Origin)
	must(t, err)
	stateRoot := filepath.Join(f.base, "producer-volume")
	must(t, os.Mkdir(stateRoot, 0700))
	observed, err := volume.Probe(ctx, stateRoot)
	must(t, err)
	binding, err := volume.Enroll(ctx, stateRoot, observed, f.b.Profile.ID, 1)
	must(t, err)
	stateDir := filepath.Join(stateRoot, "producer")
	must(t, os.Mkdir(stateDir, 0700))
	trust := capture.PreparedTrust{Profile: f.b.Profile.ID, Origin: f.b.Profile.Origin, Method: capture.BtrfsSnapshotMethod,
		Producer: pub, SnapshotOrigin: origin, MaxFiles: 8, MaxBytes: 1 << 20}
	p := capture.BtrfsProducerProfile{Format: capture.BtrfsProducerFormat, Source: sourceTree, Staging: stagingTree,
		StateVolume: binding, StateDirectory: stateDir, Trust: trust, MaxRetained: 2}
	manifest, err := capture.ProduceBtrfsExport(ctx, capture.BtrfsProducerRequest{Profile: p,
		Operation: storage.Hash([]byte("native-release-agent-fixture")), Sequence: 1}, key)
	must(t, err)
	m, err := capture.VerifyPreparedExport(manifest, trust, time.Now())
	must(t, err)
	operation := storage.Hash(manifest)
	f.b.Format = PreparedAgentFormat
	f.b.Profile.Consistency = "filesystem"
	f.b.Local.Directory += "-native-release"
	f.b.Tree = stagingTree
	f.b.Prepared = &PreparedSource{Trust: trust, ManifestFile: filepath.Join(f.base, "native-manifest.json"), NativeReleaseTickets: true}
	must(t, os.WriteFile(f.b.Prepared.ManifestFile, manifest, 0600))
	f.a, err = Open(ctx, f.b, true)
	must(t, err)
	raw, err := json.Marshal(f.b)
	must(t, err)
	bootstrap := filepath.Join(f.base, "native-bootstrap.json")
	must(t, os.WriteFile(bootstrap, raw, 0600))
	must(t, f.a.Next(ctx))
	before := errors.New("interrupted before provider release")
	f.a.Fault = func(point string) error {
		if point == "source-release-intent-durable" {
			return before
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, before) {
		t.Fatal("expected interruption before provider release", err)
	}
	if _, err = NativeReleaseTicket(ctx, f.b, operation); !errors.Is(err, observation.ErrPending) {
		t.Fatal("source exposed a ticket before releasing the view", err)
	}
	f.reopen(t)
	ticketFile := filepath.Join(f.base, "native-release.json")
	after := errors.New("interrupted after ticket readback")
	f.a.Fault = func(point string) error {
		if point != "source-provider-released" {
			return nil
		}
		read, stop := context.WithTimeout(ctx, 12*time.Second)
		defer stop()
		if raw, err := exec.CommandContext(read, binary, "source-native-release-ticket", "--bootstrap", bootstrap,
			"--operation", operation, "--output", ticketFile).CombinedOutput(); err != nil {
			t.Logf("native release reader under execution lease: %s", raw)
			return err
		}
		return after
	}
	if err = f.a.Run(ctx); !errors.Is(err, after) {
		t.Fatal("could not read the durable ticket under the source execution lease", err)
	}
	ticket, err := os.ReadFile(ticketFile)
	must(t, err)
	proof, err := capture.VerifyNativeRelease(ticket, manifest, trust, f.grant.Trust, time.Now())
	must(t, err)
	if proof.Policy != "complete-copy" || proof.Sequence != 1 || proof.Snapshot != m.SnapshotID {
		t.Fatal("release ticket lost checkpoint or snapshot binding")
	}
	must(t, f.replica.VerifyComplete(ctx, proof.Generation))
	f.reopen(t)
	must(t, f.a.Run(ctx))
	status, err := f.a.Status(ctx)
	must(t, err)
	reopened, err := NativeReleaseTicket(ctx, f.b, operation)
	must(t, err)
	if status.Phase != "COMPLETE" || status.Generation != proof.Generation || status.Prepared == nil ||
		status.Prepared.NativeRelease == nil || status.Prepared.NativeRelease.TicketSHA256 != storage.Hash(ticket) ||
		status.Milestones == nil || status.Milestones.ProviderReleaseUnix < m.SnapshotUnix ||
		status.Milestones.ProviderReleaseUnix > proof.IssuedUnix ||
		!bytes.Equal(ticket, reopened) {
		t.Fatal("source restart changed the release ticket or generation")
	}
	if _, err = os.Stat(filepath.Join(staging, m.Root)); err != nil {
		t.Fatal("source consumer modified producer-owned storage", err)
	}
	t.Log("rootless source issued a replay-stable release ticket for an independently complete generation while holding its execution lease")
}
