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
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

func preparedSourceFixture(t *testing.T, lifetime ...int64) (*fixture, ed25519.PrivateKey, capture.PreparedExport, []byte) {
	t.Helper()
	seconds := int64(1800)
	if len(lifetime) != 0 {
		seconds = lifetime[0]
	}
	f := newFixtureLifetime(t, seconds)
	data, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	must(t, os.Mkdir(filepath.Join(f.tree, "export-1"), 0700))
	must(t, os.Rename(filepath.Join(f.tree, "private.bin"), filepath.Join(f.tree, "export-1/private.bin")))
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	must(t, f.a.Close())
	f.a = nil
	f.b.Format = PreparedAgentFormat
	f.b.Profile.Consistency = "application"
	f.b.Local.Directory += "-prepared"
	f.b.Prepared = &PreparedSource{Trust: capture.PreparedTrust{Profile: f.b.Profile.ID, Origin: f.b.Profile.Origin, Method: "native-export-fixture-v1", Producer: pub, MaxBytes: f.b.Profile.MaxSourceBytes, MaxFiles: 16}, ManifestFile: filepath.Join(f.base, "producer-current.json")}
	m := capture.PreparedExport{Format: capture.PreparedExportFormat, Profile: f.b.Profile.ID, Origin: f.b.Profile.Origin, Method: f.b.Prepared.Trust.Method, Sequence: 10, SnapshotUnix: time.Now().Unix() - 3600, CompletedUnix: time.Now().Unix() - 3500, Root: "export-1", Files: []capture.PreparedFile{{Name: "private.bin", Bytes: int64(len(data)), SHA256: storage.Hash(data)}}}
	raw, e := capture.SignPreparedExport(m, f.b.Prepared.Trust, key, time.Now())
	must(t, e)
	must(t, os.WriteFile(f.b.Prepared.ManifestFile, raw, 0600))
	f.a, e = Open(context.Background(), f.b, true)
	must(t, e)
	return f, key, m, data
}

func TestPreparedSourceRefusesQuotaVolumeLossAndExpiredFrozenAdmission(t *testing.T) {
	for _, kind := range []string{"quota", "volume", "expired-after-freeze"} {
		t.Run(kind, func(t *testing.T) {
			seconds := int64(1800)
			if kind == "expired-after-freeze" {
				seconds = 4
			}
			f, _, _, _ := preparedSourceFixture(t, seconds)
			ctx := context.Background()
			statePath := filepath.Join(f.b.Local.Directory, "state/agent.json")
			before, e := os.ReadFile(statePath)
			must(t, e)
			var restore func()
			switch kind {
			case "quota":
				s, e := f.a.budget.Status(ctx)
				must(t, e)
				// Reserve the remaining metadata quota without allocating a large
				// file or filling the shared physical test disk.
				available := s.Limits.Spool - (2 << 20) - s.Used["spool"]
				size := (available - (64 << 10)) / 4096 * 4096
				finish, e := f.a.budget.Reserve(ctx, "synthetic-held-spool", int(size))
				must(t, e)
				restore = func() { must(t, finish(false)) }
			case "volume":
				marker := filepath.Join(f.b.Local.Volume.Root, volume.Sentinel)
				must(t, os.Rename(marker, marker+"-held"))
				restore = func() { must(t, os.Rename(marker+"-held", marker)) }
			case "expired-after-freeze":
				f.a.Fault = func(point string) error {
					if point == "source-prepared-view-frozen" {
						return errors.New("manifest before intent")
					}
					return nil
				}
				if f.a.Next(ctx) == nil {
					t.Fatal("freeze boundary absent")
				}
				f.a.Fault = nil
				f.expire(t)
			}
			if restore != nil {
				defer restore()
			}
			if f.a.Next(ctx) == nil {
				t.Fatal("unsafe prepared intent admitted", kind)
			}
			after, e := os.ReadFile(statePath)
			must(t, e)
			if !bytes.Equal(before, after) {
				t.Fatal("refused prepared admission changed source head", kind)
			}
			if kind != "expired-after-freeze" {
				entries, e := os.ReadDir(filepath.Join(f.b.Local.Directory, "prepared-views"))
				if e != nil && !os.IsNotExist(e) {
					t.Fatal(e)
				}
				for _, entry := range entries {
					if filepath.Ext(entry.Name()) == ".json" {
						t.Fatal("failed admission stored a manifest")
					}
				}
			}
		})
	}
}

func TestPreparedSourceFreezesPointerPreservesAgeLineageAndRestoresBothVersions(t *testing.T) {
	f, key, m, firstData := preparedSourceFixture(t)
	ctx := context.Background()
	f.a.Fault = func(point string) error {
		if point == "source-agent-intent-durable" {
			return errors.New("intent before reply")
		}
		return nil
	}
	if f.a.Next(ctx) == nil {
		t.Fatal("intent interruption absent")
	}
	old, e := os.ReadFile(f.b.Prepared.ManifestFile)
	must(t, e)
	secondData := bytes.Clone(firstData)
	secondData[0] ^= 1
	must(t, os.Mkdir(filepath.Join(f.tree, "export-2"), 0700))
	must(t, os.WriteFile(filepath.Join(f.tree, "export-2/private.bin"), secondData, 0600))
	next := m
	next.Files = append([]capture.PreparedFile(nil), m.Files...)
	next.Sequence++
	next.SnapshotUnix += 10
	next.CompletedUnix += 10
	next.Root = "export-2"
	next.Files[0].SHA256 = storage.Hash(secondData)
	raw, e := capture.SignPreparedExport(next, f.b.Prepared.Trust, key, time.Now())
	must(t, e)
	must(t, os.WriteFile(f.b.Prepared.ManifestFile, raw, 0600))
	f.reopen(t)
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	first, e := f.a.Status(ctx)
	must(t, e)
	if first.Sequence != 1 || first.Prepared == nil || first.Prepared.ProducerSequence != 10 || first.Prepared.SnapshotUnix != m.SnapshotUnix || first.Operation != storage.Hash(old) {
		t.Fatal("producer pointer replaced pending view", first)
	}
	previous, e := f.a.load()
	must(t, e)
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	second, e := f.a.Status(ctx)
	must(t, e)
	if second.Sequence != 2 || second.Prepared == nil || second.Prepared.ProducerSequence != 11 || second.Prepared.SnapshotUnix != next.SnapshotUnix || second.Operation != storage.Hash(raw) {
		t.Fatal("next export not selected", second)
	}
	current, e := f.a.load()
	must(t, e)
	common := 0
	for id, version := range previous.Previous {
		if latest, ok := current.Previous[id]; ok && latest != version {
			common++
		}
	}
	if common == 0 {
		t.Fatal("logical native artifact lineage lost across new inodes")
	}
	before, e := os.ReadFile(filepath.Join(f.b.Local.Directory, "state/agent.json"))
	must(t, e)
	if !errors.Is(f.a.Next(ctx), ErrPreparedUnchanged) {
		t.Fatal("unchanged export recaptured")
	}
	after, e := os.ReadFile(filepath.Join(f.b.Local.Directory, "state/agent.json"))
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("unchanged export refreshed signed source head")
	}
	// Rollback is refused before freezing or replacing source state.
	must(t, os.WriteFile(f.b.Prepared.ManifestFile, old, 0600))
	if f.a.Next(ctx) == nil {
		t.Fatal("producer sequence rolled back")
	}
	for index, item := range []struct {
		id   string
		data []byte
	}{{first.Generation, firstData}, {second.Generation, secondData}} {
		out := filepath.Join(f.base, []string{"prepared-restore-first", "prepared-restore-second"}[index])
		_, e = generation.RecoverMaterialized(ctx, f.replicaPath, item.id, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		if !bytes.Equal(got, item.data) {
			t.Fatal("wrong independently restored export", index)
		}
	}
	// Consumer release retained both producer-owned immutable exports.
	for _, name := range []string{"export-1/private.bin", "export-2/private.bin"} {
		if _, e = os.Stat(filepath.Join(f.tree, name)); e != nil {
			t.Fatal("producer artifact removed", e)
		}
	}
}

func TestPreparedSourceScheduleDoesNotRefreshCompletionForUnchangedExport(t *testing.T) {
	f, _, _, _ := preparedSourceFixture(t)
	ctx := context.Background()
	config := testSchedule()
	must(t, f.a.ConfigureSchedule(ctx, config))
	must(t, f.a.scheduleStep(ctx))
	first, e := f.a.ScheduleStatus(ctx)
	must(t, e)
	if first.LastSequence != 1 || first.LastCompletedUnix == 0 {
		t.Fatal("initial export not completed")
	}
	config.Revision++
	must(t, f.a.ConfigureSchedule(ctx, config))
	must(t, f.a.scheduleStep(ctx))
	unchanged, e := f.a.ScheduleStatus(ctx)
	must(t, e)
	if unchanged.Phase != "RETRY_WAIT" || unchanged.ErrorCode != "EXPORT_NOT_ADVANCED" || unchanged.LastSequence != first.LastSequence || unchanged.LastGeneration != first.LastGeneration || unchanged.LastCompletedUnix != first.LastCompletedUnix {
		t.Fatal("unchanged export refreshed completion", first, unchanged)
	}
	f.reopen(t)
	status, e := f.a.Status(ctx)
	must(t, e)
	if status.Sequence != 1 || status.Prepared == nil || status.Prepared.ProducerSequence != 10 {
		t.Fatal("schedule duplicate capture", status)
	}
}

func TestPreparedSourceRefusesDowngradeMissingProofAndUnavailableCapability(t *testing.T) {
	f, _, _, _ := preparedSourceFixture(t)
	ctx := context.Background()
	wrong := f.b
	wrong.Format = Format
	if other, e := Open(ctx, wrong, false); e == nil {
		other.Close()
		t.Fatal("prepared bootstrap silently downgraded")
	}
	wrong = f.b
	copy := *f.b.Prepared
	wrong.Prepared = &copy
	wrong.Prepared.Trust.Producer = nil
	if other, e := Open(ctx, wrong, false); e == nil {
		other.Close()
		t.Fatal("missing producer trust accepted")
	}
	must(t, f.a.Next(ctx))
	status, e := f.a.Status(ctx)
	must(t, e)
	frozen := filepath.Join(f.b.Local.Directory, "prepared-views", status.Operation+".json")
	must(t, os.Remove(frozen))
	// The current pointer must never reconstruct an already admitted missing
	// journal. History-loss recovery has a separate owner workflow.
	if f.a.Next(ctx) == nil || f.a.Run(ctx) == nil {
		t.Fatal("missing frozen manifest reconstructed")
	}
	if _, e = os.Stat(frozen); !os.IsNotExist(e) {
		t.Fatal("missing manifest recreated", e)
	}
}
