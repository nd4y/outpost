package sourceagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
	"golang.org/x/sys/unix"
)

// This separate opt-in profile streams its corpus and recovery oracles. A
// retained fixture is never mistaken for an accepted full-size execution.
func TestAsymmetricSourceScale(t *testing.T) {
	if os.Getenv("OUTPOST_ASYMMETRIC_SCALE") != "1" {
		t.Skip("explicit pinned HDD scale admission required")
	}
	size, err := strconv.ParseInt(os.Getenv("OUTPOST_ASYMMETRIC_BYTES"), 10, 64)
	if err != nil || (size != 128<<20 && size != 100<<30) {
		t.Fatal("scale requires128MiB rehearsal or physical100GiB")
	}
	recoveryMode := os.Getenv("OUTPOST_ASYMMETRIC_DEFER_RECOVERY")
	if recoveryMode != "" && recoveryMode != "1" || size == 100<<30 && recoveryMode != "1" {
		t.Fatal("full profile requires separately admitted fresh executable consumers;128MiB also supports the original in-process control")
	}
	root := os.Getenv("OUTPOST_TEST_ROOT")
	var disk unix.Statfs_t
	must(t, unix.Statfs(root, &disk))
	identity := fmt.Sprintf("%x", uint64(uint32(disk.Fsid.Val[0]))|uint64(uint32(disk.Fsid.Val[1]))<<32)
	if identity != os.Getenv("OUTPOST_ASYMMETRIC_VOLUME_FSID") {
		t.Fatal("admitted filesystem differs")
	}
	reserve := uint64(disk.Blocks) * uint64(disk.Bsize) / 5
	if uint64(disk.Bavail)*uint64(disk.Bsize) < reserve+uint64(18*size)+(1<<30) {
		t.Fatal("four retained three-holder cases, recovery overlap and20percent reserve unavailable")
	}
	tool := os.Getenv("OUTPOST_ASYMMETRIC_ORACLE")
	info, err := os.Lstat(tool)
	must(t, err)
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 128<<20 {
		t.Fatal("invalid fixture tool")
	}
	raw, err := os.ReadFile(tool)
	must(t, err)
	if !storage.ID(os.Getenv("OUTPOST_ASYMMETRIC_ORACLE_SHA256")) || storage.Hash(raw) != os.Getenv("OUTPOST_ASYMMETRIC_ORACLE_SHA256") {
		t.Fatal("unpinned fixture tool")
	}
	oracle := func(t *testing.T, op, name, phase string) string {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), tool, "--op", op, "--file", name, "--phase", phase, "--bytes", strconv.FormatInt(size, 10)).CombinedOutput()
		if err != nil {
			t.Fatalf("oracle %s/%s: %v: %s", op, phase, err, out)
		}
		var result struct {
			SHA256 string `json:"sha256"`
		}
		must(t, json.Unmarshal(out, &result))
		if op != "mutate" && !storage.ID(result.SHA256) {
			t.Fatal("oracle did not report actual full-byte hash", string(out))
		}
		t.Logf("ASYMMETRIC_ORACLE operation=%s phase=%s result=%s", op, phase, out)
		return result.SHA256
	}
	owner, err := filekit.NewOwner()
	must(t, err)
	writer, private, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	maintenance, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	epoch := &fixtureEpoch{owner: owner, writer: private, trust: generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("asymmetric-scale-repo")), Epoch: 1, Writer: writer, Maintenance: maintenance}}
	for _, split := range []bool{false, true} {
		for _, single := range []bool{true, false} {
			name := "complete-paired"
			if split {
				name = "split-paired"
			}
			if single {
				name = name[:len(name)-len("paired")] + "single"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 48*time.Hour)
				defer cancel()
				var initialHash string
				x := newAsymmetricFixtureOptions(t, epoch, split, int64(72*time.Hour/time.Second), fixtureOptions{
					Directory: filepath.Join(root, "asymmetric-scale-"+name), MaxSourceBytes: size, MaxBytes: 128 << 30, MaxObjects: generation.MaxObjects,
					Limits: diskbudget.Limits{Capacity: 2 << 30, Reserve: 256 << 20, Spool: 1 << 30, Telemetry: 1 << 20}, CertificateLifetime: 72 * time.Hour, RetainContext: true,
					InitialSource: func(t *testing.T, tree string) {
						file := filepath.Join(tree, "private.bin")
						initialHash = oracle(t, "generate", file, "base")
						info, err := os.Stat(file)
						must(t, err)
						if info.Size() != size || info.Sys().(*syscall.Stat_t).Blocks*512 < size {
							t.Fatal("source was not fully physically allocated")
						}
					},
				}, control.Limits{Parallel: 2, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 512 << 30, ReserveBytes: 16 << 30, SpoolBytes: 256 << 30, TelemetryBytes: 1 << 20})
				x.removeVerifiedRestores = true
				x.deferRecoveries = recoveryMode == "1"
				results := map[string]asymmetricResult{}
				for _, phase := range []string{"base", "patched"} {
					if phase == "patched" {
						oracle(t, "mutate", filepath.Join(x.f.tree, "private.bin"), phase)
					}
					expected := asymmetricExpected{Bytes: size, Verify: func(t *testing.T, name string) string { return oracle(t, "verify", name, phase) }}
					if phase == "base" {
						expected.SHA256 = initialHash
					}
					r := x.capture(t, ctx, single, expected)
					if phase == "base" && r.InitialBytes > size*108/100 {
						t.Fatal("initial object amplification exceeds1.08")
					}
					var sourceBodies int64
					for route, n := range r.Traffic.Requests {
						if len(route) > len(x.f.grant.Source) && route[:len(x.f.grant.Source)+1] == x.f.grant.Source+">" {
							sourceBodies += n
						}
					}
					if phase == "patched" && sourceBodies > 128<<20 {
						t.Fatal("8MiB change exceeds128MiB source body budget", sourceBodies)
					}
					var allocated int64
					must(t, filepath.WalkDir(x.f.b.Local.Volume.Root, func(p string, d fs.DirEntry, err error) error {
						if err != nil {
							return err
						}
						if d.Type().IsRegular() {
							s, e := d.Info()
							if e != nil {
								return e
							}
							allocated += s.Sys().(*syscall.Stat_t).Blocks * 512
						}
						return nil
					}))
					budget, err := x.f.a.budget.Status(ctx)
					must(t, err)
					if allocated > 2<<30 || budget.Limits.Capacity != 2<<30 {
						t.Fatal("source state exceeded2GiB", allocated)
					}
					t.Logf("ASYMMETRIC_SCALE_BUDGET phase=%s allocated=%d limit=%d", phase, allocated, int64(2<<30))
					results[phase] = r
				}
				// Keep only recovery-owner material and public trust for separately
				// mounted fresh executable consumers. Operational keys stay outside
				// that future namespace; no clean-consumer claim is made here.
				recovery := x.f.owner
				recovery.SigningKey = nil
				write := func(name string, value any) {
					b, e := json.Marshal(value)
					must(t, e)
					must(t, os.WriteFile(filepath.Join(x.f.base, name), b, 0600))
				}
				write("recovery-owner.json", recovery)
				write("trust.json", x.f.grant.Trust)
				paths := []string{}
				for _, dir := range x.dirs {
					paths = append(paths, filepath.Join(worker.DomainDirectory(dir, x.f.grant.Trust), "replica"))
				}
				write("asymmetric-result.json", struct {
					Bytes                     int64
					Results                   map[string]asymmetricResult
					Replicas                  []string
					InProcessRecoveryDeferred bool
				}{size, results, paths, x.deferRecoveries})
				t.Logf("ASYMMETRIC_SCALE_CASE_PASS name=%s bytes=%d retained-generations=2 physical-holders=3 independent-process-consumers=pending", name, size)
			})
		}
	}
	if !t.Failed() {
		t.Logf("ASYMMETRIC_SCALE_PASS bytes=%d matched-cases=4 independent-process-consumers=pending", size)
	}
}
