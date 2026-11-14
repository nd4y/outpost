package sourceagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

type scaleCountedBody struct {
	io.ReadCloser
	count  *atomic.Int64
	onRead func(int)
}

func (b scaleCountedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.count.Add(int64(n))
	if b.onRead != nil {
		b.onRead(n)
	}
	return n, err
}

// This opt-in test retains its owned fixture on failure. The runner must verify
// the host filesystem UUID, exact source and binary hashes before admission.
func TestSourceIngressScaleAndOfflineMaterializedReplica(t *testing.T) {
	if os.Getenv("OUTPOST_INGRESS_SCALE") != "1" {
		t.Skip("explicit isolated HDD scale profile required")
	}
	root := os.Getenv("OUTPOST_TEST_ROOT")
	size, err := strconv.ParseInt(os.Getenv("OUTPOST_INGRESS_SCALE_BYTES"), 10, 64)
	if err != nil || (size != 128<<20 && size != 100<<30) || root == "" || os.Getenv("OUTPOST_RECOVERY_DISTRIBUTION") == "" {
		t.Fatal("scale profile requires pinned tools, admitted root and128MiB or100GiB")
	}
	var disk unix.Statfs_t
	must(t, unix.Statfs(root, &disk))
	identity := fmt.Sprintf("%x", uint64(uint32(disk.Fsid.Val[0]))|uint64(uint32(disk.Fsid.Val[1]))<<32)
	if os.Getenv("OUTPOST_INGRESS_VOLUME_FSID") != identity {
		t.Fatal("admitted filesystem identity differs")
	}
	reserve := uint64(disk.Blocks) * uint64(disk.Bsize) / 5
	free := uint64(disk.Bavail) * uint64(disk.Bsize)
	if free < reserve+uint64(6*size)+(1<<30) {
		t.Fatal("insufficient projected fixture/recovery overlap and20percent reserve")
	}
	tool := os.Getenv("OUTPOST_INGRESS_FIXTURE_BINARY")
	toolInfo, err := os.Lstat(tool)
	must(t, err)
	if !toolInfo.Mode().IsRegular() || toolInfo.Size() < 1 || toolInfo.Size() > 128<<20 {
		t.Fatal("invalid pinned fixture executable")
	}
	raw, err := os.ReadFile(tool)
	must(t, err)
	if !storage.ID(os.Getenv("OUTPOST_INGRESS_FIXTURE_SHA256")) || storage.Hash(raw) != os.Getenv("OUTPOST_INGRESS_FIXTURE_SHA256") {
		t.Fatal("fixture binary hash differs")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := func(binary string, args ...string) []byte {
		t.Helper()
		out, e := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("scale tool failed: %v: %s", e, out)
		}
		return out
	}
	oracle := func(op, name, phase, alias string) []byte {
		args := []string{"--op", op, "--file", name, "--phase", phase, "--bytes", strconv.FormatInt(size, 10)}
		if alias != "" {
			args = append(args, "--alias", alias)
		}
		return run(tool, args...)
	}
	t.Logf("INGRESS_SCALE_ADMITTED bytes=%d projected-overlap-bytes=%d source-budget-bytes=%d", size, 6*size, int64(2<<30))
	f := newFixtureWithOptions(t, int64((48*time.Hour)/time.Second), nil, nil, fixtureOptions{
		Directory:      filepath.Join(root, "source-ingress-scale"),
		MaxSourceBytes: size, MaxBytes: 128 << 30, MaxObjects: generation.MaxObjects,
		Limits:              diskbudget.Limits{Capacity: 2 << 30, Reserve: 256 << 20, Spool: 1 << 30, Telemetry: 1 << 20},
		CertificateLifetime: 48 * time.Hour,
		InitialSource: func(t *testing.T, tree string) {
			name := filepath.Join(tree, "private.bin")
			t.Logf("INGRESS_SCALE_GENERATING bytes=%d", size)
			t.Logf("INGRESS_SCALE_GENERATED %s", oracle("generate", name, "base", ""))
			must(t, os.Link(name, filepath.Join(tree, "alias.bin")))
			info, e := os.Stat(name)
			must(t, e)
			if info.Size() != size || info.Sys().(*syscall.Stat_t).Blocks*512 < size {
				t.Fatal("source is not physically allocated at the declared length")
			}
		},
	})
	// Count received HTTP request bodies, separately from TLS/HTTP overhead,
	// response readback and receiver logical-reference counts.
	var payload, metadata atomic.Int64
	var objectsMu sync.Mutex
	objects := map[string]int64{}
	f.registryMu.Lock()
	f.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut {
			counter := &metadata
			var observe func(int)
			if strings.Contains(r.URL.Path, "/objects/") {
				counter = &payload
				id := filepath.Base(r.URL.Path)
				observe = func(n int) { objectsMu.Lock(); objects[id] += int64(n); objectsMu.Unlock() }
			}
			r.Body = scaleCountedBody{r.Body, counter, observe}
		}
		return false
	}
	f.registryMu.Unlock()
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	var currentPhase atomic.Value
	currentPhase.Store("ready")
	go func() {
		defer close(watchDone)
		timer := time.NewTicker(2 * time.Second)
		defer timer.Stop()
		progress := time.NewTicker(30 * time.Second)
		defer progress.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-progress.C:
				t.Logf("INGRESS_SCALE_PROGRESS phase=%s received-object-body-bytes=%d received-other-put-body-bytes=%d", currentPhase.Load(), payload.Load(), metadata.Load())
			case <-timer.C:
				var current unix.Statfs_t
				if unix.Statfs(root, &current) != nil || current.Fsid != disk.Fsid || uint64(current.Bavail)*uint64(current.Bsize) < reserve+(16<<20) {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { close(stopWatch); <-watchDone }()
	type result struct {
		Generation                                        string `json:"generation"`
		PayloadBytes, MetadataBytes, SourceAllocatedBytes int64
		FilePayloadBytes, DescriptorBytes                 int64
		Seconds                                           float64
		Milestones                                        *Milestones `json:"milestones"`
	}
	results := map[string]result{}
	captureOne := func(phase string) capture.Checkpoint {
		t.Helper()
		currentPhase.Store("capture-" + phase)
		p, m, started := payload.Load(), metadata.Load(), time.Now()
		objectsMu.Lock()
		before := map[string]int64{}
		for id, n := range objects {
			before[id] = n
		}
		objectsMu.Unlock()
		must(t, f.a.Next(ctx))
		must(t, f.a.Run(ctx))
		checkpoint, e := f.a.Checkpoint(ctx)
		must(t, e)
		c, e := capture.VerifyCheckpoint(checkpoint, f.grant.Trust)
		must(t, e)
		status, e := f.a.Status(ctx)
		must(t, e)
		if status.Phase != "COMPLETE" || status.Generation != c.Generation || status.Milestones == nil || status.Milestones.ProviderReleaseUnix < status.Milestones.SnapshotUnix || status.Milestones.FirstReplicaVerifiedUnix < status.Milestones.SnapshotUnix {
			t.Fatal("missing original release or replica verification observation", status)
		}
		budget, e := f.a.budget.Status(ctx)
		must(t, e)
		if budget.Limits.Capacity != 2<<30 {
			t.Fatal("source budget changed")
		}
		var allocated int64
		must(t, filepath.WalkDir(f.b.Local.Volume.Root, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.Type().IsRegular() {
				info, err := d.Info()
				if err != nil {
					return err
				}
				allocated += info.Sys().(*syscall.Stat_t).Blocks * 512
			}
			return nil
		}))
		if allocated > 2<<30 {
			t.Fatal("source runtime exceeds2GiB")
		}
		catalogRaw, e := f.replica.Catalog(ctx, c.Generation)
		must(t, e)
		catalog, e := generation.VerifyCatalog(catalogRaw, f.grant.Trust)
		must(t, e)
		// Roots and encrypted descriptor parts are metadata transported through
		// the same immutable-object endpoint as file ciphertext packs.
		descriptors := map[string]bool{}
		for _, kit := range catalog.Kits {
			descriptors[kit.Root.ID] = true
			root, err := f.replica.ReadObject(ctx, c.Generation, kit.Root)
			must(t, err)
			var envelope filekit.Envelope
			must(t, json.Unmarshal(root, &envelope))
			if envelope.Format != generation.KitFormat || envelope.Domain != catalog.Domain || envelope.File != kit.File || envelope.Version != kit.Version {
				t.Fatal("unexpected descriptor envelope")
			}
			for _, part := range envelope.Parts {
				descriptors[part.ID] = true
			}
		}
		var filePayload, descriptorBytes int64
		objectsMu.Lock()
		for id, n := range objects {
			if descriptors[id] {
				descriptorBytes += n - before[id]
			} else {
				filePayload += n - before[id]
			}
		}
		objectsMu.Unlock()
		if filePayload+descriptorBytes != payload.Load()-p {
			t.Fatal("incomplete object body accounting")
		}
		results[phase] = result{Generation: c.Generation, PayloadBytes: payload.Load() - p, MetadataBytes: metadata.Load() - m, SourceAllocatedBytes: allocated, FilePayloadBytes: filePayload, DescriptorBytes: descriptorBytes, Seconds: time.Since(started).Seconds(), Milestones: status.Milestones}
		encoded, e := json.Marshal(results[phase])
		must(t, e)
		t.Logf("INGRESS_SCALE_CAPTURE phase=%s result=%s", phase, encoded)
		return c
	}
	one := captureOne("base")
	if results["base"].PayloadBytes > size*108/100 {
		t.Fatal("initial encrypted payload exceeds declared1.08amplification", results["base"])
	}
	oracle("mutate", filepath.Join(f.tree, "private.bin"), "patched", "")
	two := captureOne("patched")
	if r := results["patched"]; r.PayloadBytes+r.MetadataBytes > 128<<20 {
		t.Fatal("8MiB change exceeded128MiB received body budget", r)
	}
	three := captureOne("unchanged")
	if results["unchanged"].FilePayloadBytes != 0 || one.Generation == two.Generation || two.Generation == three.Generation || two.Sequence != one.Sequence+1 || three.Sequence != two.Sequence+1 {
		t.Fatal("unchanged payload or generation ordering differs")
	}
	p := ownerExportProfile(t, f)
	raw, err = os.ReadFile(filepath.Join(p.ToolsDirectory, "manifest.json"))
	must(t, err)
	var tools struct {
		Revision string `json:"revision"`
	}
	must(t, json.Unmarshal(raw, &tools))
	pack := filepath.Join(p.Directory, "scale-recovery.tar")
	receipt, err := f.a.ExportRecovery(ctx, p, tools.Revision, pack)
	must(t, err)
	input, err := recoverybundle.Open(pack)
	must(t, err)
	unpacked := filepath.Join(p.Directory, "selected-reader")
	_, err = recoverybundle.Extract(ctx, input, receipt.SHA256, unpacked)
	input.Close()
	must(t, err)
	reader := packagedReader(t, unpacked)
	must(t, f.a.Close())
	f.a = nil
	f.server.Close()
	must(t, f.registry.Close())
	must(t, f.replica.Close())
	// Only exact directories and key files created by this retained fixture.
	must(t, os.RemoveAll(f.tree))
	must(t, os.RemoveAll(f.b.Local.Volume.Root))
	for _, name := range []string{f.b.DataKeyFile, f.b.WriterKeyFile, f.b.AuthorityFile, f.b.Local.CertificateFile, f.b.Local.PrivateKeyFile, f.b.Local.CAFile} {
		must(t, os.Remove(name))
	}
	for _, item := range []struct{ phase, generation string }{{"base", one.Generation}, {"patched", two.Generation}} {
		currentPhase.Store("restore-" + item.phase)
		out := filepath.Join(f.base, "restore-"+item.phase)
		run(reader, "restore-replica", "--key", filepath.Join(unpacked, "recovery-owner.json"), "--trust", filepath.Join(unpacked, "trust.json"), "--store", f.replicaPath, "--generation", item.generation, "--output", out)
		t.Logf("INGRESS_SCALE_RESTORED phase=%s oracle=%s", item.phase, oracle("verify", filepath.Join(out, "private.bin"), item.phase, filepath.Join(out, "alias.bin")))
	}
	t.Logf("INGRESS_SCALE_PASS bytes=%d independent-materialized-versions=2 source-and-authority-removed=true reader-revision=%s", size, tools.Revision)
}
