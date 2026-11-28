package upload

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"golang.org/x/sys/unix"
)

// The owner-side runner prepares this public-trust-only manifest from a
// terminal successful source-scale run. No decryption or old signing key is
// mounted in the upload process group. New lab assignment keys do not renew
// or replay any authority belonging to that source operation.
type externalScaleInput struct {
	Format      string           `json:"format"`
	SourceBytes int64            `json:"sourceBytes"`
	Trust       generation.Trust `json:"trust"`
	Base        string           `json:"base"`
	Patched     string           `json:"patched"`
	Unchanged   string           `json:"unchanged"`
}

type externalScaleChildResult struct {
	Result Result                 `json:"result"`
	HTTP   storage.HTTPBodyCounts `json:"http"`
}

type externalScaleChildConfig struct {
	childConfig
	ReadbackDirectory     string `json:",omitempty"`
	ReadbackMaxAgeSeconds int64  `json:",omitempty"`
}

func TestFullExternalUploadWorkerProcess(t *testing.T) {
	path := os.Getenv("OUTPOST_FULL_EXTERNAL_CHILD")
	if path == "" {
		t.Skip("scale subprocess helper")
	}
	raw, err := os.ReadFile(path)
	must(t, err)
	var cfg externalScaleChildConfig
	must(t, storage.Decode(raw, &cfg, 64<<10))
	raw, err = os.ReadFile(filepath.Join(cfg.Directory, "plan.json"))
	must(t, err)
	journal, err := Open(cfg.Directory, raw, cfg.Worker, cfg.Authority, false)
	must(t, err)
	defer journal.Close()
	if cfg.ReadbackMaxAgeSeconds != 0 {
		if cfg.ReadbackMaxAgeSeconds != 3600 && cfg.ReadbackMaxAgeSeconds != 86400 {
			t.Fatal("unsupported separately admitted readback age")
		}
		root := os.Getenv("OUTPOST_TEST_ROOT")
		rel, err := filepath.Rel(root, cfg.ReadbackDirectory)
		if err != nil || !filepath.IsAbs(root) || !filepath.IsAbs(cfg.ReadbackDirectory) || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatal("readback state outside the admitted fixture")
		}
		cache, err := statefile.Open(cfg.ReadbackDirectory, readback.MaxPage, true)
		must(t, err)
		defer func() { must(t, cache.Close()) }()
		journal.Readback = ReadbackOptions{Store: cache, MaxAgeSeconds: cfg.ReadbackMaxAgeSeconds}
	} else if cfg.ReadbackDirectory != "" {
		t.Fatal("readback directory without an explicit age policy")
	}
	replica, err := generation.Open(cfg.Replica, cfg.Authority.Generation, false)
	must(t, err)
	defer replica.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CA) {
		t.Fatal("invalid pinned scale endpoint certificate")
	}
	backend, err := storage.New(cfg.Profile, storage.Credentials{Access: cfg.Access, Secret: cfg.Secret, ExpiresUnix: cfg.ExpiresUnix}, roots)
	must(t, err)
	defer backend.Close()
	ctx, cancel := context.WithTimeout(t.Context(), cfg.Timeout)
	defer cancel()
	ctx, meter := storage.WithHTTPMeter(ctx, cfg.Profile)
	result, err := journal.Run(ctx, replica, backend, cfg.Key)
	must(t, err)
	state, err := journal.Status(ctx)
	must(t, err)
	if state.Phase != "COMPLETE" || state.Receipt == nil || result.CleanupPending {
		t.Fatal("scale worker did not durably complete and settle its source pin")
	}
	counts := externalScaleMeter(t, meter)
	raw, err = json.Marshal(externalScaleChildResult{Result: result, HTTP: counts})
	must(t, err)
	must(t, os.WriteFile(cfg.Result, raw, 0600))
}

func externalScaleMeter(t *testing.T, meter *storage.HTTPMeter) storage.HTTPBodyCounts {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		counts := meter.Snapshot()
		if !counts.Valid() {
			t.Fatal("invalid scale HTTP body accounting")
		}
		if !counts.Incomplete {
			return counts
		}
		if time.Now().After(deadline) {
			t.Fatal("scale HTTP body accounting remains incomplete after joined requests")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func externalScaleRead(root *os.Root, name string, maximum int64) ([]byte, error) {
	info, err := root.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("invalid bounded immutable input %s", name)
	}
	return root.ReadFile(name)
}

type externalScalePartWrites struct {
	requests int
	bytes    int64
}

type externalScaleTraffic struct {
	mu        sync.Mutex
	putBytes  int64
	partBytes int64
	partPUTs  map[string]externalScalePartWrites
	partGETs  map[string]int
}

type externalScaleRendezvous struct {
	mu     sync.Mutex
	actors map[string]bool
	ready  chan struct{}
	failed bool
}

func newExternalScaleRendezvous() *externalScaleRendezvous {
	return &externalScaleRendezvous{actors: map[string]bool{}, ready: make(chan struct{})}
}

// Admit all three first part requests before writing any of those parts.
// The normal temporary-file/fsync/immutable-create path still follows.
func (b *externalScaleRendezvous) arrive(w http.ResponseWriter, r *http.Request, actor, _ string, _ []byte) bool {
	b.mu.Lock()
	b.actors[actor] = true
	if len(b.actors) == 3 {
		select {
		case <-b.ready:
		default:
			close(b.ready)
		}
	}
	b.mu.Unlock()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	select {
	case <-b.ready:
		return false
	case <-deadline.C:
		http.Error(w, "first part concurrency rendezvous expired", http.StatusServiceUnavailable)
	case <-r.Context().Done():
	}
	b.mu.Lock()
	b.failed = true
	b.mu.Unlock()
	return true
}

func (b *externalScaleRendezvous) complete() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.actors) == 3 && !b.failed
}

func TestScaleRendezvousRequiresThreeActualPartRequests(t *testing.T) {
	for _, third := range []bool{false, true} {
		t.Run(fmt.Sprint(third), func(t *testing.T) {
			barrier := newExternalScaleRendezvous()
			logins := map[string]teststore.Login{}
			for n := range 3 {
				logins[fmt.Sprint(n)] = teststore.Login{Secret: "synthetic-rendezvous-credential"}
			}
			server := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte(t.Name())), Logins: logins, BeforePartWrite: barrier.arrive})
			p := storage.Profile{Kind: "webdav", Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10,
				Concurrency: 1, RequestsPerSecond: 1000, Attempts: 1, TimeoutMillis: 5000, CredentialScope: "namespace", NoDelete: true}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 3)
			start := func(n int) {
				access := fmt.Sprint(n)
				backend, err := storage.New(p, storage.Credentials{Access: access, Secret: logins[access].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, server.Roots)
				must(t, err)
				t.Cleanup(backend.Close)
				go func() {
					body := []byte("rendezvous-payload-" + access)
					done <- backend.PutPart(ctx, generation.Object{ID: storage.Hash(body), Bytes: len(body)}, body)
				}()
			}
			start(0)
			start(1)
			deadline := time.Now().Add(3 * time.Second)
			for {
				barrier.mu.Lock()
				arrived := len(barrier.actors)
				barrier.mu.Unlock()
				if arrived == 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("two authenticated part requests did not enter the real endpoint")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if snapshot := server.Snapshot(); len(snapshot.Writes) != 0 || barrier.complete() {
				t.Fatal("endpoint wrote or declared concurrency before the third actual request")
			}
			count := 2
			if third {
				start(2)
				count++
			} else {
				cancel()
			}
			for range count {
				select {
				case err := <-done:
					if (err == nil) != third {
						t.Fatal("unexpected real part request result", err)
					}
				case <-time.After(6 * time.Second):
					t.Fatal("part requests did not stop")
				}
			}
			snapshot := server.Snapshot()
			if third {
				if !barrier.complete() || snapshot.PeakWorkers != 3 || len(snapshot.Writes) != 3 {
					t.Fatal("three requests did not perform real distinct immutable writes", snapshot)
				}
			} else if len(snapshot.Writes) != 0 || barrier.complete() {
				t.Fatal("cancelled rendezvous wrote data or declared success")
			}
		})
	}
}

func (c *externalScaleTraffic) observe(_ http.ResponseWriter, r *http.Request, _, key string, body []byte) bool {
	if r.Method == http.MethodGet && strings.HasPrefix(key, "part-") {
		c.mu.Lock()
		c.partGETs[strings.TrimPrefix(key, "part-")]++
		c.mu.Unlock()
	}
	if r.Method == http.MethodPut {
		c.mu.Lock()
		c.putBytes += int64(len(body))
		if strings.HasPrefix(key, "part-") {
			c.partBytes += int64(len(body))
			id := strings.TrimPrefix(key, "part-")
			writes := c.partPUTs[id]
			writes.requests++
			writes.bytes += int64(len(body))
			c.partPUTs[id] = writes
		}
		c.mu.Unlock()
	}
	return false
}

func (c *externalScaleTraffic) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putBytes, c.partBytes = 0, 0
	c.partPUTs = map[string]externalScalePartWrites{}
	c.partGETs = map[string]int{}
}

func (c *externalScaleTraffic) retainedReads(refs map[string]int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for id, n := range c.partGETs {
		if _, retained := refs[id]; retained {
			count += n
		}
	}
	return count
}

func externalScalePhysicalParts(plan Plan) map[string]int {
	parts := map[string]int{}
	for _, blob := range plan.Blobs {
		for _, part := range blob.Parts {
			parts[part.ID] = part.Bytes
		}
	}
	return parts
}

func externalScaleUnchangedParts(catalog storage.Blob, writes map[string]externalScalePartWrites, retained, current map[string]int) (catalogBytes, dependencyBytes int64, err error) {
	catalogParts := make(map[string]int, len(catalog.Parts))
	for _, part := range catalog.Parts {
		catalogParts[part.ID] = part.Bytes
	}
	for id, write := range writes {
		if _, existed := retained[id]; existed {
			return 0, 0, fmt.Errorf("unchanged phase retransmitted retained part %s", id)
		}
		if size, known := catalogParts[id]; known {
			if write.requests < 1 || write.bytes != int64(size)*int64(write.requests) {
				return 0, 0, fmt.Errorf("unexpected catalog part body size for %s", id)
			}
			catalogBytes += write.bytes
			continue
		}
		size, known := current[id]
		if !known || write.requests < 1 || write.bytes != int64(size)*int64(write.requests) {
			return 0, 0, fmt.Errorf("unexpected dependency part or body size for %s", id)
		}
		dependencyBytes += write.bytes
	}
	if dependencyBytes > 64<<10 {
		return 0, 0, fmt.Errorf("unchanged phase sent %d new dependency part bytes, exceeding 64 KiB", dependencyBytes)
	}
	return catalogBytes, dependencyBytes, nil
}

func externalScaleCacheRecords(t *testing.T, cfg childConfig, directory string, age int64, backend *storage.Backend) (map[string]readback.Record, int64) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cfg.Directory, "plan.json"))
	must(t, err)
	journal, err := Open(cfg.Directory, raw, cfg.Worker, cfg.Authority, false)
	must(t, err)
	defer journal.Close()
	cache, err := statefile.Open(directory, readback.MaxPage, false)
	must(t, err)
	defer func() { must(t, cache.Close()) }()
	journal.Readback = ReadbackOptions{Store: cache, MaxAgeSeconds: age}
	audit, err := journal.newAudit(t.Context(), backend)
	must(t, err)
	defer audit.close()
	// Inspect only persisted local evidence after every worker has exited.
	// This is not another network audit or a current-persistence claim.
	records := map[string]readback.Record{}
	oldest := time.Now().Unix()
	for id := range audit.blobs {
		proof, present := audit.proofs[id]
		if !present || !audit.usable(id) {
			t.Fatal("completed worker lacks current age-bound local evidence")
		}
		records[audit.keys[id].ID] = proof.Record
		oldest = min(oldest, proof.ObservedUnix)
	}
	return records, oldest
}

func TestScaleRetainedTrafficUsesActualMultipartIDs(t *testing.T) {
	f := fixtureBytes(t, 128<<10)
	traffic := &externalScaleTraffic{}
	traffic.reset()
	server := f.server(t, "webdav", 0, traffic.observe)
	backend := f.backend(t, server, 0)
	plan, err := Verify(f.plan(t, server, 1, 500), f.authority)
	must(t, err)
	retained := externalScalePhysicalParts(plan)
	for _, blob := range plan.Blobs {
		if len(blob.Parts) < 2 {
			continue
		}
		payload, err := f.replicas[0].ReadObject(t.Context(), f.id, blob.Object)
		must(t, err)
		offset := 0
		for _, part := range blob.Parts {
			must(t, backend.PutPart(t.Context(), part, payload[offset:offset+part.Bytes]))
			offset += part.Bytes
		}
		must(t, backend.SealBlob(t.Context(), blob))
		traffic.reset()
		got, err := backend.ReadBlob(t.Context(), blob.Object)
		must(t, err)
		if storage.Hash(got) != blob.Object.ID || traffic.retainedReads(retained) != len(blob.Parts) {
			t.Fatal("actual multipart reads escaped retained physical-part accounting")
		}
		if traffic.retainedReads(map[string]int{blob.Object.ID: blob.Object.Bytes}) != 0 {
			t.Fatal("fixture did not distinguish logical object IDs from physical parts")
		}
		traffic.reset()
		part := blob.Parts[0]
		must(t, backend.PutPart(t.Context(), part, payload[:part.Bytes]))
		_, _, attempts := traffic.snapshot()
		if attempts[part.ID] != (externalScalePartWrites{requests: 1, bytes: int64(part.Bytes)}) || retained[part.ID] != part.Bytes || server.Snapshot().Writes["part-"+part.ID] != 1 {
			t.Fatal("retained multipart PUT was missed or immutable data was rewritten")
		}
		return
	}
	t.Fatal("fixture did not create a real split object")
}

func TestScaleUnchangedPartsSeparateSignedCatalog(t *testing.T) {
	f := fixtureBytes(t, 128<<10)
	traffic := &externalScaleTraffic{}
	traffic.reset()
	server := f.server(t, "webdav", 0, traffic.observe)
	backend := f.backend(t, server, 0)
	trust := f.authority.Generation
	metadata := []byte("new synthetic dependency metadata")
	ref := generation.Object{ID: storage.Hash(metadata), Bytes: len(metadata)}
	objects := []generation.Object{ref}
	for n := range 1024 {
		objects = append(objects, generation.Object{ID: storage.Hash([]byte(strconv.Itoa(n))), Bytes: 1})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	raw, err := generation.SignCatalog(generation.Catalog{
		Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch,
		Sequence: 1, SnapshotUnix: 1, Policy: 1, KitFormat: generation.TypedKitFormat,
		Kits: []generation.Kit{{File: storage.Hash([]byte("test file")), Version: storage.Hash([]byte("test version")),
			Root: generation.Object{ID: storage.Hash([]byte("test root")), Bytes: 1}, Objects: objects}},
	}, f.writer)
	must(t, err)
	_, err = generation.VerifyCatalog(raw, trust)
	must(t, err)
	if len(raw) <= 64<<10 {
		t.Fatal("catalog fixture did not exceed the dependency bound")
	}
	ctx := t.Context()
	catalog := generation.Object{ID: storage.Hash(raw), Bytes: len(raw)}
	blob, err := storage.Describe(catalog, raw, server.Options.MaxObject)
	must(t, err)
	if len(blob.Parts) < 2 {
		t.Fatal("fixture did not create a split catalog")
	}
	for range 3 {
		must(t, backend.PutBlob(ctx, catalog, raw))
	}
	must(t, backend.PutPart(ctx, ref, metadata))
	_, total, writes := traffic.snapshot()
	current := map[string]int{ref.ID: ref.Bytes}
	catalogBytes, dependencyBytes, err := externalScaleUnchangedParts(blob, writes, nil, current)
	must(t, err)
	if catalogBytes != 3*int64(len(raw)) || dependencyBytes != int64(len(metadata)) || total != catalogBytes+dependencyBytes {
		t.Fatal("catalog and dependency bodies were not separately accounted", catalogBytes, dependencyBytes, total)
	}
	if _, _, err := externalScaleUnchangedParts(blob, writes, current, current); err == nil {
		t.Fatal("retained dependency PUT escaped the accounting")
	}
	if _, _, err := externalScaleUnchangedParts(blob, writes, nil, nil); err == nil {
		t.Fatal("unknown dependency PUT escaped the accounting")
	}
	tooLarge := externalScalePartWrites{requests: 1, bytes: 64<<10 + 1}
	if _, _, err := externalScaleUnchangedParts(blob, map[string]externalScalePartWrites{ref.ID: tooLarge}, nil, map[string]int{ref.ID: int(tooLarge.bytes)}); err == nil {
		t.Fatal("new dependency PUT exceeded the unchanged byte bound")
	}
	part := blob.Parts[0]
	write := writes[part.ID]
	write.bytes++
	writes[part.ID] = write
	if _, _, err := externalScaleUnchangedParts(blob, writes, nil, current); err == nil {
		t.Fatal("catalog part with an incorrect body size escaped the accounting")
	}
}

func (c *externalScaleTraffic) snapshot() (int64, int64, map[string]externalScalePartWrites) {
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := make(map[string]externalScalePartWrites, len(c.partPUTs))
	for id, writes := range c.partPUTs {
		parts[id] = writes
	}
	return c.putBytes, c.partBytes, parts
}

func externalScaleRunChildren(t *testing.T, children []*child, timeout time.Duration) {
	t.Helper()
	type outcome struct {
		index int
		err   error
	}
	done := make(chan outcome, len(children))
	started, joined := 0, 0
	// Join every child before a failed protocol can close its endpoint or
	// permit another phase. The original short-test helper stays unchanged.
	t.Cleanup(func() {
		if joined == started {
			return
		}
		for _, c := range children[:started] {
			_ = c.cmd.Process.Kill()
		}
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		for joined < started {
			select {
			case <-done:
				joined++
			case <-deadline.C:
				t.Errorf("scale worker stop did not join all children: %d/%d", joined, started)
				return
			}
		}
	})
	for index, c := range children {
		binary, err := os.Executable()
		must(t, err)
		c.cmd = exec.Command(binary, "-test.run=^TestFullExternalUploadWorkerProcess$", "-test.timeout="+(c.config.Timeout+5*time.Second).String())
		c.cmd.Env = append(os.Environ(), "OUTPOST_FULL_EXTERNAL_CHILD="+c.path)
		c.cmd.Stdout, c.cmd.Stderr = &c.log, &c.log
		c.done = make(chan error, 1)
		must(t, c.cmd.Start())
		started++
		go func() { c.done <- c.cmd.Wait() }()
		go func() { done <- outcome{index, <-c.done} }()
	}
	deadline := time.NewTimer(timeout + 5*time.Second)
	defer deadline.Stop()
	for joined < started {
		select {
		case result := <-done:
			joined++
			if result.err != nil {
				t.Fatalf("scale worker failed: %v %s", result.err, children[result.index].log.String())
			}
		case <-deadline.C:
			t.Fatal("scale workers exceeded the admitted whole-operation window")
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

// This is deliberately separate from the unchanged short latency/failover
// profiles. A shared-HDD scale execution cannot establish the 1.5x promise.
func TestFullGenerationExternalScale(t *testing.T) {
	if os.Getenv("OUTPOST_FULL_EXTERNAL_SCALE") != "1" {
		t.Skip("requires separately admitted HDD source generations and reserve")
	}
	inputDirectory, root := os.Getenv("OUTPOST_FULL_EXTERNAL_INPUT"), os.Getenv("OUTPOST_TEST_ROOT")
	if !filepath.IsAbs(inputDirectory) || !filepath.IsAbs(root) || inputDirectory == root {
		t.Fatal("separate absolute immutable input and admitted output roots required")
	}
	input, err := os.OpenRoot(inputDirectory)
	must(t, err)
	defer input.Close()
	raw, err := externalScaleRead(input, "input.json", 64<<10)
	must(t, err)
	var source externalScaleInput
	must(t, storage.Decode(raw, &source, 64<<10))
	if source.Format != "outpost-external-scale-input-1" || source.SourceBytes != 128<<20 && source.SourceBytes != 100<<30 {
		t.Fatal("only the admitted128MiB or physical100GiB source profile is supported")
	}
	var readbackAge int64
	if value := os.Getenv("OUTPOST_FULL_EXTERNAL_READBACK_MAX_AGE_SECONDS"); value != "" {
		readbackAge, err = strconv.ParseInt(value, 10, 64)
		must(t, err)
		if readbackAge != 0 && readbackAge != 3600 && readbackAge != 86400 {
			t.Fatal("only fresh, one-hour rehearsal or one-day full readback policies are admitted")
		}
	}
	t.Logf("EXTERNAL_SCALE_READBACK maximum-age-seconds=%d fresh-recovery-required=true", readbackAge)
	var fs unix.Statfs_t
	must(t, unix.Statfs(root, &fs))
	fsid := fmt.Sprintf("%x", uint64(uint32(fs.Fsid.Val[0]))|uint64(uint32(fs.Fsid.Val[1]))<<32)
	if fsid != os.Getenv("OUTPOST_FULL_EXTERNAL_FSID") {
		t.Fatal("output filesystem differs from the admitted HDD")
	}
	checkReserve := func(t *testing.T) {
		t.Helper()
		must(t, unix.Statfs(root, &fs))
		if uint64(fs.Bavail)*uint64(fs.Bsize) < uint64(fs.Blocks)*uint64(fs.Bsize)/5+uint64(14*source.SourceBytes)+(1<<30) {
			t.Fatal("insufficient20percent reserve plus conservative full fixture/recovery overlap")
		}
	}
	checkReserve(t)
	base := filepath.Join(root, "full-external-scale")
	must(t, os.Mkdir(base, 0700)) // Existing or unknown data is never adopted or removed.
	f := &fixture{base: base, childTimeout: 24 * time.Hour}
	plannerPublic, planner, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	f.planner, f.authority = planner, Authority{Generation: source.Trust, Planner: plannerPublic}
	for range 3 {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		must(t, err)
		f.keys = append(f.keys, key)
		f.workers = append(f.workers, Worker{ID: Identity(pub), Class: "trusted", PublicKey: pub})
	}
	ctx := t.Context()
	ids := []string{source.Base, source.Patched, source.Unchanged}
	catalogs := make([][]byte, len(ids))
	for n, id := range ids {
		if !storage.ID(id) {
			t.Fatal("invalid expected generation")
		}
		catalogs[n], err = externalScaleRead(input, "catalogs/"+id, generation.MaxCatalog)
		must(t, err)
		if storage.Hash(catalogs[n]) != id {
			t.Fatal("input catalog digest differs")
		}
		_, err = generation.Dependencies(catalogs[n], source.Trust)
		must(t, err)
	}
	// Every worker receives its own physically copied full retained history.
	// These are distinct files, not hardlinked input views or shards. The lab
	// still shares a host/controller and does not prove physical failure domains.
	for n := range 3 {
		dir := filepath.Join(base, fmt.Sprintf("holder-%d", n))
		must(t, os.Mkdir(dir, 0700))
		replica, err := generation.Open(dir, source.Trust, true)
		must(t, err)
		t.Cleanup(func() { must(t, replica.Close()) })
		f.replicas, f.dirs = append(f.replicas, replica), append(f.dirs, dir)
		for phase, catalog := range catalogs {
			id, err := replica.Receive(ctx, catalog, func(ref generation.Object) ([]byte, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				data, err := externalScaleRead(input, "objects/"+ref.ID, int64(ref.Bytes))
				if err != nil || len(data) != ref.Bytes || storage.Hash(data) != ref.ID {
					return nil, fmt.Errorf("invalid immutable source object %s", ref.ID)
				}
				return data, nil
			})
			must(t, err)
			if id != ids[phase] {
				t.Fatal("physical holder received a different generation")
			}
		}
		t.Logf("EXTERNAL_SCALE_HOLDER_READY holder=%d retained-generations=%d", n, len(ids))
	}
	for _, kind := range []string{"s3", "webdav"} {
		if !t.Run(kind, func(t *testing.T) {
			checkReserve(t)
			dir := filepath.Join(base, kind)
			must(t, os.Mkdir(dir, 0700))
			logins := map[string]teststore.Login{}
			for _, worker := range f.workers {
				logins[worker.ID] = teststore.Login{Secret: "synthetic-scale-credential"}
			}
			traffic := &externalScaleTraffic{}
			traffic.reset()
			rendezvous := newExternalScaleRendezvous()
			target := teststore.New(t, teststore.Options{Kind: kind, Namespace: storage.Hash([]byte(source.Trust.Domain + "/" + source.Trust.Repository)),
				Directory: dir, MaxObject: 8 << 20, Delay: 10 * time.Millisecond, Logins: logins, Before: traffic.observe, BeforePartWrite: rendezvous.arrive})
			p := storage.Profile{Kind: kind, Endpoint: target.Endpoint(), Namespace: target.Options.Namespace, MaxObjectBytes: target.Options.MaxObject,
				Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 30000, CredentialScope: "namespace", NoDelete: true}
			if kind == "s3" {
				p.Region = target.Options.Region
			}
			backend, err := storage.New(p, storage.Credentials{Access: f.workers[0].ID, Secret: logins[f.workers[0].ID].Secret, ExpiresUnix: f.expiresUnix()}, target.Roots)
			must(t, err)
			defer backend.Close()
			priorEvidence := make([]map[string]readback.Record, len(f.workers))
			retainedParts := map[string]int{}
			for phase, name := range []string{"base", "patched", "unchanged"} {
				started := time.Now()
				traffic.reset()
				phaseContext, phaseMeter := storage.WithHTTPMeter(ctx, p)
				if phase == 1 {
					if err := backend.Publish(phaseContext, catalogs[phase], source.Trust); err == nil {
						t.Fatal("incomplete increment was published")
					}
					if _, err := backend.Catalog(phaseContext, ids[phase], source.Trust); !storage.Missing(err) {
						t.Fatal("incomplete increment exposed a complete marker", err)
					}
				}
				plan, err := Build(ctx, f.replicas[0], ids[phase], Plan{Format: Format, Operation: storage.Hash([]byte(kind + "/" + name + "/" + ids[phase])),
					Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: f.workers, StartMillis: time.Now().Add(200 * time.Millisecond).UnixMilli(), ExpiresUnix: f.expiresUnix(), SlotMillis: 30000}, planner)
				must(t, err)
				verifiedPlan, err := Verify(plan, f.authority)
				must(t, err)
				children := make([]*child, 3)
				for n := range children {
					f.serial++
					job := filepath.Join(base, fmt.Sprintf("job-%d", f.serial))
					must(t, os.Mkdir(job, 0700))
					journal, err := Open(job, plan, f.workers[n].ID, f.authority, true)
					must(t, err)
					must(t, journal.Close())
					cfg := childConfig{Directory: job, Replica: f.dirs[n], Worker: f.workers[n].ID, Result: job + "/result.json", Access: f.workers[n].ID,
						Secret: logins[f.workers[n].ID].Secret, Key: f.keys[n], Authority: f.authority, Profile: p, ExpiresUnix: f.expiresUnix(), Timeout: f.childTimeout,
						CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.HTTP.Certificate().Raw})}
					childCfg := externalScaleChildConfig{childConfig: cfg}
					if readbackAge > 0 {
						childCfg.ReadbackDirectory = filepath.Join(base, fmt.Sprintf("readback-%s-%d", kind, n))
						childCfg.ReadbackMaxAgeSeconds = readbackAge
						if phase == 0 {
							must(t, os.Mkdir(childCfg.ReadbackDirectory, 0700))
						}
					}
					data, err := json.Marshal(childCfg)
					must(t, err)
					path := job + "/child.json"
					must(t, os.WriteFile(path, data, 0600))
					children[n] = &child{config: cfg, path: path}
				}
				externalScaleRunChildren(t, children, f.childTimeout)
				putBytes, partBytes, partPUTs := traffic.snapshot()
				if phase == 1 && putBytes > 128<<20 {
					t.Fatalf("8MiB replacement exceeded128MiB received PUT bodies: %d", putBytes)
				}
				if phase == 2 {
					if readbackAge > 0 && traffic.retainedReads(retainedParts) != 0 {
						t.Fatal("enabled readback reuse fetched retained payload during unchanged capture")
					}
					catalog := generation.Object{ID: ids[phase], Bytes: len(catalogs[phase])}
					catalogBlob, err := storage.Describe(catalog, catalogs[phase], p.MaxObjectBytes)
					must(t, err)
					catalogBytes, dependencyBytes, err := externalScaleUnchangedParts(catalogBlob, partPUTs, retainedParts, externalScalePhysicalParts(verifiedPlan))
					must(t, err)
					if catalogBytes+dependencyBytes != partBytes {
						t.Fatal("unchanged part accounting differs from total received part bytes")
					}
					t.Logf("EXTERNAL_SCALE_UNCHANGED_PARTS protocol=%s catalog-body-bytes=%d dependency-body-bytes=%d total-part-body-bytes=%d", kind, catalogBytes, dependencyBytes, partBytes)
				}
				snapshot := target.Snapshot()
				actors := map[string]bool{}
				for _, event := range snapshot.Events {
					actors[event.Actor] = true
				}
				if phase == 0 && (len(actors) != 3 || snapshot.PeakWorkers != 3 || !rendezvous.complete()) {
					t.Fatal("three distinct concurrent durable uploaders missing", len(actors), snapshot.PeakWorkers)
				}
				for key, count := range snapshot.Writes {
					if count != 1 {
						t.Fatal("immutable target key physically rewritten", key, count)
					}
				}
				if _, err := backend.Catalog(phaseContext, ids[phase], source.Trust); err != nil {
					t.Fatal("complete target closure unavailable", err)
				}
				for n, c := range children {
					data, err := os.ReadFile(c.config.Result)
					must(t, err)
					var proof externalScaleChildResult
					must(t, storage.Decode(data, &proof, 64<<10))
					if !proof.HTTP.Valid() || proof.HTTP.Incomplete || proof.Result.CleanupPending {
						t.Fatal("incomplete scale worker result or HTTP accounting")
					}
					if readbackAge > 0 {
						directory := filepath.Join(base, fmt.Sprintf("readback-%s-%d", kind, n))
						records, oldest := externalScaleCacheRecords(t, c.config, directory, readbackAge, backend)
						preserved := 0
						for id, record := range records {
							if old, existed := priorEvidence[n][id]; existed {
								if old != record {
									t.Fatal("retained object evidence changed its supporting time or length")
								}
								preserved++
							}
						}
						if proof.Result.Receipt.ObservedUnix != oldest || phase > 0 && (preserved == 0 || proof.Result.Receipt.Verification != "cached-target-readback") {
							t.Fatal("receipt age differs from its current dependency evidence or claims fresh verification", proof.Result.Receipt)
						}
						priorEvidence[n] = records
						t.Logf("EXTERNAL_SCALE_CACHE protocol=%s phase=%s worker=%d records=%d preserved=%d oldest=%d", kind, name, n, len(records), preserved, oldest)
					}
					t.Logf("EXTERNAL_SCALE_HTTP protocol=%s phase=%s worker=%d counts=%s", kind, name, n, data)
				}
				parentCounts, err := json.Marshal(externalScaleMeter(t, phaseMeter))
				must(t, err)
				t.Logf("EXTERNAL_SCALE_HTTP protocol=%s phase=%s worker=parent counts=%s", kind, name, parentCounts)
				t.Logf("EXTERNAL_SCALE_CAPTURE protocol=%s phase=%s source-bytes=%d received-put-body-bytes=%d part-body-bytes=%d parts=%d actors=%d peak=%d seconds=%.6f", kind, name, source.SourceBytes, putBytes, partBytes, len(partPUTs), len(actors), snapshot.PeakWorkers, time.Since(started).Seconds())
				retainedParts = externalScalePhysicalParts(verifiedPlan)
			}
			// A fresh materialized store is downloaded through the actual adapter.
			// The separate consumer stage will mount only its immutable files,
			// public trust/recovery material and the pinned standalone reader.
			recovered := filepath.Join(base, "recovered-"+kind)
			must(t, os.Mkdir(recovered, 0700))
			replica, err := generation.Open(recovered, source.Trust, true)
			must(t, err)
			defer replica.Close()
			recoveryContext, recoveryMeter := storage.WithHTTPMeter(ctx, p)
			for _, id := range ids {
				must(t, backend.Recover(recoveryContext, id, replica))
			}
			recoveryCounts, err := json.Marshal(externalScaleMeter(t, recoveryMeter))
			must(t, err)
			t.Logf("EXTERNAL_SCALE_HTTP protocol=%s phase=recover counts=%s", kind, recoveryCounts)
			t.Logf("EXTERNAL_SCALE_RECOVERED protocol=%s retained-generations=%d", kind, len(ids))
		}) {
			t.FailNow()
		}
	}
	t.Logf("EXTERNAL_SCALE_PASS source-bytes=%d holders=3 upload-processes=3 protocols=2 retained-generations=%d standalone-consumers-pending=true", source.SourceBytes, len(ids))
}
