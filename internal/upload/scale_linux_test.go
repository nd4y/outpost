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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
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

func TestFullExternalUploadWorkerProcess(t *testing.T) {
	path := os.Getenv("OUTPOST_FULL_EXTERNAL_CHILD")
	if path == "" {
		t.Skip("scale subprocess helper")
	}
	raw, err := os.ReadFile(path)
	must(t, err)
	var cfg childConfig
	must(t, storage.Decode(raw, &cfg, 64<<10))
	raw, err = os.ReadFile(filepath.Join(cfg.Directory, "plan.json"))
	must(t, err)
	journal, err := Open(cfg.Directory, raw, cfg.Worker, cfg.Authority, false)
	must(t, err)
	defer journal.Close()
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

type externalScaleTraffic struct {
	mu        sync.Mutex
	putBytes  int64
	partBytes int64
	partPUTs  map[string]int
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
	if r.Method == http.MethodPut {
		c.mu.Lock()
		c.putBytes += int64(len(body))
		if strings.HasPrefix(key, "part-") {
			c.partBytes += int64(len(body))
			c.partPUTs[strings.TrimPrefix(key, "part-")]++
		}
		c.mu.Unlock()
	}
	return false
}

func (c *externalScaleTraffic) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putBytes, c.partBytes = 0, 0
	c.partPUTs = map[string]int{}
}

func (c *externalScaleTraffic) snapshot() (int64, int64, map[string]int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := make(map[string]int, len(c.partPUTs))
	for id, count := range c.partPUTs {
		parts[id] = count
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
	refs := make([]map[string]int, len(ids))
	for n, id := range ids {
		if !storage.ID(id) {
			t.Fatal("invalid expected generation")
		}
		catalogs[n], err = externalScaleRead(input, "catalogs/"+id, generation.MaxCatalog)
		must(t, err)
		if storage.Hash(catalogs[n]) != id {
			t.Fatal("input catalog digest differs")
		}
		dependencies, err := generation.Dependencies(catalogs[n], source.Trust)
		must(t, err)
		refs[n] = make(map[string]int, len(dependencies))
		for _, ref := range dependencies {
			refs[n][ref.ID] = ref.Bytes
		}
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
					data, err := json.Marshal(cfg)
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
					if partBytes > 64<<10 {
						t.Fatal("unchanged source created unexpected new file-sized payload", partBytes)
					}
					for id := range partPUTs {
						if _, existed := refs[1][id]; existed {
							t.Fatal("unchanged phase retransmitted a retained payload or descriptor", id)
						}
					}
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
					t.Logf("EXTERNAL_SCALE_HTTP protocol=%s phase=%s worker=%d counts=%s", kind, name, n, data)
				}
				parentCounts, err := json.Marshal(externalScaleMeter(t, phaseMeter))
				must(t, err)
				t.Logf("EXTERNAL_SCALE_HTTP protocol=%s phase=%s worker=parent counts=%s", kind, name, parentCounts)
				t.Logf("EXTERNAL_SCALE_CAPTURE protocol=%s phase=%s source-bytes=%d received-put-body-bytes=%d part-body-bytes=%d parts=%d actors=%d peak=%d seconds=%.6f", kind, name, source.SourceBytes, putBytes, partBytes, len(partPUTs), len(actors), snapshot.PeakWorkers, time.Since(started).Seconds())
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
