package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type fixture struct {
	base, input, id, version     string
	data                         []byte
	owner                        filekit.Owner
	store                        *filekit.Store
	authority                    Authority
	planner, writer, maintenance ed25519.PrivateKey
	replicas                     []*generation.Replica
	dirs                         []string
	workers                      []Worker
	keys                         []ed25519.PrivateKey
	serial                       int
	childTimeout                 time.Duration
}

func newFixture(t *testing.T) *fixture {
	return fixtureBytes(t, 3<<20)
}
func fixtureBytes(t *testing.T, size int) *fixture {
	f := &fixture{base: teststore.Root(t)}
	var e error
	f.owner, e = filekit.NewOwner()
	must(t, e)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	maintenance, maintenanceKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	plannerPub, planner, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.writer = key
	f.planner = planner
	f.maintenance = maintenanceKey
	f.authority = Authority{generation.Trust{Domain: f.owner.Domain, Repository: storage.Hash([]byte("synthetic repository")), Epoch: 1, Writer: pub, Maintenance: maintenance}, plannerPub}
	f.store, e = filekit.OpenStore(filepath.Join(f.base, "source-store"), f.owner, true)
	must(t, e)
	t.Cleanup(func() { f.store.Close() })
	f.input = filepath.Join(f.base, "input")
	f.data = make([]byte, size)
	_, e = rand.Read(f.data)
	must(t, e)
	copy(f.data, []byte("private-source-marker-not-for-external-plaintext"))
	must(t, os.WriteFile(f.input, f.data, 0640))
	for i := 0; i < 3; i++ {
		dir := filepath.Join(f.base, "replica-"+string(rune('a'+i)))
		must(t, os.Mkdir(dir, 0700))
		r, e := generation.Open(dir, f.authority.Generation, true)
		must(t, e)
		f.dirs = append(f.dirs, dir)
		f.replicas = append(f.replicas, r)
		t.Cleanup(func() { r.Close() })
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		must(t, e)
		f.workers = append(f.workers, Worker{ID: Identity(pub), Class: "trusted", PublicKey: pub})
		f.keys = append(f.keys, key)
	}
	f.id, f.version = f.capture(t, 1, "")
	return f
}
func (f *fixture) capture(t *testing.T, seq uint64, parent string) (string, string) {
	v, e := f.store.Backup(context.Background(), f.input, filekit.BackupOptions{Names: []string{"do-not-export-private-name.bin", "alias.bin"}})
	must(t, e)
	c := generation.Catalog{Format: generation.Format, Domain: f.authority.Generation.Domain, Repository: f.authority.Generation.Repository, Epoch: 1, Sequence: seq, Parent: parent, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}
	id, e := generation.Seal(context.Background(), f.store, []string{v.Version}, f.replicas[0], c, f.writer)
	must(t, e)
	raw, e := f.replicas[0].Catalog(context.Background(), id)
	must(t, e)
	for _, r := range f.replicas[1:] {
		_, e = r.Receive(context.Background(), raw, func(ref generation.Object) ([]byte, error) {
			return f.replicas[0].ReadObject(context.Background(), id, ref)
		})
		must(t, e)
	}
	return id, v.Version
}
func (f *fixture) server(t *testing.T, kind string, delay time.Duration, before teststore.Hook) *teststore.Server {
	return f.externalServer(t, teststore.Options{Kind: kind, Delay: delay, Before: before})
}

func (f *fixture) externalServer(t *testing.T, options teststore.Options) *teststore.Server {
	t.Helper()
	logins := map[string]teststore.Login{}
	for i, w := range f.workers {
		logins[w.ID] = teststore.Login{Secret: "test-secret-" + string(rune('a'+i))}
	}
	options.Namespace = storage.Hash([]byte(f.authority.Generation.Domain + "/" + f.authority.Generation.Repository))
	options.Logins = logins
	return teststore.New(t, options)
}
func profile(s *teststore.Server) storage.Profile {
	p := storage.Profile{Kind: s.Options.Kind, Endpoint: s.Endpoint(), Namespace: s.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 3000, CredentialScope: "namespace", NoDelete: true}
	if p.Kind == "s3" {
		p.Region = s.Options.Region
	}
	if s.Options.MoveOnly {
		p.WriteMode = storage.WebDAVMoveMode
		p.MaxStagingAttempts = 3
	}
	return p
}
func (f *fixture) backend(t *testing.T, s *teststore.Server, worker int) *storage.Backend {
	b, e := storage.New(profile(s), storage.Credentials{Access: f.workers[worker].ID, Secret: s.Options.Logins[f.workers[worker].ID].Secret, ExpiresUnix: f.expiresUnix()}, s.Roots)
	must(t, e)
	t.Cleanup(b.Close)
	return b
}
func (f *fixture) expiresUnix() int64 {
	return time.Now().Add(max(time.Minute, 2*f.childTimeout)).Unix()
}
func (f *fixture) plan(t *testing.T, s *teststore.Server, workers int, slot int64) []byte {
	p := Plan{Format: Format, Operation: storage.Hash([]byte(s.Endpoint() + "/" + f.id)), Profile: profile(s), AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: f.workers[:workers], StartMillis: time.Now().Add(200 * time.Millisecond).UnixMilli(), ExpiresUnix: f.expiresUnix(), SlotMillis: slot}
	raw, e := Build(context.Background(), f.replicas[0], f.id, p, f.planner)
	must(t, e)
	return raw
}

type childConfig struct {
	Directory, Replica, Worker, Result, Access, Secret string
	Key                                                ed25519.PrivateKey
	Authority                                          Authority
	Profile                                            storage.Profile
	CA                                                 []byte
	ExpiresUnix                                        int64
	Timeout                                            time.Duration
}
type child struct {
	cmd    *exec.Cmd
	log    bytes.Buffer
	done   chan error
	config childConfig
	path   string
}

func (f *fixture) prepare(t *testing.T, s *teststore.Server, raw []byte, worker int) *child {
	f.serial++
	dir := filepath.Join(f.base, "job-"+string(rune('a'+f.serial)))
	must(t, os.Mkdir(dir, 0700))
	j, e := Open(dir, raw, f.workers[worker].ID, f.authority, true)
	must(t, e)
	must(t, j.Close())
	cfg := childConfig{Directory: dir, Replica: f.dirs[worker], Worker: f.workers[worker].ID, Result: dir + "/result.json", Access: f.workers[worker].ID, Secret: s.Options.Logins[f.workers[worker].ID].Secret, Key: f.keys[worker], Authority: f.authority, Profile: profile(s), CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.HTTP.Certificate().Raw}), ExpiresUnix: f.expiresUnix(), Timeout: max(20*time.Second, f.childTimeout)}
	data, e := json.Marshal(cfg)
	must(t, e)
	path := dir + "/child.json"
	must(t, os.WriteFile(path, data, 0600))
	return &child{config: cfg, path: path}
}
func (c *child) start(t *testing.T) {
	t.Helper()
	binary, e := os.Executable()
	must(t, e)
	c.cmd = exec.Command(binary, "-test.run=^TestExternalUploadWorkerProcess$", "-test.timeout="+(c.config.Timeout+5*time.Second).String())
	c.cmd.Env = append(os.Environ(), "OUTPOST_UPLOAD_CHILD="+c.path)
	c.cmd.Stdout = &c.log
	c.cmd.Stderr = &c.log
	c.done = make(chan error, 1)
	must(t, c.cmd.Start())
	go func() { c.done <- c.cmd.Wait() }()
	t.Cleanup(func() {
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
	})
}
func (c *child) wait(t *testing.T, success bool) {
	t.Helper()
	select {
	case e := <-c.done:
		if success && e != nil {
			t.Fatalf("worker failed: %v %s", e, c.log.String())
		}
		if !success && e == nil {
			t.Fatal("killed worker unexpectedly succeeded")
		}
	case <-time.After(c.config.Timeout + 5*time.Second):
		_ = c.cmd.Process.Kill()
		t.Fatal("worker deadline exceeded")
	}
}
func TestExternalUploadWorkerProcess(t *testing.T) {
	path := os.Getenv("OUTPOST_UPLOAD_CHILD")
	if path == "" {
		t.Skip("subprocess helper")
	}
	raw, e := os.ReadFile(path)
	must(t, e)
	var cfg childConfig
	must(t, json.Unmarshal(raw, &cfg))
	raw, e = os.ReadFile(cfg.Directory + "/plan.json")
	must(t, e)
	j, e := Open(cfg.Directory, raw, cfg.Worker, cfg.Authority, false)
	must(t, e)
	defer j.Close()
	r, e := generation.Open(cfg.Replica, cfg.Authority.Generation, false)
	must(t, e)
	defer r.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CA) {
		t.Fatal("invalid test CA")
	}
	b, e := storage.New(cfg.Profile, storage.Credentials{Access: cfg.Access, Secret: cfg.Secret, ExpiresUnix: cfg.ExpiresUnix}, roots)
	must(t, e)
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	result, e := j.Run(ctx, r, b, cfg.Key)
	must(t, e)
	state, e := j.Status(ctx)
	must(t, e)
	if state.Phase != "COMPLETE" || state.Receipt == nil || result.CleanupPending {
		t.Fatal("worker did not durably complete")
	}
	data, e := json.Marshal(result)
	must(t, e)
	must(t, os.WriteFile(cfg.Result, data, 0600))
}
func recoverBytes(t *testing.T, f *fixture, s *teststore.Server, id, version string, want []byte) {
	t.Helper()
	base := teststore.Root(t)
	dir := filepath.Join(base, "replica")
	must(t, os.Mkdir(dir, 0700))
	r, e := generation.Open(dir, f.authority.Generation, true)
	must(t, e)
	defer r.Close()
	b := f.backend(t, s, 0)
	must(t, b.Recover(context.Background(), id, r))
	kit := filepath.Join(base, "kit")
	must(t, r.ExportKit(context.Background(), id, version, kit))
	owner := f.owner
	owner.SigningKey = nil
	store, e := filekit.OpenStore(kit, owner, false)
	must(t, e)
	defer store.Close()
	out := filepath.Join(base, "restored")
	desc, e := store.Restore(context.Background(), version, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, desc.Names[0]))
	must(t, e)
	if !bytes.Equal(got, want) {
		t.Fatal("independent restored bytes differ")
	}
	a, e := os.Stat(filepath.Join(out, desc.Names[0]))
	must(t, e)
	alias, e := os.Stat(filepath.Join(out, desc.Names[1]))
	must(t, e)
	if !os.SameFile(a, alias) || a.Mode().Perm() != 0640 {
		t.Fatal("restored attributes differ")
	}
}
func TestThreeProcessesAndIndependentCloudRecovery(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			// Keep the three-process fixture independent of HDD fsync latency.
			f.childTimeout = 120 * time.Second
			const slotMillis = 180000
			baseline := f.server(t, kind, 40*time.Millisecond, nil)
			single := f.prepare(t, baseline, f.plan(t, baseline, 1, slotMillis), 0)
			start := time.Now()
			single.start(t)
			single.wait(t, true)
			singleTime := time.Since(start)
			target := f.server(t, kind, 40*time.Millisecond, nil)
			raw := f.plan(t, target, 3, slotMillis)
			children := []*child{}
			for i := 0; i < 3; i++ {
				children = append(children, f.prepare(t, target, raw, i))
			}
			start = time.Now()
			for _, c := range children {
				c.start(t)
			}
			for _, c := range children {
				c.wait(t, true)
			}
			parallelTime := time.Since(start)
			snapshot := target.Snapshot()
			actors := map[string]int{}
			for _, event := range snapshot.Events {
				actors[event.Actor]++
			}
			if len(actors) != 3 || snapshot.PeakWorkers != 3 {
				t.Fatal("three distinct concurrent uploaders not observed", actors, snapshot.PeakWorkers)
			}
			for key, count := range snapshot.Writes {
				if count != 1 {
					t.Fatal("physical object rewritten", key)
				}
			}
			t.Logf("bounded delayed-endpoint fixture: single=%s three=%s ratio=%.2f physical-parts=%d", singleTime, parallelTime, float64(singleTime)/float64(parallelTime), len(snapshot.Events))
			// A later, incomplete generation cannot replace the retained complete one.
			oldID, oldVersion, oldBytes := f.id, f.version, append([]byte(nil), f.data...)
			changed := append([]byte(nil), f.data...)
			copy(changed[10000:18000], bytes.Repeat([]byte{91}, 8000))
			must(t, os.WriteFile(f.input, changed, 0640))
			next, nextVersion := f.capture(t, 2, oldID)
			catalog, e := f.replicas[0].Catalog(context.Background(), next)
			must(t, e)
			b := f.backend(t, target, 0)
			if e = b.Publish(context.Background(), catalog, f.authority.Generation); e == nil {
				t.Fatal("partial generation published")
			}
			if _, e = b.Catalog(context.Background(), next, f.authority.Generation); !storage.Missing(e) {
				t.Fatal("partial complete marker visible", e)
			}
			// Even a forged complete marker plus a valid signed catalog cannot
			// substitute for its missing dependencies or replace a local old copy.
			catalogRef := generation.Object{ID: next, Bytes: len(catalog)}
			must(t, b.PutBlob(context.Background(), catalogRef, catalog))
			marker, e := json.Marshal(storage.Complete{Format: storage.CompleteFormat, Domain: f.authority.Generation.Domain, Repository: f.authority.Generation.Repository, Epoch: 1, Generation: next, Catalog: catalogRef})
			must(t, e)
			must(t, b.Put(context.Background(), "complete-"+next, marker))
			localDir := filepath.Join(f.base, "retained-local")
			must(t, os.Mkdir(localDir, 0700))
			local, e := generation.Open(localDir, f.authority.Generation, true)
			must(t, e)
			must(t, b.Recover(context.Background(), oldID, local))
			if e = b.Recover(context.Background(), next, local); e == nil {
				t.Fatal("forged marker certified absent parts")
			}
			status, e := local.Status(context.Background())
			must(t, e)
			if status.LatestComplete != oldID {
				t.Fatal("forged marker replaced old complete")
			}
			must(t, local.Close())
			// The cached-plan workers can finish the missing closure despite the
			// untrusted marker; both retained versions must then recover alone.
			f.id = next
			f.version = nextVersion
			nextRaw := f.plan(t, target, 3, slotMillis)
			secondWorkers := []*child{}
			for i := 0; i < 3; i++ {
				secondWorkers = append(secondWorkers, f.prepare(t, target, nextRaw, i))
			}
			for _, c := range secondWorkers {
				c.start(t)
			}
			for _, c := range secondWorkers {
				c.wait(t, true)
			}
			for _, r := range f.replicas {
				r.Close()
			}
			for _, dir := range f.dirs {
				must(t, os.RemoveAll(dir))
			}
			f.store.Close()
			must(t, os.RemoveAll(filepath.Join(f.base, "source-store")))
			must(t, os.Remove(f.input))
			recoverBytes(t, f, target, oldID, oldVersion, oldBytes)
			recoverBytes(t, f, target, next, nextVersion, changed)
			entries, e := os.ReadDir(target.Options.Directory)
			must(t, e)
			verifiedPlan, e := Verify(raw, f.authority)
			must(t, e)
			verifiedNext, e := Verify(nextRaw, f.authority)
			must(t, e)
			knownPlans := map[string]Plan{storage.Hash(raw): verifiedPlan, storage.Hash(nextRaw): verifiedNext}
			claims := 0
			for _, entry := range entries {
				data, e := os.ReadFile(filepath.Join(target.Options.Directory, entry.Name()))
				must(t, e)
				if strings.Contains(entry.Name(), "-claim-") {
					var c Claim
					must(t, json.Unmarshal(data, &c))
					known, ok := knownPlans[c.Plan]
					if !ok {
						t.Fatal("unknown claim plan")
					}
					must(t, VerifyClaim(data, known, c.Plan))
					claims++
				}
				if bytes.Contains(data, []byte("do-not-export-private-name")) || bytes.Contains(data, []byte("private-source-marker-not-for-external-plaintext")) {
					t.Fatal("plaintext leaked to target")
				}
			}
			if claims == 0 {
				t.Fatal("no signed assignment claims observed")
			}
		})
	}
}
func TestWorkerSIGKILLReassignmentAndRestart(t *testing.T) {
	testWorkerSIGKILLReassignment(t, 0)
}

func TestWeightedWorkerSIGKILLReassignmentAndRestart(t *testing.T) {
	testWorkerSIGKILLReassignment(t, MaxWorkerWeight)
}

func testWorkerSIGKILLReassignment(t *testing.T, weight int) {
	t.Helper()
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.workers[0].Weight = weight
			blocked := make(chan string, 1)
			var once sync.Once
			var enabled atomic.Bool
			enabled.Store(true)
			target := f.server(t, kind, time.Millisecond, func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
				if enabled.Load() && actor == f.workers[0].ID && r.Method == "PUT" && strings.HasPrefix(key, "part-") {
					once.Do(func() { blocked <- key })
					<-r.Context().Done()
					return true
				}
				return false
			})
			raw := f.plan(t, target, 3, 1000)
			children := []*child{}
			for i := 0; i < 3; i++ {
				children = append(children, f.prepare(t, target, raw, i))
			}
			for _, c := range children {
				c.start(t)
			}
			var part string
			select {
			case part = <-blocked:
			case <-time.After(6 * time.Second):
				t.Fatal("worker did not reach cut point")
			}
			if _, e := os.Stat(target.Path("complete-" + f.id)); !os.IsNotExist(e) {
				t.Fatal("incomplete target published before cut")
			}
			failedAt := time.Now()
			must(t, children[0].cmd.Process.Kill())
			children[0].wait(t, false)
			enabled.Store(false)
			children[1].wait(t, true)
			children[2].wait(t, true)
			elapsed := time.Since(failedAt)
			if elapsed > 10*time.Second {
				t.Fatal("bounded reassignment exceeded", elapsed)
			}
			found := false
			for _, event := range target.Snapshot().Events {
				if event.Key == part && event.Actor != f.workers[0].ID {
					found = true
				}
			}
			if !found {
				t.Fatal("failed assignment was not completed by another worker")
			}
			t.Logf("actual SIGKILL; durable completion by surviving workers within %s", elapsed)
			restarted := &child{config: children[0].config, path: children[0].path}
			restarted.start(t)
			restarted.wait(t, true)
			recoverBytes(t, f, target, f.id, f.version, f.data)
		})
	}
}
func TestPlanPolicyIdentityAndDurableBinding(t *testing.T) {
	f := newFixture(t)
	target := f.server(t, "s3", 0, nil)
	raw := f.plan(t, target, 3, 1000)
	p, e := Verify(raw, f.authority)
	must(t, e)
	denied := p
	denied.AllowExternal = false
	if _, e = Build(context.Background(), f.replicas[0], f.id, denied, f.planner); !errors.Is(e, ErrDenied) {
		t.Fatal("external denial bypassed", e)
	}
	denied = p
	denied.Workers = append([]Worker(nil), p.Workers...)
	denied.Workers[0].Class = "untrusted"
	if _, e = Build(context.Background(), f.replicas[0], f.id, denied, f.planner); !errors.Is(e, ErrDenied) {
		t.Fatal("trusted-only domain bypassed", e)
	}
	denied.AllowedClasses = []string{"trusted", "untrusted"}
	denied.Profile.CredentialScope = "account"
	if _, e = Build(context.Background(), f.replicas[0], f.id, denied, f.planner); !errors.Is(e, ErrDenied) {
		t.Fatal("broad credentials delegated to untrusted worker", e)
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-4] ^= 1
	if _, e = Verify(bad, f.authority); e == nil {
		t.Fatal("bad signature accepted")
	}
	child := f.prepare(t, target, raw, 0)
	j, e := Open(child.config.Directory, raw, f.workers[0].ID, f.authority, false)
	must(t, e)
	defer j.Close()
	b := f.backend(t, target, 0)
	if _, e = j.Run(context.Background(), f.replicas[0], b, f.keys[1]); !errors.Is(e, ErrDenied) {
		t.Fatal("wrong worker identity accepted", e)
	}
	if target.Snapshot().Requests != 0 {
		t.Fatal("denied plan reached target")
	}
	expired := p
	expired.StartMillis = time.Now().Add(-5 * time.Second).UnixMilli()
	expired.ExpiresUnix = time.Now().Add(-time.Second).Unix()
	expiredRaw, e := Build(context.Background(), f.replicas[0], f.id, expired, f.planner)
	must(t, e)
	expiredChild := f.prepare(t, target, expiredRaw, 0)
	expiredJournal, e := Open(expiredChild.config.Directory, expiredRaw, f.workers[0].ID, f.authority, false)
	must(t, e)
	defer expiredJournal.Close()
	if _, e = expiredJournal.Run(context.Background(), f.replicas[0], b, f.keys[0]); !errors.Is(e, ErrDenied) || target.Snapshot().Requests != 0 {
		t.Fatal("expired plan started requests", e)
	}
	invalid := p
	invalid.ExpiresUnix = int64(^uint64(0) >> 1)
	if invalid.policy() == nil {
		t.Fatal("timestamp overflow admitted")
	}
	if VerifyClaim([]byte("{}"), Plan{}, storage.Hash(raw)) == nil {
		t.Fatal("invalid claim plan admitted")
	}
	p.Operation = storage.Hash([]byte("other operation"))
	changed, e := Build(context.Background(), f.replicas[0], f.id, p, f.planner)
	must(t, e)
	if changedJournal, e := Open(child.config.Directory, changed, f.workers[0].ID, f.authority, false); e == nil {
		changedJournal.Close()
		t.Fatal("journal rebound")
	}
}
