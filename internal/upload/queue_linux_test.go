package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func queueLimits() QueueLimits {
	return QueueLimits{MaxJobs: 4, Parallel: 2, AttemptMillis: 4000, RetryBaseMillis: 100, RetryMaxMillis: 500}
}
func queueFor(t *testing.T, f *fixture, limits QueueLimits) (*Queue, string) {
	t.Helper()
	dir := filepath.Join(teststore.Root(t), "queue")
	must(t, os.Mkdir(dir, 0700))
	q, e := OpenQueue(dir, f.workers[0].ID, f.authority, limits, true)
	must(t, e)
	t.Cleanup(func() { q.Close() })
	return q, dir
}
func planOperation(t *testing.T, raw []byte, a Authority) string {
	t.Helper()
	p, e := Verify(raw, a)
	must(t, e)
	return p.Operation
}
func (f *fixture) resolve(t *testing.T, servers ...*teststore.Server) BackendResolver {
	t.Helper()
	return func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		for _, s := range servers {
			if p.Endpoint == s.Endpoint() {
				return storage.New(p, storage.Credentials{Access: f.workers[0].ID, Secret: s.Options.Logins[f.workers[0].ID].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, s.Roots)
			}
		}
		return nil, storage.ErrDenied
	}
}
func changePlan(t *testing.T, f *fixture, raw []byte, change func(*Plan)) []byte {
	t.Helper()
	p, e := Verify(raw, f.authority)
	must(t, e)
	change(&p)
	p.Signature = nil
	unsigned, e := json.Marshal(p)
	must(t, e)
	p.Signature = ed25519.Sign(f.planner, append([]byte(Format+"\x00"), unsigned...))
	result, e := json.Marshal(p)
	must(t, e)
	return result
}
func waitQueue(t *testing.T, q *Queue, predicate func(QueueState) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s, e := q.Status(context.Background())
		must(t, e)
		if predicate(s) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s, e := q.Status(context.Background())
	jobs := map[string]any{}
	for op, j := range s.Jobs {
		jobs[op] = struct {
			Phase, Error string
			Attempts     uint64
		}{j.Phase, j.ErrorCode, j.Attempts}
	}
	t.Fatalf("queue condition not reached: revision=%d jobs=%+v error=%v", s.Revision, jobs, e)
}
func TestQueueTargetIsolationAndAutomaticRetry(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			// Exercise isolation/retry with several physical parts within the same
			// bounded deadlines under the race detector on one CPU. The independent
			// throughput/reassignment fixtures retain their larger payloads.
			f := fixtureBytes(t, 256<<10)
			var unavailable atomic.Bool
			unavailable.Store(true)
			slow := f.server(t, kind, 0, func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
				if unavailable.Load() {
					w.WriteHeader(503)
					return true
				}
				return false
			})
			healthy := f.server(t, kind, 0, nil)
			q, _ := queueFor(t, f, queueLimits())
			a, b := f.plan(t, slow, 1, 1000), f.plan(t, healthy, 1, 1000)
			must(t, q.Enqueue(context.Background(), f.replicas[0], a))
			must(t, q.Enqueue(context.Background(), f.replicas[0], b))
			opA, opB := planOperation(t, a, f.authority), planOperation(t, b, f.authority)
			ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- q.Run(ctx, f.replicas[0], f.resolve(t, slow, healthy), f.keys[0]) }()
			waitQueue(t, q, func(s QueueState) bool { return s.Jobs[opB].Phase == "COMPLETE" && s.Jobs[opA].Attempts >= 2 })
			state, e := q.Status(ctx)
			must(t, e)
			if state.Jobs[opA].Phase == "COMPLETE" {
				t.Fatal("unavailable target falsely complete")
			}
			pins, e := f.replicas[0].Status(ctx)
			must(t, e)
			if _, ok := pins.Pins[q.pin(opA)]; !ok {
				t.Fatal("retryable job lost source pin")
			}
			unavailable.Store(false)
			must(t, <-done)
			state, e = q.Status(ctx)
			must(t, e)
			for _, j := range state.Jobs {
				if j.Phase != "COMPLETE" || j.CleanupPending || j.Receipt == nil {
					t.Fatal("incomplete queue", j.Phase)
				}
			}
			before := slow.Snapshot().Requests + healthy.Snapshot().Requests
			must(t, q.Enqueue(ctx, f.replicas[0], a))
			must(t, q.Run(ctx, f.replicas[0], f.resolve(t, slow, healthy), f.keys[0]))
			if slow.Snapshot().Requests+healthy.Snapshot().Requests != before {
				t.Fatal("terminal duplicate repeated network work")
			}
			pins, e = f.replicas[0].Status(ctx)
			must(t, e)
			if len(pins.Pins) != 0 {
				t.Fatal("completed job pins retained", pins.Pins)
			}
			recoverBytes(t, f, slow, f.id, f.version, f.data)
			recoverBytes(t, f, healthy, f.id, f.version, f.data)
		})
	}
}
func TestQueueSlowResolverAndCancellation(t *testing.T) {
	f := newFixture(t)
	slow := f.server(t, "s3", 0, nil)
	healthy := f.server(t, "webdav", 0, nil)
	limits := queueLimits()
	limits.AttemptMillis = 3000
	q, _ := queueFor(t, f, limits)
	a, b := f.plan(t, slow, 1, 1000), f.plan(t, healthy, 1, 1000)
	must(t, q.Enqueue(context.Background(), f.replicas[0], a))
	must(t, q.Enqueue(context.Background(), f.replicas[0], b))
	normal := f.resolve(t, healthy)
	entered := make(chan struct{})
	var once sync.Once
	resolver := func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if p.Endpoint == slow.Endpoint() {
			once.Do(func() { close(entered) })
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return normal(ctx, p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx, f.replicas[0], resolver, f.keys[0]) }()
	<-entered
	waitQueue(t, q, func(s QueueState) bool { return s.Jobs[planOperation(t, b, f.authority)].Phase == "COMPLETE" })
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queue failed to join cancelled resolver")
	}
	if slow.Snapshot().Requests != 0 {
		t.Fatal("blocked resolver unexpectedly contacted target")
	}
	s, e := q.Status(context.Background())
	must(t, e)
	if s.Jobs[planOperation(t, a, f.authority)].Phase != "RETRY_WAIT" {
		t.Fatal("cancellation state not durable")
	}
}
func TestQueueAdmissionBoundsBindingAndBlockedRetry(t *testing.T) {
	f := newFixture(t)
	var full atomic.Bool
	full.Store(true)
	s := f.server(t, "webdav", 0, func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
		if full.Load() {
			w.WriteHeader(507)
			return true
		}
		return false
	})
	limits := queueLimits()
	limits.MaxJobs = 1
	q, dir := queueFor(t, f, limits)
	raw := f.plan(t, s, 1, 1000)
	op := planOperation(t, raw, f.authority)
	denied := changePlan(t, f, raw, func(p *Plan) { p.AllowExternal = false })
	if e := q.Enqueue(context.Background(), f.replicas[0], denied); e == nil {
		t.Fatal("external policy bypass")
	}
	must(t, q.Enqueue(context.Background(), f.replicas[0], raw))
	must(t, q.Enqueue(context.Background(), f.replicas[0], raw))
	rebound := changePlan(t, f, raw, func(p *Plan) { p.SlotMillis = 2000 })
	if e := q.Enqueue(context.Background(), f.replicas[0], rebound); !errors.Is(e, ErrConflict) {
		t.Fatal("operation rebound", e)
	}
	extra := changePlan(t, f, raw, func(p *Plan) { p.Operation = storage.Hash([]byte("another operation")) })
	if e := q.Enqueue(context.Background(), f.replicas[0], extra); !errors.Is(e, storage.ErrCapacity) {
		t.Fatal("queue cap ignored", e)
	}
	pins, e := f.replicas[0].Status(context.Background())
	must(t, e)
	if len(pins.Pins) != 1 {
		t.Fatal("rejected admission leaked pins")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if e = q.Run(ctx, f.replicas[0], f.resolve(t, s), f.keys[0]); !errors.Is(e, ErrBlocked) {
		t.Fatal("capacity must block, not succeed", e)
	}
	state, e := q.Status(ctx)
	must(t, e)
	if state.Jobs[op].ErrorCode != "CAPACITY" {
		t.Fatal("missing capacity classification")
	}
	full.Store(false)
	must(t, q.Retry(ctx, op))
	must(t, q.Run(ctx, f.replicas[0], f.resolve(t, s), f.keys[0]))
	different := limits
	different.Parallel = 1
	if reopened, e := OpenQueue(dir, f.workers[0].ID, f.authority, different, false); e == nil {
		reopened.Close()
		t.Fatal("queue resource identity rebound")
	}
	// Never silently recreate a lost/corrupt queue journal from remote claims.
	must(t, os.WriteFile(filepath.Join(dir, "queue.json"), []byte("{}"), 0600))
	if reopened, e := OpenQueue(dir, f.workers[0].ID, f.authority, limits, false); e == nil {
		reopened.Close()
		t.Fatal("corrupt queue accepted")
	}
}
func TestQueueInterruptedAdmissionExpiryAndCompletionCleanup(t *testing.T) {
	for _, point := range []string{"admission-intent", "admission-pin", "job-complete"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			target := f.server(t, "s3", 0, nil)
			q, dir := queueFor(t, f, queueLimits())
			raw := f.plan(t, target, 1, 1000)
			op := planOperation(t, raw, f.authority)
			cut := errors.New("injected durable boundary")
			q.Fault = func(at string) error {
				if at == point {
					return cut
				}
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			e := q.Enqueue(ctx, f.replicas[0], raw)
			if point == "job-complete" {
				must(t, e)
				e = q.Run(ctx, f.replicas[0], f.resolve(t, target), f.keys[0])
			}
			if !errors.Is(e, cut) {
				t.Fatal("cut not exercised", e)
			}
			must(t, q.Close())
			reopened, e := OpenQueue(dir, f.workers[0].ID, f.authority, queueLimits(), false)
			must(t, e)
			defer reopened.Close()
			must(t, reopened.Run(ctx, f.replicas[0], f.resolve(t, target), f.keys[0]))
			state, e := reopened.Status(ctx)
			must(t, e)
			if state.Jobs[op].Phase != "COMPLETE" || state.Jobs[op].CleanupPending {
				t.Fatal("durable recovery incomplete")
			}
			pins, e := f.replicas[0].Status(ctx)
			must(t, e)
			if len(pins.Pins) != 0 {
				t.Fatal("completion cleanup not recovered")
			}
		})
	}
	f := newFixture(t)
	target := f.server(t, "s3", 0, nil)
	q, _ := queueFor(t, f, queueLimits())
	raw := f.plan(t, target, 1, 1000)
	raw = changePlan(t, f, raw, func(p *Plan) {
		p.StartMillis = time.Now().Add(-time.Second).UnixMilli()
		p.ExpiresUnix = time.Now().Add(2 * time.Second).Unix()
	})
	op := planOperation(t, raw, f.authority)
	must(t, q.Enqueue(context.Background(), f.replicas[0], raw))
	p, e := Verify(raw, f.authority)
	must(t, e)
	time.Sleep(time.Until(time.Unix(p.ExpiresUnix, 0)) + 5*time.Millisecond)
	if e = q.Run(context.Background(), f.replicas[0], f.resolve(t, target), f.keys[0]); !errors.Is(e, ErrBlocked) {
		t.Fatal("expired job did not block", e)
	}
	if target.Snapshot().Requests != 0 {
		t.Fatal("expired plan contacted target")
	}
	state, e := q.Status(context.Background())
	must(t, e)
	pins, e := f.replicas[0].Status(context.Background())
	must(t, e)
	if state.Jobs[op].Phase != "EXPIRED" || len(pins.Pins) != 1 {
		t.Fatal("expired authority released source")
	}
	if e = q.Retry(context.Background(), op); e == nil {
		t.Fatal("expired plan revived")
	}
}
func TestQueueThrottleDeadlineSurvivesReopen(t *testing.T) {
	f := newFixture(t)
	target := f.server(t, "webdav", 0, func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(429)
		return true
	})
	q, dir := queueFor(t, f, queueLimits())
	raw := f.plan(t, target, 1, 1000)
	op := planOperation(t, raw, f.authority)
	must(t, q.Enqueue(context.Background(), f.replicas[0], raw))
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if e := q.Run(ctx, f.replicas[0], f.resolve(t, target), f.keys[0]); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	state, e := q.Status(context.Background())
	must(t, e)
	if state.Jobs[op].NextMillis < time.Now().Add(30*time.Second).UnixMilli() {
		t.Fatal("server cooldown not persisted")
	}
	before := target.Snapshot().Requests
	must(t, q.Close())
	reopened, e := OpenQueue(dir, f.workers[0].ID, f.authority, queueLimits(), false)
	must(t, e)
	defer reopened.Close()
	bounded, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	_ = reopened.Run(bounded, f.replicas[0], f.resolve(t, target), f.keys[0])
	if target.Snapshot().Requests != before {
		t.Fatal("restart bypassed persisted throttle")
	}
}

func TestQueueInstancesKeepIndependentPins(t *testing.T) {
	f := newFixture(t)
	target := f.server(t, "webdav", 0, nil)
	first, _ := queueFor(t, f, queueLimits())
	second, _ := queueFor(t, f, queueLimits())
	raw := f.plan(t, target, 1, 1000)
	op := planOperation(t, raw, f.authority)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	must(t, first.Enqueue(ctx, f.replicas[0], raw))
	must(t, second.Enqueue(ctx, f.replicas[0], raw))
	if first.pin(op) == second.pin(op) {
		t.Fatal("independent queues share a pin")
	}
	must(t, first.Run(ctx, f.replicas[0], f.resolve(t, target), f.keys[0]))
	pins, e := f.replicas[0].Status(ctx)
	must(t, e)
	if len(pins.Pins) != 1 || pins.Pins[second.pin(op)].Generation != f.id {
		t.Fatal("completion released another queue's source")
	}
	must(t, second.Run(ctx, f.replicas[0], f.resolve(t, target), f.keys[0]))
	pins, e = f.replicas[0].Status(ctx)
	must(t, e)
	if len(pins.Pins) != 0 {
		t.Fatal("independent queue cleanup incomplete")
	}
}
func TestUploadQueueProcess(t *testing.T) {
	path := os.Getenv("OUTPOST_QUEUE_CHILD")
	if path == "" {
		t.Skip("subprocess helper")
	}
	raw, e := os.ReadFile(path)
	must(t, e)
	var cfg childConfig
	must(t, json.Unmarshal(raw, &cfg))
	q, e := OpenQueue(cfg.Directory, cfg.Worker, cfg.Authority, queueLimits(), false)
	must(t, e)
	defer q.Close()
	source, e := generation.Open(cfg.Replica, cfg.Authority.Generation, false)
	must(t, e)
	defer source.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CA) {
		t.Fatal("invalid fixture CA")
	}
	resolver := func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		return storage.New(p, storage.Credentials{Access: cfg.Access, Secret: cfg.Secret, ExpiresUnix: cfg.ExpiresUnix}, roots)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	must(t, q.Run(ctx, source, resolver, cfg.Key))
}
func TestQueueActualSIGKILLAndRestart(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			reached := make(chan struct{})
			var once sync.Once
			var block atomic.Bool
			block.Store(true)
			target := f.server(t, kind, 0, func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
				if block.Load() && r.Method == "PUT" && strings.HasPrefix(key, "part-") {
					once.Do(func() { close(reached) })
					<-r.Context().Done()
					return true
				}
				return false
			})
			q, dir := queueFor(t, f, queueLimits())
			raw := f.plan(t, target, 1, 1000)
			op := planOperation(t, raw, f.authority)
			must(t, q.Enqueue(context.Background(), f.replicas[0], raw))
			cfg := childConfig{Directory: dir, Replica: f.dirs[0], Worker: f.workers[0].ID, Key: f.keys[0], Authority: f.authority, Profile: profile(target), CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.HTTP.Certificate().Raw}), Access: f.workers[0].ID, Secret: target.Options.Logins[f.workers[0].ID].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}
			config := filepath.Join(f.base, "queue-child.json")
			data, e := json.Marshal(cfg)
			must(t, e)
			must(t, os.WriteFile(config, data, 0600))
			start := func() (*exec.Cmd, <-chan error, *bytes.Buffer) {
				binary, e := os.Executable()
				must(t, e)
				cmd := exec.Command(binary, "-test.run=^TestUploadQueueProcess$", "-test.timeout=25s")
				cmd.Env = append(os.Environ(), "OUTPOST_QUEUE_CHILD="+config)
				log := new(bytes.Buffer)
				cmd.Stdout = log
				cmd.Stderr = log
				must(t, cmd.Start())
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				t.Cleanup(func() { _ = cmd.Process.Kill() })
				return cmd, done, log
			}
			cmd, done, _ := start()
			select {
			case <-reached:
			case <-time.After(7 * time.Second):
				t.Fatal("queue did not reach kill point")
			}
			state, e := q.Status(context.Background())
			must(t, e)
			if state.Jobs[op].Phase != "RUNNING" {
				t.Fatal("running attempt not durable")
			}
			must(t, cmd.Process.Kill())
			if e = <-done; e == nil {
				t.Fatal("SIGKILL unexpectedly succeeded")
			}
			block.Store(false)
			_, done, log := start()
			select {
			case e = <-done:
				if e != nil {
					t.Fatalf("restart: %v %s", e, log.String())
				}
			case <-time.After(22 * time.Second):
				t.Fatal("restart exceeded bound")
			}
			state, e = q.Status(context.Background())
			must(t, e)
			if state.Jobs[op].Phase != "COMPLETE" || state.Jobs[op].Attempts < 2 {
				t.Fatal("restart did not reconcile incomplete attempt")
			}
			recoverBytes(t, f, target, f.id, f.version, f.data)
		})
	}
}
