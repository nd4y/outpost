package worker

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

// The new long-operation compatibility cases check retained effects, not the
// existing short disk-latency profile. Default variants keep their original wait.
func waitOperationWindow(t *testing.T, operationMillis int64, condition func() bool) {
	t.Helper()
	if operationMillis == 0 {
		wait(t, condition)
		return
	}
	waitFor(t, time.Minute, condition)
}

func logWindowQueueProgress(t *testing.T, w *Worker, domain control.Domain, job control.Job) {
	t.Helper()
	if !t.Failed() {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	dir := filepath.Join(DomainDirectory(w.dir, domain.Trust), "uploads", job.Operation)
	authority := upload.Authority{Generation: domain.Trust, Planner: domain.Planner}
	q, err := openExternalQueue(w.root, w.relative(dir), w.node, authority, false, 0, nil)
	if err != nil {
		t.Logf("queue diagnostic open: %v", err)
		return
	}
	defer q.Close()
	state, err := q.Status(ctx)
	if err != nil {
		t.Logf("queue diagnostic status: %v", err)
		return
	}
	entry := state.Jobs[job.Operation]
	t.Logf("queue diagnostic: phase=%s attempts=%d error=%s", entry.Phase, entry.Attempts, entry.ErrorCode)
	journal, err := upload.Open(filepath.Join(dir, "jobs", job.Operation), entry.Plan, w.node, authority, false)
	if err != nil {
		t.Logf("journal diagnostic open: %v", err)
		return
	}
	defer journal.Close()
	progress, err := journal.Status(ctx)
	if err != nil {
		t.Logf("journal diagnostic status: %v", err)
		return
	}
	complete := 0
	for _, part := range progress.Parts {
		if part.Complete {
			complete++
		}
	}
	plan, err := upload.Verify(entry.Plan, authority)
	if err != nil {
		t.Logf("plan diagnostic: %v", err)
		return
	}
	tasks, err := plan.Tasks()
	if err == nil {
		t.Logf("journal diagnostic: phase=%s complete=%d started=%d planned=%d slotMillis=%d", progress.Phase, complete, len(progress.Parts), len(tasks), plan.SlotMillis)
	}
}

func TestWorkerLongOperationKeepsShortRequestsAndConfigurationExpiry(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	server := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository))})
	profile := storage.Profile{Kind: "webdav", Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 1, TimeoutMillis: 1000, CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: profile.ID(), Profile: profile}}
	f.domain.Placement.Targets = []string{profile.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: profile.ID()}}
	replica, err := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	op := storage.Hash([]byte("explicit long operation"))
	f.cfg.ExpiresUnix = time.Now().Add(8 * time.Second).Unix()
	raw, err := upload.Build(t.Context(), replica, f.generation, upload.Plan{Format: upload.Format, Operation: op, Profile: profile, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}}, StartMillis: time.Now().UnixMilli(), ExpiresUnix: f.cfg.ExpiresUnix, SlotMillis: 1000}, planner)
	must(t, err)
	job := control.Job{Operation: op, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: profile.ID(), Plan: raw}
	entered := make(chan time.Time, 1)
	alive := make(chan struct{})
	joined := make(chan struct{})
	w.resolve = func(ctx context.Context, _ storage.Profile) (*storage.Backend, error) {
		end, _ := ctx.Deadline()
		entered <- end
		select {
		case <-time.After(300 * time.Millisecond):
			close(alive)
		case <-ctx.Done():
		}
		<-ctx.Done()
		close(joined)
		return nil, ctx.Err()
	}
	f.cfg.Limits.AttemptMillis = 100
	f.cfg.Limits.OperationMillis = upload.MaxAttemptMillis
	cfg := f.config(t, 0, []control.Job{job})
	stopWorker := start(t, w)
	var once sync.Once
	stop := func() { once.Do(stopWorker) }
	t.Cleanup(stop)
	select {
	case deadline := <-entered:
		if !deadline.Equal(time.Unix(cfg.ExpiresUnix, 0)) {
			t.Fatal("long operation lost the configuration deadline", deadline)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("long operation did not reach resolver")
	}
	select {
	case <-alive:
	case <-time.After(time.Second):
		t.Fatal("operation incorrectly inherited the short request budget")
	}
	select {
	case <-joined:
	case <-time.After(9 * time.Second):
		t.Fatal("long operation survived signed configuration expiry")
	}
	stop()
	state, err := w.Status(t.Context())
	must(t, err)
	if state.Jobs[op].Phase == "COMPLETE" || len(state.Jobs[op].Receipt) != 0 {
		t.Fatal("expired operation manufactured completion")
	}
	if cfg.Limits.AttemptMillis != 100 || profile.TimeoutMillis != 1000 {
		t.Fatal("operation opt-in changed original request bounds")
	}
}
