package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/telemetry"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestWorkerPublishesBothExternalTargetsAndStandaloneRecovery(t *testing.T) {
	testWorkerCloudTargets(t, false)
}

func TestWorkerHTTPObservationCapacityDoesNotStopExternalRecovery(t *testing.T) {
	testWorkerCloudTargets(t, true)
}

func TestWorkerParallelUploadsShareOneTargetRequestGate(t *testing.T) {
	f := newFixture(t)
	const operationWindow = 60 * time.Second
	f.cfg.Limits.OperationMillis = operationWindow.Milliseconds()
	w := f.nodes[0]
	ctx := context.Background()
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	firstRequest := make(chan struct{})
	firstFinished := make(chan struct{})
	release := make(chan struct{})
	releaseFirst := sync.OnceFunc(func() { close(release) })
	defer releaseFirst()
	secondRequest := make(chan struct{})
	var requests atomic.Int32
	server := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
		Logins: map[string]teststore.Login{w.node: {Secret: "isolated-cloud-secret"}},
		Before: func(out http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
			switch requests.Add(1) {
			case 1:
				close(firstRequest)
				defer close(firstFinished)
				select {
				case <-release:
				case <-r.Context().Done():
					return true
				}
			case 2:
				close(secondRequest)
			}
			return false
		}})
	p := storage.Profile{Kind: "webdav", Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 3000, CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
	f.domain.Placement.Targets = []string{p.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
	replica, err := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	worker := upload.Worker{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
	jobs := []control.Job{}
	for _, name := range []string{"upload-first", "upload-second"} {
		op := storage.Hash([]byte(name))
		plan, err := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: op, Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{worker}, StartMillis: time.Now().UnixMilli(), ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(), SlotMillis: 10000}, planner)
		must(t, err)
		jobs = append(jobs, control.Job{Operation: op, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: plan})
	}
	var resolved atomic.Int32
	bothReady := make(chan struct{})
	secondResolved := make(chan struct{})
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		b, err := storage.New(p, storage.Credentials{Access: w.node, Secret: server.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, server.Roots)
		if err != nil {
			return nil, err
		}
		// Both jobs must finish local preparation before either starts the
		// short provider request. Release the second while the first is held.
		number := resolved.Add(1)
		switch number {
		case 1:
			select {
			case <-bothReady:
			case <-ctx.Done():
				b.Close()
				return nil, ctx.Err()
			}
		case 2:
			close(bothReady)
			select {
			case <-firstRequest:
				close(secondResolved)
			case <-ctx.Done():
				b.Close()
				return nil, ctx.Err()
			}
		}
		return b, nil
	}
	f.config(t, 0, jobs)
	stop := start(t, w)
	select {
	case <-firstRequest:
	case <-time.After(operationWindow):
		t.Fatalf("first upload never reached target after local preparation, resolved=%d", resolved.Load())
	}
	select {
	case <-secondResolved:
	case <-firstFinished:
		t.Fatal("provider request ended before the second resolved backend entered competition")
	}
	select {
	case <-secondRequest:
		t.Fatal("separate upload jobs exceeded target concurrency")
	case <-firstFinished:
		t.Fatal("first provider request ended before releasing the target gate")
	case <-time.After(200 * time.Millisecond):
	}
	releaseFirst()
	waitFor(t, operationWindow, func() bool { return complete(w, jobs[0].Operation) && complete(w, jobs[1].Operation) })

	w.mu.Lock()
	first := w.active
	w.mu.Unlock()
	f.cfg.Revision++
	f.config(t, 0, jobs)
	wait(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.active != nil && w.active.cfg.Revision == f.cfg.Revision
	})
	w.mu.Lock()
	sameGate := w.active != first && w.active.requestGates[p.ID()] == first.requestGates[p.ID()]
	w.mu.Unlock()
	if !sameGate {
		t.Fatal("same signed target lost its gate on configuration refresh")
	}
	stop()
}

func logCloudTransferBinding(t *testing.T, ctx context.Context, w *Worker, domain control.Domain, window int64, job control.Job, kind string, admittedAt int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	status, err := w.Status(ctx)
	if err != nil {
		t.Logf("cloud observation kind=%s worker_status=%s", kind, errorCode(err))
		return
	}
	local := status.Jobs[job.Operation]
	dir := w.relative(filepath.Join(DomainDirectory(w.dir, domain.Trust), "uploads", job.Operation))
	queue, err := openExternalQueue(w.root, dir, w.node, upload.Authority{Generation: domain.Trust, Planner: domain.Planner}, false, window, nil)
	if err != nil {
		t.Logf("cloud observation kind=%s open_queue=%s worker_phase=%s", kind, errorCode(err), local.Phase)
		return
	}
	defer queue.Close()
	state, err := queue.Status(ctx)
	if err != nil {
		t.Logf("cloud observation kind=%s queue_status=%s worker_phase=%s", kind, errorCode(err), local.Phase)
		return
	}
	queued := state.Jobs[job.Operation]
	store, err := statefile.OpenAt(w.root, externalHTTPDirectory, maxExternalHTTPRecord, false)
	if err != nil {
		t.Logf("cloud observation kind=%s open_sample=%s missing=%t queue_phase=%s", kind, errorCode(err), errors.Is(err, os.ErrNotExist), queued.Phase)
		return
	}
	defer store.Close()
	key := w.externalHTTPKey()
	if key == nil {
		t.Logf("cloud observation kind=%s sample_verifier_available=false", kind)
		return
	}
	sample, err := readExternalHTTPAttempt(store, w.node, job.Domain, job.Target, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Logf("cloud observation kind=%s read_sample=%s missing=%t queue_phase=%s", kind, errorCode(err), errors.Is(err, os.ErrNotExist), queued.Phase)
		return
	}
	var receipt upload.Receipt
	receiptsMatch := storage.Decode(local.Receipt, &receipt, 4096) == nil && queued.Receipt != nil && receipt == *queued.Receipt
	t.Logf("cloud observation kind=%s worker_phase=%s queue_phase=%s operation_matches=%t plan_matches=%t attempt_matches=%t receipts_match=%t sample_outcome=%s complete_counts=%t admitted_ms=%d started_ms=%d finished_ms=%d worker_updated_s=%d receipt_observed_s=%d",
		kind, local.Phase, queued.Phase, sample.Operation == job.Operation, sample.Plan == storage.Hash(queued.Plan), sample.Attempt == queued.Attempts,
		receiptsMatch, sample.Outcome, sample.Counts != nil && !sample.Counts.Incomplete, admittedAt, sample.StartedMillis, sample.FinishedMillis, local.UpdatedUnix, receipt.ObservedUnix)
}

func testWorkerCloudTargets(t *testing.T, exhaustTelemetry bool) {
	t.Helper()
	f := newFixture(t)
	// Publication and independent recovery share a durable local budget ledger.
	// Give the signed claim slot and whole operation time for those writes.
	// The focused upload test covers a 500 ms signed slot.
	const (
		claimSlot       = 10 * time.Second
		operationWindow = 60 * time.Second
		publicationWait = 70 * time.Second
	)
	f.cfg.Limits.OperationMillis = operationWindow.Milliseconds()
	if exhaustTelemetry {
		f.cfg.Limits.TelemetryBytes = 64 << 10
	}
	ctx := context.Background()
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.CloudReadbackMaxAgeSeconds = 3600
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	w := f.nodes[0]
	replica, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	targets := map[string]*teststore.Server{}
	profiles := map[string]storage.Profile{}
	jobs := []control.Job{}
	planExpiry := time.Now().Add(4 * time.Minute).Unix()
	for _, kind := range []string{"s3", "webdav"} {
		server := teststore.New(t, teststore.Options{Kind: kind, Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)), Logins: map[string]teststore.Login{w.node: {Secret: "isolated-cloud-secret"}}})
		p := storage.Profile{Kind: kind, Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
		if kind == "s3" {
			p.Region = server.Options.Region
		}
		targets[p.ID()] = server
		profiles[p.ID()] = p
		f.cfg.Targets = append(f.cfg.Targets, control.Target{ID: p.ID(), Profile: p})
		f.domain.Placement.Targets = append(f.domain.Placement.Targets, p.ID())
		f.domain.Placement.CloudEdges = append(f.domain.Placement.CloudEdges, policy.CloudEdge{Node: w.node, Target: p.ID()})
		op := storage.Hash([]byte("cloud-" + kind))
		plan, e := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: op, Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}}, StartMillis: time.Now().Add(100 * time.Millisecond).UnixMilli(), ExpiresUnix: planExpiry, SlotMillis: claimSlot.Milliseconds()}, planner)
		must(t, e)
		jobs = append(jobs, control.Job{Operation: op, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: plan})
	}
	bodyBudget, e := storage.NewHTTPBodyBudget(16 << 20)
	must(t, e)
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		server, ok := targets[p.ID()]
		if !ok {
			return nil, ErrDenied
		}
		backend, err := storage.New(p, storage.Credentials{Access: w.node, Secret: server.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, server.Roots)
		if err != nil {
			return nil, err
		}
		bound, err := backend.WithHTTPBodyBudget(bodyBudget)
		if err != nil {
			backend.Close()
		}
		return bound, err
	}
	f.config(t, 0, jobs)
	stop := start(t, w)
	waitPublication := func(revision uint64) {
		t.Helper()
		started := time.Now()
		statusCtx, cancel := context.WithTimeout(ctx, publicationWait)
		defer cancel()
		var last Status
		defer func() {
			if !t.Failed() {
				return
			}
			t.Logf("cloud publication revision %d observed_revision=%d elapsed=%s wait=%s operation=%s claim_slot=%s",
				revision, last.Revision, time.Since(started).Round(time.Millisecond), publicationWait, operationWindow, claimSlot)
			for _, job := range jobs {
				state, observed := last.Jobs[job.Operation]
				t.Logf("cloud publication %s observed=%t phase=%s attempts=%d last_error=%s",
					profiles[job.Target].Kind, observed, state.Phase, state.Attempts, state.ErrorCode)
			}
		}()
		waitFor(t, publicationWait, func() bool {
			status, err := w.Status(statusCtx)
			if err != nil {
				return false
			}
			last = status
			for _, job := range jobs {
				if status.Jobs[job.Operation].Phase != "COMPLETE" {
					return false
				}
			}
			return true
		})
	}
	waitPublication(f.cfg.Revision)
	// New owner revisions explicitly enable reuse, then require a fresh audit.
	// Completed receipts remain historical; a new operation requests new work.
	var admittedAt int64
	for _, age := range []int64{3600, 0} {
		f.cfg.Revision++
		f.domain.CloudReadbackMaxAgeSeconds = age
		if age == 0 && !exhaustTelemetry {
			// The exact latest-attempt assertion below needs one telemetry
			// writer. The earlier revisions still publish in parallel.
			f.cfg.Limits.Parallel = 1
		}
		for i, old := range jobs {
			p, e := upload.Verify(old.Plan, upload.Authority{Generation: f.domain.Trust, Planner: pub})
			must(t, e)
			p.Operation = storage.Hash([]byte(old.Operation + time.Now().String()))
			plan, e := upload.Build(ctx, replica, f.generation, p, planner)
			must(t, e)
			jobs[i].Operation, jobs[i].Plan = p.Operation, plan
		}
		admittedAt = time.Now().UnixMilli()
		f.config(t, 0, jobs)
		waitPublication(f.cfg.Revision)
		status, e := w.Status(ctx)
		must(t, e)
		for _, j := range jobs {
			var receipt upload.Receipt
			must(t, json.Unmarshal(status.Jobs[j.Operation].Receipt, &receipt))
			want := "full-target-readback"
			if age > 0 {
				want = "cached-target-readback"
			}
			if receipt.Verification != want {
				t.Fatal("owner cloud policy not applied", receipt)
			}
		}
	}
	snapshot, e := w.ManagementSnapshot(ctx, workerEnrollment(t, f, 0), f.domain.Trust.Domain)
	must(t, e)
	record, e := TelemetryRecord(snapshot, w.node)
	must(t, e)
	w.addExternalHTTPMetrics(ctx, f.domain.Trust.Domain, 1, snapshot, &record)
	metrics := map[string]*int64{}
	for _, metric := range record.Metrics {
		if metric.Name == "external_http_attempt_requests" {
			metrics[metric.Target] = metric.Value
		}
	}
	for _, job := range jobs {
		value, ok := metrics[job.Target]
		if !ok || (exhaustTelemetry && value != nil) || (!exhaustTelemetry && (value == nil || *value <= 0)) {
			logCloudTransferBinding(t, ctx, w, f.domain, f.cfg.Limits.OperationMillis, job, profiles[job.Target].Kind, admittedAt)
			t.Fatalf("unexpected scoped HTTP measurement kind=%s metric_present=%t value_present=%t", profiles[job.Target].Kind, ok, value != nil)
		}
		projection, err := w.ExternalTransferStatus(ctx, job.Operation)
		must(t, err)
		if projection.Target != job.Target || (projection.Attempt == nil) != exhaustTelemetry {
			logCloudTransferBinding(t, ctx, w, f.domain, f.cfg.Limits.OperationMillis, job, profiles[job.Target].Kind, admittedAt)
			t.Fatalf("unexpected local transfer observation kind=%s target_matches=%t sample_present=%t",
				profiles[job.Target].Kind, projection.Target == job.Target, projection.Attempt != nil)
		}
		if attempt := projection.Attempt; attempt != nil &&
			(attempt.StartedMillis < admittedAt || attempt.FinishedMillis < attempt.StartedMillis ||
				attempt.FinishedMillis > time.Now().UnixMilli()) {
			t.Fatalf("transfer observation time is outside the current publication: admitted=%d started=%d finished=%d",
				admittedAt, attempt.StartedMillis, attempt.FinishedMillis)
		}
		if exhaustTelemetry {
			attempt := upload.HTTPAttempt{Node: w.node, Domain: job.Domain, Target: job.Target, Operation: job.Operation, Plan: storage.Hash(job.Plan), Attempt: 99, StartedMillis: time.Now().UnixMilli(), Outcome: "STARTED"}
			if e = w.writeExternalHTTPAttempt(ctx, attempt); !errors.Is(e, statefile.ErrCapacity) {
				t.Fatal("fixture did not reach the separate telemetry budget", e)
			}
		}
	}
	_, e = telemetry.Encode(w.node, f.domain.Trust.Domain, record)
	must(t, e)
	stop()
	for _, j := range jobs {
		backend, e := w.resolve(ctx, profiles[j.Target])
		must(t, e)
		defer backend.Close()
		destination := filepath.Join(f.base, "cloud-copy-"+profiles[j.Target].Kind)
		must(t, os.Mkdir(destination, 0700))
		copy, e := generation.Open(destination, f.domain.Trust, true)
		must(t, e)
		defer copy.Close()
		must(t, backend.Recover(ctx, f.generation, copy))
		kit := destination + "-kit"
		must(t, copy.ExportKit(ctx, f.generation, f.version, kit))
		owner := f.dataOwner
		owner.SigningKey = nil
		reader, e := filekit.OpenStore(kit, owner, false)
		must(t, e)
		defer reader.Close()
		out := destination + "-restore"
		_, e = reader.Restore(ctx, f.version, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "dataset/данные.bin"))
		must(t, e)
		if !bytes.Equal(got, f.content) {
			t.Fatal("cloud-only recovery differs")
		}
	}
}
