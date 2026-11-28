package worker

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestWorkerReportsDurablyConfirmedRunningUploadBytes(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	ctx := t.Context()
	f.cfg.Limits.OperationMillis = (45 * time.Second).Milliseconds()
	plannerPublic, planner := key(t)
	f.domain.Planner = plannerPublic
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	markerReached, release := make(chan struct{}), make(chan struct{})
	markerOnce, releaseOnce := sync.OnceFunc(func() { close(markerReached) }), sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	const secret = "isolated-progress-fixture"
	target := teststore.New(t, teststore.Options{
		Kind: "webdav", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
		Logins: map[string]teststore.Login{w.node: {Secret: secret}},
		Before: func(_ http.ResponseWriter, r *http.Request, actor, name string, _ []byte) bool {
			if r.Method == http.MethodPut && name == "complete-"+f.generation && actor == w.node {
				markerOnce()
				select {
				case <-release:
				case <-r.Context().Done():
					return true
				}
			}
			return false
		},
	})
	profile := storage.Profile{Kind: "webdav", Endpoint: target.Endpoint(), Namespace: target.Options.Namespace,
		MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2,
		TimeoutMillis: 15000, CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: profile.ID(), Profile: profile}}
	f.domain.Placement.Targets = []string{profile.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: profile.ID()}}
	operation := storage.Hash([]byte("worker-running-upload-report"))
	replica, err := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	owner := upload.Worker{ID: w.node, Class: "trusted",
		PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
	planRaw, err := upload.Build(ctx, replica, f.generation, upload.Plan{
		Format: upload.Format, Operation: operation, Profile: profile, AllowExternal: true,
		AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{owner}, StartMillis: time.Now().UnixMilli(),
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(), SlotMillis: 15000,
	}, planner)
	must(t, err)
	plan, err := upload.Verify(planRaw, upload.Authority{Generation: f.domain.Trust, Planner: plannerPublic})
	must(t, err)
	tasks, err := plan.Tasks()
	must(t, err)
	var expected int64
	for _, task := range tasks {
		expected += int64(task.Part.Bytes)
	}
	jobs := []control.Job{{Operation: operation, Executor: w.node, Kind: "upload",
		Domain: f.domain.Trust.Domain, Generation: f.generation, Target: profile.ID(), Plan: planRaw}}
	cfg := f.config(t, 0, jobs)
	must(t, w.admit(ctx, cfg))
	enrollment := workerEnrollment(t, f, 0)
	read := func() (management.Job, error) {
		snapshot, err := w.ManagementSnapshot(ctx, enrollment, f.domain.Trust.Domain)
		if err != nil {
			return management.Job{}, err
		}
		for _, job := range snapshot.Jobs {
			if job.Operation == operation {
				return job, nil
			}
		}
		return management.Job{}, ErrDenied
	}
	old, err := read()
	must(t, err)
	if old.Phase != "QUEUED" || old.CompletedBytes != nil || old.TotalBytes != nil {
		t.Fatal("old unstarted status fabricated progress", old)
	}
	w.resolve = func(_ context.Context, p storage.Profile) (*storage.Backend, error) {
		return storage.New(p, storage.Credentials{Access: w.node, Secret: secret,
			ExpiresUnix: time.Now().Add(time.Minute).Unix()}, target.Roots)
	}
	stop := start(t, w)
	select {
	case <-markerReached:
	case <-time.After(20 * time.Second):
		t.Fatal("worker did not reach isolated publication after confirmed parts")
	}
	waitFor(t, 5*time.Second, func() bool {
		row, err := read()
		return err == nil && row.Phase == "RUNNING" && row.CompletedBytes != nil && *row.CompletedBytes == expected &&
			row.TotalBytes != nil && *row.TotalBytes == expected
	})
	releaseOnce()
	waitFor(t, 12*time.Second, func() bool {
		row, err := read()
		return err == nil && row.Phase == "COMPLETE" && row.CompletedBytes == nil && row.TotalBytes == nil
	})
	stop()
}
