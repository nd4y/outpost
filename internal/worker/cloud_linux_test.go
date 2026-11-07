package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestWorkerPublishesBothExternalTargetsAndStandaloneRecovery(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	w := f.nodes[0]
	replica, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	targets := map[string]*teststore.Server{}
	profiles := map[string]storage.Profile{}
	jobs := []control.Job{}
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
		plan, e := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: op, Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}}, StartMillis: time.Now().Add(100 * time.Millisecond).UnixMilli(), ExpiresUnix: time.Now().Add(time.Minute).Unix(), SlotMillis: 500}, planner)
		must(t, e)
		jobs = append(jobs, control.Job{Operation: op, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: plan})
	}
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		server, ok := targets[p.ID()]
		if !ok {
			return nil, ErrDenied
		}
		return storage.New(p, storage.Credentials{Access: w.node, Secret: server.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, server.Roots)
	}
	f.config(t, 0, jobs)
	stop := start(t, w)
	wait(t, func() bool {
		for _, j := range jobs {
			if !complete(w, j.Operation) {
				return false
			}
		}
		return true
	})
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
