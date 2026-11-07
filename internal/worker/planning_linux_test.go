package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
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

func TestAutonomousExternalPlanningPublishesNewGenerationsOnBothProtocols(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	ctx := context.Background()
	push, pull := f.rules()
	plannerPub, planner := key(t)
	f.domain.Planner = plannerPub
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	workers := []upload.Worker{}
	logins := map[string]teststore.Login{}
	for i, w := range f.nodes {
		workers = append(workers, upload.Worker{ID: w.node, Class: f.cfg.Nodes[i].Class, PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)})
		logins[w.node] = teststore.Login{Secret: "synthetic-autonomous-cloud"}
	}
	targets := map[string]*teststore.Server{}
	profiles := map[string]storage.Profile{}
	for _, kind := range []string{"s3", "webdav"} {
		s := teststore.New(t, teststore.Options{Kind: kind, Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)), Logins: logins})
		p := storage.Profile{Kind: kind, Endpoint: s.Endpoint(), Namespace: s.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
		if kind == "s3" {
			p.Region = s.Options.Region
		}
		targets[p.ID()] = s
		profiles[p.ID()] = p
		f.cfg.Targets = append(f.cfg.Targets, control.Target{ID: p.ID(), Profile: p})
		f.domain.Placement.Targets = append(f.domain.Placement.Targets, p.ID())
		for _, w := range f.nodes {
			f.domain.Placement.CloudEdges = append(f.domain.Placement.CloudEdges, policy.CloudEdge{Node: w.node, Target: p.ID()})
		}
		grant, e := upload.SignDelegation(upload.Delegation{Format: upload.DelegationFormat, Trust: f.domain.Trust, Epoch: 1, Profile: p, AllowedClasses: []string{"trusted", "untrusted"}, Workers: workers, StartMillis: f.cfg.NotBefore * 1000, ExpiresUnix: f.cfg.ExpiresUnix, SlotMillis: 500}, planner)
		must(t, e)
		f.cfg.Uploads = append(f.cfg.Uploads, grant)
	}
	for _, w := range f.nodes {
		w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
			s, ok := targets[p.ID()]
			if !ok {
				return nil, ErrDenied
			}
			return storage.New(p, storage.Credentials{Access: w.node, Secret: s.Options.Logins[w.node].Secret, ExpiresUnix: f.cfg.ExpiresUnix}, s.Roots)
		}
	}
	f.replicationConfig(t, 0, 1, push)
	f.replicationConfig(t, 1, 1, push, pull)
	f.replicationConfig(t, 2, 1, pull)
	stopB, stopA, stopC := start(t, f.nodes[1]), start(t, f.nodes[0]), start(t, f.nodes[2])
	waitComplete := func(id string) {
		started := time.Now()
		ready := func() bool {
			for _, w := range f.nodes {
				for _, grant := range f.cfg.Uploads {
					if !complete(w, upload.DelegatedOperation(grant, id)) {
						return false
					}
				}
			}
			return true
		}
		// This fixture runs six target jobs on one CPU. Its completion bound
		// includes race instrumentation; protocol attempt deadlines stay unchanged.
		for time.Since(started) < 30*time.Second {
			if ready() {
				t.Logf("generation completed across three workers/two targets in %s", time.Since(started))
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		for _, w := range f.nodes {
			s, e := w.Status(ctx)
			if e != nil {
				t.Log("status", e)
				continue
			}
			for _, grant := range f.cfg.Uploads {
				j := s.Jobs[upload.DelegatedOperation(grant, id)]
				t.Logf("node=%s target-job=%s phase=%s attempts=%d error=%s", w.node, j.Job.Operation, j.Phase, j.Attempts, j.ErrorCode)
			}
		}
		t.Fatal("autonomous cloud generation did not complete within fixture budget")
	}
	waitComplete(f.generation)
	for _, grant := range f.cfg.Uploads {
		var plan []byte
		for _, w := range f.nodes {
			raw, e := w.state.Read("upload-plan-" + upload.DelegatedOperation(grant, f.generation) + ".json")
			must(t, e)
			if plan == nil {
				plan = raw
			} else if !bytes.Equal(plan, raw) {
				t.Fatal("worker plan caches differ")
			}
		}
	}
	store, e := filekit.OpenStore(filepath.Join(f.base, "source-kit"), f.dataOwner, false)
	must(t, e)
	changed := bytes.Repeat([]byte("new autonomous generation"), 16384)
	input := filepath.Join(f.base, "next-source")
	must(t, os.WriteFile(input, changed, 0640))
	version, e := store.Backup(ctx, input, filekit.BackupOptions{Names: []string{"dataset/данные.bin"}})
	must(t, e)
	f.nodes[0].mu.Lock()
	replica := f.nodes[0].active.domains[f.domain.Trust.Domain].replica
	f.nodes[0].mu.Unlock()
	second, e := generation.Seal(ctx, store, []string{version.Version}, replica, generation.Catalog{Format: generation.Format, Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: 1, Sequence: 2, Parent: f.generation, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, f.writer)
	must(t, e)
	must(t, store.Close())
	// The owner published no new job, delegation or configuration for generation2.
	waitComplete(second)
	stopC()
	stopA()
	stopB()
	must(t, os.Remove(input))
	must(t, os.Remove(filepath.Join(f.base, "input")))
	must(t, os.RemoveAll(filepath.Join(f.base, "source-kit")))
	for target, p := range profiles {
		backend, e := f.nodes[0].resolve(ctx, p)
		must(t, e)
		for label, item := range map[string]struct {
			id   string
			data []byte
		}{"old": {f.generation, f.content}, "new": {second, changed}} {
			dir := filepath.Join(f.base, "cloud-"+target+"-"+label)
			must(t, os.Mkdir(dir, 0700))
			r, e := generation.Open(dir, f.domain.Trust, true)
			must(t, e)
			must(t, backend.Recover(ctx, item.id, r))
			must(t, r.Close())
			out := dir + "-restored"
			_, e = generation.RecoverMaterialized(ctx, dir, item.id, f.domain.Trust, f.dataOwner, generation.RecoverySelection{}, out)
			must(t, e)
			got, e := os.ReadFile(filepath.Join(out, "dataset/данные.bin"))
			must(t, e)
			if !bytes.Equal(got, item.data) {
				t.Fatal("autonomous cloud recovery mismatch", p.Kind, label)
			}
		}
		backend.Close()
	}
}

func TestAutonomousUploadCannotBypassCurrentOwnerPlacement(t *testing.T) {
	f := newFixture(t)
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	w := f.nodes[0]
	p := storage.Profile{Kind: "webdav", Endpoint: "https://storage.invalid/collection", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)), MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1, Attempts: 1, TimeoutMillis: 1000, CredentialScope: "namespace", NoDelete: true}
	grant, e := upload.SignDelegation(upload.Delegation{Format: upload.DelegationFormat, Trust: f.domain.Trust, Epoch: 1, Profile: p, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}}, StartMillis: f.cfg.NotBefore * 1000, ExpiresUnix: f.cfg.ExpiresUnix, SlotMillis: 1000}, planner)
	must(t, e)
	c := f.cfg
	c.Node = w.node
	c.Domains = []control.Domain{f.domain}
	c.Uploads = []json.RawMessage{grant}
	c.Targets = []control.Target{{ID: p.ID(), Profile: p}}
	if _, e = control.Sign(c, f.owner); e == nil {
		t.Fatal("planner grant bypassed owner placement")
	}
	c.Domains[0].Placement.Targets = []string{p.ID()}
	c.Domains[0].Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	accepted, e := control.Verify(raw, f.owner.Public().(ed25519.PublicKey), w.node)
	must(t, e)
	_, g, ok := accepted.UploadDelegation(storage.Hash(grant))
	if !ok {
		t.Fatal("delegation missing")
	}
	j := control.UploadJob(grant, g, f.generation, w.node)
	if !accepted.Autonomous(j) {
		t.Fatal("valid automatic job denied")
	}
	j.Target = storage.Hash([]byte("other"))
	if accepted.Autonomous(j) {
		t.Fatal("target substitution accepted")
	}
	j = control.UploadJob(grant, g, f.generation, w.node)
	accepted.Uploads = nil
	if accepted.Autonomous(j) {
		t.Fatal("removed grant remained authorized")
	}
}

func TestPlanningWithdrawalPreservesCacheAndCorruptionFailsClosed(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	p := storage.Profile{Kind: "webdav", Endpoint: "https://storage.invalid/collection", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)), MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1, Attempts: 1, TimeoutMillis: 1000, CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
	f.domain.Placement.Targets = []string{p.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
	grant, e := upload.SignDelegation(upload.Delegation{Format: upload.DelegationFormat, Trust: f.domain.Trust, Epoch: 1, Profile: p, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}}, StartMillis: f.cfg.NotBefore * 1000, ExpiresUnix: f.cfg.ExpiresUnix, SlotMillis: 1000}, planner)
	must(t, e)
	f.cfg.Uploads = []json.RawMessage{grant}
	c := f.config(t, 0, nil)
	scope, e := c.CompileAutonomy()
	must(t, e)
	r, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer r.Close()
	_, g, ok := c.UploadDelegation(storage.Hash(grant))
	if !ok {
		t.Fatal("missing grant")
	}
	j := control.UploadJob(grant, g, f.generation, w.node)
	v := &view{cfg: c, autonomy: scope}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Fault = func(point string) error {
		if point == "upload-plan-durable" {
			cancel()
		}
		return nil
	}
	if _, e = w.planUpload(ctx, v, j, r); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled planning succeeded", e)
	}
	w.Fault = nil
	ctx = context.Background()
	name := "upload-plan-" + j.Operation + ".json"
	saved, e := w.state.Read(name)
	must(t, e)
	withdrawn := c
	withdrawn.Uploads = nil
	scope, e = withdrawn.CompileAutonomy()
	must(t, e)
	if _, e = w.planUpload(ctx, &view{cfg: withdrawn, autonomy: scope}, j, r); !errors.Is(e, ErrDenied) {
		t.Fatal("withdrawn delegation resumed", e)
	}
	still, e := w.state.Read(name)
	must(t, e)
	if !bytes.Equal(saved, still) {
		t.Fatal("withdrawal changed cached plan")
	}
	must(t, w.state.WithLock(ctx, func() error { return w.state.Write(name, []byte("{}")) }))
	if _, e = w.planUpload(ctx, v, j, r); !errors.Is(e, upload.ErrDenied) {
		t.Fatal("corrupt cache silently rebuilt", e)
	}
	still, e = w.state.Read(name)
	must(t, e)
	if string(still) != "{}" {
		t.Fatal("corrupt evidence overwritten")
	}
	status, e := r.Status(ctx)
	must(t, e)
	if _, ok := status.Pins[planningPin(j)]; !ok {
		t.Fatal("unresolved operation lost its source protection")
	}
}
