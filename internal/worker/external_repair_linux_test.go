package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func TestWorkerOwnerAdmitsMissingRepairAndSeparateCorruptCopyReplacement(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	w := f.nodes[0]
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	targets := map[string]*teststore.Server{}
	profile := func(kind string) storage.Profile {
		server := teststore.New(t, teststore.Options{Kind: kind, Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
			Logins: map[string]teststore.Login{w.node: {Secret: "isolated-cloud-secret"}}})
		p := storage.Profile{Kind: kind, Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
		if kind == "s3" {
			p.Region = server.Options.Region
		}
		targets[p.ID()] = server
		return p
	}
	old, replacement := profile("s3"), profile("webdav")
	admitTarget := func(p storage.Profile) {
		f.cfg.Targets = append(f.cfg.Targets, control.Target{ID: p.ID(), Profile: p})
		f.domain.Placement.Targets = append(f.domain.Placement.Targets, p.ID())
		f.domain.Placement.CloudEdges = append(f.domain.Placement.CloudEdges, policy.CloudEdge{Node: w.node, Target: p.ID()})
	}
	admitTarget(old)
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, ok := targets[p.ID()]
		if !ok {
			return nil, ErrDenied
		}
		return storage.New(p, storage.Credentials{Access: w.node, Secret: s.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, s.Roots)
	}
	replicaPath := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	replica, err := generation.Open(replicaPath, f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	executor := upload.Worker{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
	job := func(name string, p storage.Profile) control.Job {
		t.Helper()
		op := storage.Hash([]byte(name))
		now := time.Now()
		plan, err := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: op, Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{executor}, StartMillis: now.UnixMilli(), ExpiresUnix: now.Add(time.Minute).Unix(), SlotMillis: 1000}, planner)
		must(t, err)
		return control.Job{Operation: op, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: plan}
	}
	first := job("external-initial", old)
	f.config(t, 0, []control.Job{first})
	stop := start(t, w)
	wait(t, func() bool { return complete(w, first.Operation) })
	status, err := w.Status(ctx)
	must(t, err)
	originalReceipt := bytes.Clone(status.Jobs[first.Operation].Receipt)
	plan, err := upload.Verify(first.Plan, upload.Authority{Generation: f.domain.Trust, Planner: pub})
	must(t, err)
	path := targets[old.ID()].Path("part-" + plan.Blobs[0].Parts[0].ID)
	healthy, err := os.ReadFile(path)
	must(t, err)
	must(t, os.Remove(path))
	reader, err := w.resolve(ctx, old)
	must(t, err)
	defer reader.Close()
	audit, err := reader.AuditGeneration(ctx, f.generation, f.domain.Trust)
	if !storage.Missing(err) || audit.State != "MISSING" {
		t.Fatal("missing dependency remained apparently healthy", audit, err)
	}
	repair := job("external-missing-repair", old)
	f.cfg.Revision++
	f.config(t, 0, []control.Job{repair})
	wait(t, func() bool { return complete(w, repair.Operation) })
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, healthy) {
		t.Fatal("owner-authorized repair did not restore exact part", err)
	}
	audit, err = reader.AuditGeneration(ctx, f.generation, f.domain.Trust)
	must(t, err)
	if audit.State != "VERIFIED_CIPHERTEXT" {
		t.Fatal("repaired target failed full fresh audit", audit)
	}
	corrupt := bytes.Clone(healthy)
	corrupt[0] ^= 1
	must(t, os.WriteFile(path, corrupt, 0600))
	conflict := job("external-corrupt-refusal", old)
	f.cfg.Revision++
	f.config(t, 0, []control.Job{conflict})
	wait(t, func() bool {
		s, err := w.Status(ctx)
		return err == nil && s.Jobs[conflict.Operation].Phase == "BLOCKED"
	})
	next := job("external-independent-replacement", replacement)
	proposed := f.cfg
	proposed.Revision++
	proposed.Node = w.node
	proposed.Domains = []control.Domain{f.domain}
	proposed.Jobs = []control.Job{next}
	if _, err := control.Sign(proposed, f.owner); !errors.Is(err, control.ErrDenied) {
		t.Fatal("new target used without an owner placement edge", err)
	}
	admitTarget(replacement)
	f.cfg.Revision++
	f.config(t, 0, []control.Job{next})
	wait(t, func() bool { return complete(w, next.Operation) })
	stop()
	status, err = w.Status(ctx)
	must(t, err)
	if !bytes.Equal(status.Jobs[first.Operation].Receipt, originalReceipt) || len(status.Jobs[conflict.Operation].Receipt) != 0 {
		t.Fatal("repair changed original evidence or certified corrupted data")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, corrupt) {
		t.Fatal("replacement touched corrupted canonical object", err)
	}
	must(t, replica.Close())
	must(t, os.Rename(replicaPath, replicaPath+"-unavailable"))
	backend, err := w.resolve(ctx, replacement)
	must(t, err)
	defer backend.Close()
	raw, err := backend.Catalog(ctx, f.generation, f.domain.Trust)
	must(t, err)
	owner := f.dataOwner
	owner.SigningKey = nil
	dest := filepath.Join(f.base, "replacement-restore")
	receipt, err := generation.RecoverCatalog(ctx, f.generation, raw, f.domain.Trust, owner, generation.RecoverySelection{}, backend.ReadBlob, dest)
	must(t, err)
	got, err := os.ReadFile(filepath.Join(dest, "dataset/данные.bin"))
	must(t, err)
	if !receipt.CheckpointMatch || !bytes.Equal(got, f.content) {
		t.Fatal("replacement cannot independently restore expected content")
	}
}
