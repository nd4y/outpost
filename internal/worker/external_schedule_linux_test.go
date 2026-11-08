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
	"reflect"
	"strings"
	"sync/atomic"
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

func TestWorkerScheduledExternalAuditDetectsLossAndResumesAfterRestart(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	bindFixture(t, f, w)
	ctx := context.Background()
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.ExternalAuditIntervalSeconds = 4
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	target := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
		Logins: map[string]teststore.Login{w.node: {Secret: "isolated-cloud-secret"}}})
	p := storage.Profile{Kind: "webdav", Endpoint: target.Endpoint(), Namespace: target.Options.Namespace, MaxObjectBytes: 64 << 10,
		Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
	f.domain.Placement.Targets = []string{p.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return storage.New(p, storage.Credentials{Access: w.node, Secret: target.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, target.Roots)
	}
	replica, err := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	worker := upload.Worker{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
	operation := storage.Hash([]byte("scheduled-external"))
	raw, err := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: operation, Profile: p, AllowExternal: true,
		AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{worker}, StartMillis: time.Now().UnixMilli(), ExpiresUnix: time.Now().Add(time.Minute).Unix(), SlotMillis: 1000}, planner)
	must(t, err)
	plan, err := upload.Verify(raw, upload.Authority{Generation: f.domain.Trust, Planner: pub})
	must(t, err)
	job := control.Job{Operation: operation, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: raw}
	f.config(t, 0, []control.Job{job})
	stop := start(t, w)
	wait(t, func() bool { return complete(w, operation) })
	var first ExternalAuditStatus
	wait(t, func() bool {
		first, err = w.ScheduledExternalAuditStatus(ctx, operation)
		return err == nil && first.State == "VERIFIED_CIPHERTEXT"
	})
	if first.Receipt == nil || first.Receipt.Generation != f.generation || first.Receipt.Target != p.ID() {
		t.Fatal("wrong scheduled proof", first)
	}
	status, err := w.Status(ctx)
	must(t, err)
	original := bytes.Clone(status.Jobs[operation].Receipt)
	writes := target.Snapshot().Writes
	key := "part-" + plan.Blobs[0].Parts[0].ID
	path := target.Path(key)
	part, err := os.ReadFile(path)
	must(t, err)
	must(t, os.Remove(path))
	wait(t, func() bool {
		report, err := w.ScheduledExternalAuditStatus(ctx, operation)
		return err == nil && report.State == "MISSING" && report.Receipt == nil
	})
	stop()
	reopened, err := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots, Resolve: w.resolve, Guard: w.guard})
	must(t, err)
	defer reopened.Close()
	historical, err := reopened.ScheduledExternalAuditStatus(ctx, operation)
	must(t, err)
	if historical.State != "MISSING" {
		t.Fatal("restart erased the last failed audit", historical)
	}
	requests := target.Snapshot().Requests
	snapshot, err := reopened.ManagementSnapshot(ctx, workerEnrollment(t, f, 0), f.domain.Trust.Domain)
	must(t, err)
	copy := snapshot.ExternalCopies[0]
	if copy.Operation != operation || copy.State != "OBSERVED_COMPLETE" || copy.ReceiptDigest != storage.Hash(original) ||
		copy.Audit == nil || copy.Audit.State != "MISSING" || copy.Audit.ObservedUnix != historical.FinishedUnix ||
		copy.Audit.ExpiresUnix != historical.FinishedUnix+f.domain.ExternalAuditIntervalSeconds ||
		target.Snapshot().Requests != requests {
		t.Fatal("snapshot refreshed the old receipt or lost the actual missing observation", copy)
	}
	// Independent fixture repair. The scheduled auditor never writes to storage.
	must(t, os.WriteFile(path, part, 0600))
	stop = start(t, reopened)
	var next ExternalAuditStatus
	wait(t, func() bool {
		next, err = reopened.ScheduledExternalAuditStatus(ctx, operation)
		return err == nil && next.State == "VERIFIED_CIPHERTEXT" && next.Receipt != nil && next.Receipt.ObservedUnix > first.Receipt.ObservedUnix
	})
	stop()
	status, err = reopened.Status(ctx)
	must(t, err)
	if !reflect.DeepEqual(writes, target.Snapshot().Writes) || !bytes.Equal(original, status.Jobs[operation].Receipt) || next.Window != first.Window {
		t.Fatal("scheduled check touched target/history or accumulated another window")
	}
	f.domain.ExternalAuditIntervalSeconds = 0
	f.cfg.Revision++
	f.config(t, 0, []control.Job{job})
	before := target.Snapshot().Requests
	if _, err = reopened.ScheduledExternalAuditStatus(ctx, operation); !errors.Is(err, ErrDenied) || target.Snapshot().Requests != before {
		t.Fatal("disabled schedule still reports current proof", err)
	}
}

func TestWorkerScheduledExternalRepairReplaysDurableMissingPart(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			w := f.nodes[0]
			bindFixture(t, f, w)
			ctx := context.Background()
			pub, planner := key(t)
			f.domain.Planner = pub
			f.domain.ExternalAuditIntervalSeconds = 4
			f.domain.ExternalRepairMissing = true
			f.domain.Placement.Edges = nil
			f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
			target := teststore.New(t, teststore.Options{Kind: kind, Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
				Logins: map[string]teststore.Login{w.node: {Secret: "isolated-cloud-secret"}}})
			p := storage.Profile{Kind: kind, Endpoint: target.Endpoint(), Namespace: target.Options.Namespace, MaxObjectBytes: 64 << 10,
				Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
			if kind == "s3" {
				p.Region = target.Options.Region
			}
			f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
			f.domain.Placement.Targets = []string{p.ID()}
			f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
			w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return storage.New(p, storage.Credentials{Access: w.node, Secret: target.Options.Logins[w.node].Secret, ExpiresUnix: f.cfg.ExpiresUnix}, target.Roots)
			}
			executor := upload.Worker{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
			grant := upload.Delegation{Format: upload.DelegationFormat, Trust: f.domain.Trust, Epoch: 1, Profile: p, AllowMissingRepair: true,
				AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{executor},
				StartMillis: f.cfg.NotBefore * 1000, ExpiresUnix: f.cfg.ExpiresUnix, SlotMillis: 1000}
			raw, err := upload.SignDelegation(grant, planner)
			must(t, err)
			f.cfg.Uploads = []json.RawMessage{raw}
			cfg := f.config(t, 0, nil)
			original := control.UploadJob(raw, grant, f.generation, w.node)
			w.Fault = func(point string) error {
				if point == "external-repair-before-admission" {
					return errors.New("stop after the audit record and before queue admission")
				}
				return nil
			}
			stop := start(t, w)
			wait(t, func() bool { return complete(w, original.Operation) })
			wait(t, func() bool {
				report, err := w.ScheduledExternalAuditStatus(ctx, original.Operation)
				return err == nil && report.State == "VERIFIED_CIPHERTEXT"
			})
			status, err := w.Status(ctx)
			must(t, err)
			firstReceipt := bytes.Clone(status.Jobs[original.Operation].Receipt)
			before := target.Snapshot().Writes
			retained, err := w.state.Read("upload-plan-" + original.Operation + ".json")
			must(t, err)
			plan, err := upload.Verify(retained, upload.Authority{Generation: f.domain.Trust, Planner: pub})
			must(t, err)
			partKey := "part-" + plan.Blobs[0].Parts[0].ID
			partPath := target.Path(partKey)
			healthy, err := os.ReadFile(partPath)
			must(t, err)
			must(t, os.Remove(partPath))
			var observed ExternalAuditStatus
			wait(t, func() bool {
				observed, err = w.ScheduledExternalAuditStatus(ctx, original.Operation)
				return err == nil && observed.Repair != nil && observed.State == "MISSING"
			})
			stop()
			if observed.Repair.Part != strings.TrimPrefix(partKey, "part-") {
				t.Fatal("audit recorded the wrong missing part", observed.Repair)
			}
			job := control.UploadRepairJob(raw, grant, f.generation, w.node, *observed.Repair)
			authority := upload.Authority{Generation: f.domain.Trust, Planner: pub}
			foreignPart := *observed.Repair
			foreignPart.Part = storage.Hash([]byte("part outside the retained map"))
			if _, err = upload.DeriveMissingRepair(retained, authority, foreignPart); !errors.Is(err, upload.ErrDenied) {
				t.Fatal("retained plan authorized a foreign part", err)
			}
			status, err = w.Status(ctx)
			must(t, err)
			if len(status.Jobs) != 1 || !reflect.DeepEqual(before, target.Snapshot().Writes) {
				t.Fatal("read-only audit crossed the admission checkpoint")
			}
			compiled, err := cfg.CompileAutonomy()
			must(t, err)
			if !compiled.Permits(job) || !cfg.AutonomousUpload(job) {
				t.Fatal("valid repair denied")
			}
			ownerDisabled := cfg
			ownerDisabled.Domains = append([]control.Domain(nil), cfg.Domains...)
			ownerDisabled.Domains[0].ExternalRepairMissing = false
			compiled, err = ownerDisabled.CompileAutonomy()
			must(t, err)
			if compiled.Permits(job) || ownerDisabled.AutonomousUpload(job) {
				t.Fatal("planner alone authorized a repair")
			}
			grant.AllowMissingRepair = false
			legacy, err := upload.SignDelegation(grant, planner)
			must(t, err)
			plannerDisabled := cfg
			plannerDisabled.Uploads = []json.RawMessage{legacy}
			legacyJob := control.UploadRepairJob(legacy, grant, f.generation, w.node, *observed.Repair)
			compiled, err = plannerDisabled.CompileAutonomy()
			must(t, err)
			if compiled.Permits(legacyJob) || plannerDisabled.AutonomousUpload(legacyJob) {
				t.Fatal("owner alone authorized a repair")
			}
			reopened, err := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots, Resolve: w.resolve, Guard: w.guard})
			must(t, err)
			t.Cleanup(func() { must(t, reopened.Close()) })
			stop = start(t, reopened)
			wait(t, func() bool {
				status, err := reopened.Status(ctx)
				must(t, err)
				attempt := status.Jobs[job.Operation]
				if attempt.Phase == "BLOCKED" {
					t.Fatal("repair blocked", attempt.ErrorCode)
				}
				return attempt.Phase == "COMPLETE"
			})
			got, err := os.ReadFile(partPath)
			must(t, err)
			if !bytes.Equal(got, healthy) {
				t.Fatal("repair wrote different bytes")
			}
			after := target.Snapshot().Writes
			for name, writes := range after {
				if strings.HasPrefix(name, "part-") && name != partKey && before[name] != writes {
					t.Fatal("repair wrote another payload", name)
				}
			}
			if after[partKey] != before[partKey]+1 {
				t.Fatal("repair did not create exactly one part")
			}
			corrupt := bytes.Clone(healthy)
			corrupt[0] ^= 1
			must(t, os.WriteFile(partPath, corrupt, 0600))
			wait(t, func() bool {
				report, err := reopened.ScheduledExternalAuditStatus(ctx, original.Operation)
				return err == nil && report.State == "INVALID_CONTENT" && report.Repair == nil
			})
			restored, err := os.ReadFile(partPath)
			must(t, err)
			if !bytes.Equal(restored, corrupt) {
				t.Fatal("repair overwrote a corrupt canonical object")
			}
			must(t, os.WriteFile(partPath, healthy, 0600))
			catalog, err := storage.Describe(generation.Object{ID: f.generation, Bytes: len(plan.Catalog)}, plan.Catalog, p.MaxObjectBytes)
			must(t, err)
			must(t, os.Remove(target.Path("part-"+catalog.Parts[0].ID)))
			wait(t, func() bool {
				report, err := reopened.ScheduledExternalAuditStatus(ctx, original.Operation)
				return err == nil && report.State == "MISSING" && report.Repair == nil
			})
			stop()
			status, err = reopened.Status(ctx)
			must(t, err)
			if len(status.Jobs) != 2 || !bytes.Equal(firstReceipt, status.Jobs[original.Operation].Receipt) ||
				!reflect.DeepEqual(after, target.Snapshot().Writes) {
				t.Fatal("catalog loss or corruption authorized writes or modified historical evidence")
			}
		})
	}
}

func TestWorkerScheduledExternalAuditChecksOptedInHistory(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.AttemptMillis = 60000
	f.cfg.Limits.Parallel = 1
	w := f.nodes[0]
	bindFixture(t, f, w)
	ctx := context.Background()
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.ExternalAuditIntervalSeconds = 3
	f.domain.ExternalRepairMissing = true
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	var oldPart string
	var armed atomic.Bool
	auditRead, auditCanceled := make(chan struct{}), make(chan struct{})
	target := teststore.New(t, teststore.Options{Kind: "webdav",
		Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)),
		Logins:    map[string]teststore.Login{w.node: {Secret: "isolated-history-secret"}},
		Before: func(_ http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
			if r.Method != http.MethodGet || !armed.Load() || key != oldPart || !armed.CompareAndSwap(true, false) {
				return false
			}
			close(auditRead)
			<-r.Context().Done()
			close(auditCanceled)
			return true
		}})
	p := storage.Profile{Kind: "webdav", Endpoint: target.Endpoint(), Namespace: target.Options.Namespace,
		MaxObjectBytes: 1 << 20, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 12000,
		CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
	f.domain.Placement.Targets = []string{p.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return storage.New(p, storage.Credentials{Access: w.node, Secret: target.Options.Logins[w.node].Secret, ExpiresUnix: f.cfg.ExpiresUnix}, target.Roots)
	}
	executor := upload.Worker{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}
	raw, err := upload.SignDelegation(upload.Delegation{Format: upload.DelegationFormat, Trust: f.domain.Trust, Epoch: 1,
		Profile: p, AllowMissingRepair: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{executor},
		StartMillis: f.cfg.NotBefore * 1000, ExpiresUnix: f.cfg.ExpiresUnix, SlotMillis: 1000}, planner)
	must(t, err)
	f.cfg.Uploads = []json.RawMessage{raw}
	replica, err := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, err)
	defer replica.Close()
	store, err := filekit.OpenStore(filepath.Join(f.base, "source-kit"), f.dataOwner, false)
	must(t, err)
	defer store.Close()
	path := filepath.Join(f.base, "changed-input")
	must(t, os.WriteFile(path, bytes.Repeat([]byte("next retained generation"), 4096), 0600))
	version, err := store.Backup(ctx, path, filekit.BackupOptions{Names: []string{"dataset/данные.bin"}})
	must(t, err)
	trust := f.domain.Trust
	next, err := generation.Seal(ctx, store, []string{version.Version}, replica, generation.Catalog{
		Format: generation.Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch, Sequence: 2,
		Parent: f.generation, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, f.writer)
	must(t, err)
	firstOp, nextOp := upload.DelegatedOperation(raw, f.generation), upload.DelegatedOperation(raw, next)
	f.config(t, 0, nil)
	stop := start(t, w)
	waitFor(t, 120*time.Second, func() bool { return complete(w, firstOp) && complete(w, nextOp) })
	waitFor(t, 25*time.Second, func() bool {
		report, err := w.ScheduledExternalAuditStatus(ctx, nextOp)
		return err == nil && report.State == "VERIFIED_CIPHERTEXT"
	})
	if _, err = w.ScheduledExternalAuditStatus(ctx, firstOp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("default schedule audited older generation", err)
	}
	parts := func(operation string) []upload.Task {
		t.Helper()
		raw, err := w.state.Read("upload-plan-" + operation + ".json")
		must(t, err)
		plan, err := upload.Verify(raw, upload.Authority{Generation: trust, Planner: pub})
		must(t, err)
		tasks, err := plan.Tasks()
		must(t, err)
		return tasks
	}
	current := map[string]bool{}
	for _, task := range parts(nextOp) {
		current[task.Part.ID] = true
	}
	for _, task := range parts(firstOp) {
		if !current[task.Part.ID] {
			oldPart = "part-" + task.Part.ID
			break
		}
	}
	if oldPart == "" {
		t.Fatal("older generation has no independent payload")
	}
	writes := target.Snapshot().Writes
	must(t, os.Remove(target.Path(oldPart)))
	f.domain.ExternalAuditGenerations = 2
	f.cfg.Revision++
	cfg := f.config(t, 0, nil)
	var historic ExternalAuditStatus
	waitFor(t, 25*time.Second, func() bool {
		historic, err = w.ScheduledExternalAuditStatus(ctx, firstOp)
		return err == nil && historic.State == "MISSING" && historic.Repair == nil
	})
	cfg.Domains[0].ExternalAuditGenerations = 17
	if _, err = control.Sign(cfg, f.owner); !errors.Is(err, control.ErrDenied) {
		t.Fatal("unbounded historical scope admitted", err)
	}
	armed.Store(true)
	select {
	case <-auditRead:
	case <-time.After(25 * time.Second):
		t.Fatal("older-generation reread did not reach the held request")
	}
	historic, err = w.ScheduledExternalAuditStatus(ctx, firstOp)
	must(t, err)
	if historic.State != "MISSING" {
		t.Fatal("previous historical result absent at withdrawal", historic.State)
	}
	f.domain.ExternalAuditGenerations = 1
	f.cfg.Revision++
	f.config(t, 0, nil)
	select {
	case <-auditCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("narrowed scope did not cancel the old request")
	}
	waitFor(t, 25*time.Second, func() bool {
		report, err := w.ScheduledExternalAuditStatus(ctx, nextOp)
		return err == nil && report.State == "VERIFIED_CIPHERTEXT" && report.FinishedUnix > historic.FinishedUnix+f.domain.ExternalAuditIntervalSeconds
	})
	stop()
	final, err := w.ScheduledExternalAuditStatus(ctx, firstOp)
	must(t, err)
	status, err := w.Status(ctx)
	must(t, err)
	if final.FinishedUnix != historic.FinishedUnix || final.State != "MISSING" || len(status.Jobs) != 2 ||
		!reflect.DeepEqual(writes, target.Snapshot().Writes) {
		t.Fatal("history refreshed after withdrawal or authorized a write", historic, final)
	}
}
