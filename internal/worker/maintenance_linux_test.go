package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func maintenanceReplica(t *testing.T, f *fixture) (*generation.Replica, string) {
	t.Helper()
	w := f.nodes[0]
	ctx := context.Background()
	r, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	t.Cleanup(func() { r.Close() })
	raw, e := r.Catalog(ctx, f.generation)
	must(t, e)
	catalog, e := generation.VerifyCatalog(raw, f.domain.Trust)
	must(t, e)
	newRoot := []byte("opaque replacement kit root")
	catalog.Sequence++
	catalog.Parent = f.generation
	catalog.Kits[0].Root = generation.Object{ID: storage.Hash(newRoot), Bytes: len(newRoot)}
	raw, e = generation.SignCatalog(catalog, f.writer)
	must(t, e)
	head, e := r.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) {
		if ref.ID == storage.Hash(newRoot) {
			return newRoot, nil
		}
		return r.ReadObject(ctx, f.generation, ref)
	})
	must(t, e)
	return r, head
}

func maintenanceCommandFixture(t *testing.T, f *fixture) (*generation.Replica, string, func([]byte, string, uint64) []byte) {
	t.Helper()
	r, head := maintenanceReplica(t, f)
	w := f.nodes[0]
	ctx := context.Background()
	service, signer := key(t)
	cfg := f.cfg
	cfg.Node = w.node
	cfg.Domains = []control.Domain{f.domain}
	cfg.Jobs = nil
	grant, e := command.SignAuthority(command.Authority{Format: command.AuthorityFormat, Service: service, Node: w.node, Tenant: storage.Hash([]byte("tenant")), Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, WriterEpoch: 1, AuthorityEpoch: 1, Kinds: []string{"maintenance"}, NotBefore: cfg.NotBefore, ExpiresUnix: cfg.ExpiresUnix}, f.owner)
	must(t, e)
	cfg.Commands = []json.RawMessage{grant}
	policy, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, w.Accept(ctx, policy))
	return r, head, func(permit []byte, operation string, seq uint64) []byte {
		now := time.Now().Unix()
		env := command.Envelope{Format: command.EnvelopeFormat, Actor: storage.Hash([]byte("maintainer")), Service: command.Identity(service), Node: w.node, Sequence: seq, ConfigurationDigest: storage.Hash(policy), AdmittedUnix: now, Request: command.Request{Operation: operation, Reason: "OWNER_MAINTENANCE", Tenant: storage.Hash([]byte("tenant")), Domain: f.domain.Trust.Domain, Kind: "maintenance", ExpectedRevision: cfg.Revision, Authority: grant, MaintenancePermit: permit, ExpiresUnix: min(now+120, cfg.ExpiresUnix)}}
		out, e := command.SignEnvelope(env, w.owner, signer)
		must(t, e)
		return out
	}
}
func maintenancePermit(t *testing.T, f *fixture, r *generation.Replica, op string, signer ed25519.PrivateKey, retire ...string) []byte {
	t.Helper()
	status, e := r.Status(context.Background())
	must(t, e)
	raw, e := generation.SignPermit(generation.Permit{Format: generation.Format, Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: 1, Revision: status.Revision, Operation: op, Retire: retire}, signer)
	must(t, e)
	return raw
}

func TestWorkerRetentionCheckpointUsesStoppedAdmittedReplica(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	r, head, _ := maintenanceCommandFixture(t, f)
	w := f.nodes[0]
	domain := f.domain.Trust.Domain
	ctx := context.Background()
	permission := maintenancePermit(t, f, r, storage.Hash([]byte("retention checkpoint")), f.maintenance, f.generation)
	_, e := r.Maintain(ctx, permission)
	must(t, e)
	must(t, w.lease.WithLock(ctx, func() error {
		if _, e := w.RetentionCheckpoint(ctx, domain); !errors.Is(e, generation.ErrConflict) {
			t.Fatal("checkpoint ignored the active worker lease", e)
		}
		return nil
	}))
	if _, e = w.RetentionCheckpoint(ctx, storage.Hash([]byte("unknown domain"))); !errors.Is(e, ErrDenied) {
		t.Fatal("unknown replica accepted", e)
	}
	raw, e := w.RetentionCheckpoint(ctx, domain)
	must(t, e)
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	must(t, os.Remove(filepath.Join(dir, "retention.json")))
	must(t, w.RestoreRetentionCheckpoint(ctx, domain, raw, storage.Hash(raw)))
	must(t, r.VerifyComplete(ctx, head))
	got, e := os.ReadFile(filepath.Join(dir, "retention.json"))
	must(t, e)
	if !bytes.Equal(got, raw) {
		t.Fatal("restored bytes differ from checkpoint")
	}
}

func TestWorkerRecoversSignedReplicaIndexUnderStoppedLease(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	cfg := f.config(t, 0, nil)
	w := f.nodes[0]
	trust := f.domain.Trust
	ctx := context.Background()
	path := filepath.Join(DomainDirectory(w.dir, trust), "replica")
	state := filepath.Join(path, "state.json")
	must(t, w.EnableReplicaIndexCopy(ctx, trust.Domain))
	replica, e := w.openReplicaAt(w.relative(path), trust, false)
	must(t, e)
	defer replica.Close()
	admit := w.admission(filepath.ToSlash(w.relative(path)))
	replica.Admit = admit
	pin := storage.Hash([]byte("retain while index is lost"))
	must(t, replica.Pin(ctx, pin, f.generation, "restore"))
	must(t, os.Remove(state))
	must(t, w.lease.WithLock(ctx, func() error {
		if changed, e := w.RecoverReplicaIndexCopy(ctx, trust.Domain); changed || !errors.Is(e, generation.ErrConflict) {
			t.Fatal("recovery ran while the execution lease was held", changed, e)
		}
		return nil
	}))
	changed, e := w.RecoverReplicaIndexCopy(ctx, trust.Domain)
	must(t, e)
	if !changed {
		t.Fatal("missing primary index was not reconstructed")
	}
	status, e := replica.Status(ctx)
	must(t, e)
	if status.Pins[pin].Generation != f.generation || status.LatestComplete != f.generation {
		t.Fatal("reconstructed index lost protected references", status)
	}
	must(t, replica.VerifyComplete(ctx, f.generation))
	stop := start(t, w)
	waitFor(t, 30*time.Second, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.active != nil
	})
	stop()
	must(t, os.Rename(path, path+"-temporarily-unavailable"))
	if view, e := w.start(ctx, cfg); !errors.Is(e, generation.ErrIndexRecovery) {
		if view != nil {
			must(t, w.stop(view))
		}
		t.Fatal("worker accepted loss of an already enrolled replica directory", e)
	}
	if _, e := os.Stat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("worker reinitialized the lost replica directory", e)
	}
	must(t, os.Rename(path+"-temporarily-unavailable", path))
}

func TestWorkerScheduledMaintenanceResumesFromOfflineCache(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.AttemptMillis = 60000
	f.endpoint(t, nil)
	r, head, makeCommand := maintenanceCommandFixture(t, f)
	w := f.nodes[0]
	ctx := context.Background()
	sign := func(op, node string, from int64, sequence uint64) []byte {
		t.Helper()
		legacy := maintenancePermit(t, f, r, op, f.maintenance, f.generation)
		p, e := generation.VerifyPermit(legacy, f.domain.Trust)
		must(t, e)
		p.Format = generation.PermitWindowFormat
		p.Window = &generation.PermitWindow{Node: node, StartUnix: from, ExpiresUnix: from + 75}
		raw, e := generation.SignPermit(p, f.maintenance)
		must(t, e)
		return makeCommand(raw, op, sequence)
	}
	foreign := storage.Hash([]byte("foreign scheduled operation"))
	foreignCommand := sign(foreign, f.nodes[1].node, time.Now().Unix(), 1)
	denial, e := w.ExecuteCommand(ctx, foreignCommand)
	must(t, e)
	if a := verifyWorkerAck(t, w, foreignCommand, denial); a.State != "FAILED" || a.ErrorCode != "POLICY_BLOCKED" {
		t.Fatal("foreign timed permit was admitted", a)
	}
	op := storage.Hash([]byte("scheduled operation"))
	startUnix := time.Now().Add(22 * time.Second).Unix()
	raw := sign(op, w.node, startUnix, 2)
	ack, e := w.ExecuteCommand(ctx, raw)
	must(t, e)
	if len(ack) != 0 {
		t.Fatal("future command reported complete")
	}
	reopened, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer reopened.Close()
	stop := start(t, reopened)
	defer stop()
	s, e := reopened.Status(ctx)
	must(t, e)
	work := s.Controls.Operations[op].Work
	if work == nil || work.NextMillis != startUnix*1000 || work.Phase != "QUEUED" || work.Attempts != 0 || time.Now().Unix() >= startUnix {
		t.Fatal("future work did not survive reopen before the signed window", work)
	}
	must(t, r.VerifyComplete(ctx, f.generation))
	waitFor(t, 90*time.Second, func() bool {
		status, e := reopened.Status(ctx)
		return e == nil && len(status.Controls.Operations[op].Ack) != 0
	})
	ack, e = reopened.ExecuteCommand(ctx, raw)
	must(t, e)
	if result := verifyWorkerAck(t, reopened, raw, ack); result.State != "COMPLETE" || result.ObservedUnix < startUnix {
		t.Fatal("unexpected scheduled maintenance outcome", result)
	}
	receipt, e := r.MaintenanceResult(ctx, op)
	must(t, e)
	if receipt.CompletedUnix < startUnix || receipt.AbsentCatalogs != 1 {
		t.Fatal("missing physical retirement inside signed window", receipt)
	}
	must(t, r.VerifyComplete(ctx, head))
}

func TestWorkerCommandMaintenanceSeparateAuthorityAndActualOutcome(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.AttemptMillis = 60000
	f.endpoint(t, nil)
	r, head, makeCommand := maintenanceCommandFixture(t, f)
	w := f.nodes[0]
	ctx := context.Background()
	for n, kind := range []string{"wrong-key", "wrong-operation", "protected", "closed", "valid"} {
		op := storage.Hash([]byte(kind))
		permitOp := op
		signer := f.maintenance
		retire := f.generation
		if kind == "wrong-key" {
			signer = f.writer
		}
		if kind == "wrong-operation" {
			permitOp = storage.Hash([]byte("another-operation"))
		}
		if kind == "protected" {
			retire = head
		}
		permission := maintenancePermit(t, f, r, permitOp, signer, retire)
		if kind == "closed" {
			trust := f.domain.Trust
			now := time.Now().Unix()
			grant, e := generation.SignRetentionProtection(generation.RetentionProtection{
				Format: generation.RetentionProtectionFormat, Node: w.node, Domain: trust.Domain, Repository: trust.Repository,
				Epoch: trust.Epoch, Operation: op, Action: "CLOSE", NotBefore: now - 60, ExpiresUnix: now + 60,
			}, f.maintenance)
			must(t, e)
			_, e = w.ApplyRetentionProtection(ctx, trust.Domain, grant)
			must(t, e)
		}
		raw := makeCommand(permission, op, uint64(n+1))
		ack, e := w.ExecuteCommand(ctx, raw)
		must(t, e)
		if kind == "wrong-key" || kind == "wrong-operation" {
			if a := verifyWorkerAck(t, w, raw, ack); a.State != "FAILED" || a.ErrorCode != "POLICY_BLOCKED" {
				t.Fatal("invalid deletion authority admitted", a)
			}
			must(t, r.VerifyComplete(ctx, f.generation))
			continue
		}
		if len(ack) != 0 {
			t.Fatal("admission claimed execution")
		}
		stop := start(t, w)
		var record CommandRecord
		waitFor(t, 60*time.Second, func() bool {
			record = actionRecord(t, w, raw)
			return len(record.Ack) != 0
		})
		stop()
		a := verifyWorkerAck(t, w, raw, record.Ack)
		if kind == "protected" {
			if a.State != "FAILED" || a.ErrorCode != "MAINTENANCE_BLOCKED" {
				t.Fatal(a)
			}
			must(t, r.VerifyComplete(ctx, f.generation))
			continue
		}
		if kind == "closed" {
			if a.State != "FAILED" || a.ErrorCode != "EFFECT_UNCONFIRMED" {
				t.Fatal(a)
			}
			must(t, r.VerifyComplete(ctx, f.generation))
			continue
		}
		var result MaintenanceReceipt
		must(t, json.Unmarshal(record.Result, &result))
		if a.State != "COMPLETE" || a.ResultDigest != storage.Hash(record.Result) || result.Kind != "maintenance" || result.Result.Operation != op || result.Result.AbsentObjects < 1 || result.Result.AbsentCatalogs != 1 {
			t.Fatal("missing GC outcome", a, result)
		}
		must(t, r.VerifyComplete(ctx, head))
		again, e := w.ExecuteCommand(ctx, raw)
		must(t, e)
		if !bytes.Equal(again, record.Ack) {
			t.Fatal("receipt changed")
		}
	}
}

func TestWorkerCommandMaintenanceSIGKILLAfterReplicaResultDoesNotDeleteLaterData(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	r, head, makeCommand := maintenanceCommandFixture(t, f)
	w := f.nodes[0]
	ctx := context.Background()
	op := storage.Hash([]byte("maintenance-crash"))
	permission := maintenancePermit(t, f, r, op, f.maintenance, f.generation)
	envelope := makeCommand(permission, op, 1)
	in := commandChild{planningChild: planningChild{Directory: w.dir, Node: w.node, Point: "worker-command-maintenance-result-durable", Owner: w.owner, Certificate: w.cert.Certificate[0], CA: f.ca.cert.Raw, Key: w.cert.PrivateKey.(ed25519.PrivateKey)}, Envelope: envelope, Run: true}
	raw, e := json.Marshal(in)
	must(t, e)
	file := filepath.Join(f.base, "maintenance-child.json")
	must(t, os.WriteFile(file, raw, 0600))
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestWorkerCommandSIGKILLChild$")
	child.Env = append(os.Environ(), "OUTPOST_WORKER_COMMAND_CHILD="+file)
	output, e := child.CombinedOutput()
	exit, ok := e.(*exec.ExitError)
	if !ok || bounded.Err() != nil {
		t.Fatalf("not killed %v %s", e, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("wrong exit %v %s", e, output)
	}
	before := actionRecord(t, w, envelope)
	if len(before.Ack) > 0 {
		t.Fatal("worker ACK preceded result boundary")
	}
	original, e := r.MaintenanceResult(ctx, op)
	must(t, e)
	orphan := []byte("arrived after committed maintenance result")
	name := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica", "objects", storage.Hash(orphan))
	must(t, os.WriteFile(name, orphan, 0600))
	other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer other.Close()
	stop := start(t, other)
	after := waitAction(t, other, envelope)
	stop()
	if a := verifyWorkerAck(t, other, envelope, after.Ack); a.State != "COMPLETE" {
		t.Fatal(a)
	}
	var result MaintenanceReceipt
	must(t, json.Unmarshal(after.Result, &result))
	if result.Result != original {
		t.Fatal("replica result changed on command replay")
	}
	got, e := os.ReadFile(name)
	must(t, e)
	if !bytes.Equal(got, orphan) {
		t.Fatal("old command deleted later bytes")
	}
	must(t, r.VerifyComplete(ctx, head))
}
