package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func recoveryFixture(t *testing.T, f *fixture) (*recovery.Executor, recovery.Profile) {
	t.Helper()
	ctx := context.Background()
	w := f.nodes[0]
	vol := filepath.Join(f.base, "recovery-volume")
	must(t, os.Mkdir(vol, 0700))
	probe, e := volume.Probe(ctx, vol)
	must(t, e)
	bind, e := volume.Enroll(ctx, vol, probe, w.node, 1)
	must(t, e)
	key := filepath.Join(f.base, "private-recovery-owner.json")
	owner := f.dataOwner
	owner.SigningKey = nil
	must(t, filekit.WriteOwner(key, owner))
	p := recovery.Profile{Format: recovery.ProfileFormat, Node: w.node, Directory: filepath.Join(vol, "output"), Volume: bind, Limits: recovery.Limits{Bytes: 64 << 20, Entries: 1024, FreeBytes: 1 << 20, FreeInodes: 32}, Presets: []recovery.Preset{{ID: storage.Hash([]byte("test-private-recovery")), Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: f.domain.Trust.Epoch, OwnerFile: key}}}
	x, e := recovery.OpenExecutor(ctx, p, true)
	must(t, e)
	t.Cleanup(func() { x.Close() })
	return x, p
}
func TestWorkerRecoveryKeylessAdmissionTrustedRuntimeAndOriginalReport(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	raw := makeCommand("restore", f.generation, 1)
	ack, e := w.ExecuteCommand(ctx, raw)
	must(t, e)
	if len(ack) != 0 {
		t.Fatal("queue claimed completion")
	}
	stop := start(t, w)
	wait(t, func() bool { s, e := w.Status(ctx); return e == nil && s.Phase == "ACTIVE" })
	time.Sleep(80 * time.Millisecond)
	stop()
	op := actionRecord(t, w, raw)
	if op.Work.Attempts != 0 || len(op.Ack) != 0 {
		t.Fatal("keyless worker attempted decryption", op)
	}
	state, e := w.Status(ctx)
	must(t, e)
	if state.Format != RecoveryFormat {
		t.Fatal("missing reader fence")
	}
	if e = w.MigrateControls(ctx, true); e == nil {
		t.Fatal("rollback discarded restore history")
	}
	x, p := recoveryFixture(t, f)
	w.recovery = x
	must(t, os.RemoveAll(filepath.Join(f.base, "source-kit")))
	must(t, os.Remove(filepath.Join(f.base, "input")))
	stop = start(t, w)
	op = waitAction(t, w, raw)
	stop()
	a := verifyWorkerAck(t, w, raw, op.Ack)
	if a.State != "COMPLETE" || op.Work.CleanupPending {
		t.Fatal(a, op.Work)
	}
	var result recovery.Receipt
	must(t, json.Unmarshal(op.Result, &result))
	must(t, result.Validate())
	body, e := os.ReadFile(filepath.Join(p.Directory, "results", a.Operation, "data", "dataset/данные.bin"))
	must(t, e)
	if !bytes.Equal(body, f.content) {
		t.Fatal("restored bytes differ")
	}
	if result.Binding != storage.Hash(raw) || result.Restored.Generation != f.generation {
		t.Fatal("wrong command binding")
	}
	must(t, os.Remove(p.Presets[0].OwnerFile))
	again, e := w.ExecuteCommand(ctx, raw)
	must(t, e)
	if !bytes.Equal(again, op.Ack) {
		t.Fatal("historical ACK changed")
	}
	grant := commandEnrollment(t, f)
	snap, e := w.ManagementSnapshot(ctx, grant, f.domain.Trust.Domain)
	must(t, e)
	if len(snap.Commands) != 1 || snap.Commands[0].Restore == nil || snap.Commands[0].VerifiedUnix != result.VerifiedUnix || snap.Commands[0].Verification != "DECRYPTED" {
		t.Fatal("restore report lost", snap.Commands)
	}
	rep, e := w.OpenReporter(ctx, storage.Hash([]byte("restore-report")), f.domain.Trust.Domain, grant, true)
	must(t, e)
	defer rep.Close()
	encoded, e := rep.Enqueue(ctx, snap)
	must(t, e)
	enrollment, e := management.VerifyEnrollment(grant, w.owner)
	must(t, e)
	report, e := management.VerifyReport(encoded, enrollment, time.Now())
	must(t, e)
	if report.Format != management.RecoveryReportFormat || report.Generations[0].VerifiedUnix != 0 {
		t.Fatal("selected restore recertified whole inventory")
	}
	for _, private := range []string{p.Directory, p.Presets[0].OwnerFile, "dataset/", "данные.bin"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("private recovery metadata in report")
		}
	}
	report.Format = management.CommandReportFormat
	if _, e = management.SignReport(report, enrollment, w.cert.PrivateKey.(ed25519.PrivateKey), time.Now()); e == nil {
		t.Fatal("restore accepted old report")
	}
}
func TestWorkerRecoveryPauseBeforePublicationJoinsAndResumes(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	x, p := recoveryFixture(t, f)
	w.recovery = x
	raw := makeCommand("restore", f.generation, 1)
	env, _, e := command.VerifyEnvelope(raw, w.owner)
	must(t, e)
	reached := make(chan struct{})
	unblock := make(chan struct{})
	first := true
	x.Fault = func(point string) error {
		if point == "recovery-before-publish" && first {
			first = false
			close(reached)
			<-unblock
		}
		return nil
	}
	_, e = w.ExecuteCommand(ctx, raw)
	must(t, e)
	stop := start(t, w)
	select {
	case <-reached:
	case <-time.After(8 * time.Second):
		t.Fatal("restore did not reach publication")
	}
	pause := makeCommand("pause", "", 2)
	done := make(chan error, 1)
	go func() { _, e := w.ExecuteCommand(ctx, pause); done <- e }()
	wait(t, func() bool { s, e := w.Status(ctx); return e == nil && s.Controls.Domains[f.domain.Trust.Domain] })
	close(unblock)
	must(t, <-done)
	if _, e = os.Stat(filepath.Join(p.Directory, "results", env.Request.Operation)); !os.IsNotExist(e) {
		t.Fatal("paused restore published", e)
	}
	op := actionRecord(t, w, raw)
	if len(op.Ack) > 0 {
		t.Fatal("pause terminalized restore", op)
	}
	_, e = w.ExecuteCommand(ctx, makeCommand("resume", "", 3))
	must(t, e)
	op = waitAction(t, w, raw)
	stop()
	if verifyWorkerAck(t, w, raw, op.Ack).State != "COMPLETE" {
		t.Fatal(op)
	}
	retained, e := os.ReadDir(filepath.Join(p.Directory, "staging"))
	must(t, e)
	if len(retained) != 1 {
		t.Fatal("canceled stage not retained", len(retained))
	}
	replica, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	st, e := replica.Status(ctx)
	must(t, e)
	if len(st.Pins) != 0 {
		t.Fatal("completed pin retained")
	}
}

func TestWorkerRecoverySIGKILLBetweenBundleAndSignedResult(t *testing.T) {
	for _, point := range []string{"recovery-bundle-durable", "recovery-before-pin-release", "worker-command-work-result-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			f.endpoint(t, nil)
			_, makeCommand := workerCommandFixture(t, f, 0, nil)
			w := f.nodes[0]
			ctx := context.Background()
			x, p := recoveryFixture(t, f)
			envelope := makeCommand("restore", f.generation, 1)
			in := commandChild{planningChild: planningChild{Directory: w.dir, Node: w.node, Point: point, Owner: w.owner, Certificate: w.cert.Certificate[0], CA: f.ca.cert.Raw, Key: w.cert.PrivateKey.(ed25519.PrivateKey)}, Envelope: envelope, Run: true, Recovery: &p}
			raw, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(f.base, "recovery-child.json")
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
			env, _, e := command.VerifyEnvelope(envelope, w.owner)
			must(t, e)
			before, e := x.Outcome(ctx, recoveryRequest(env, envelope))
			must(t, e)
			if before == nil {
				t.Fatal("published result missing")
			}
			beforeRecord := actionRecord(t, w, envelope)
			if (len(beforeRecord.Ack) > 0) != (point == "worker-command-work-result-durable") {
				t.Fatal("wrong durable boundary")
			}
			must(t, os.Remove(p.Presets[0].OwnerFile))
			other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots, Recovery: x})
			must(t, e)
			defer other.Close()
			stop := start(t, other)
			after := waitAction(t, other, envelope)
			stop()
			var receipt recovery.Receipt
			must(t, json.Unmarshal(after.Result, &receipt))
			if receipt != *before || verifyWorkerAck(t, other, envelope, after.Ack).State != "COMPLETE" || after.Work.CleanupPending {
				t.Fatal("original result changed", receipt, after.Work)
			}
			if len(beforeRecord.Ack) > 0 && !bytes.Equal(beforeRecord.Ack, after.Ack) {
				t.Fatal("original ACK changed")
			}
			body, e := os.ReadFile(filepath.Join(p.Directory, "results", env.Request.Operation, "data/dataset/данные.bin"))
			must(t, e)
			if !bytes.Equal(body, f.content) {
				t.Fatal("restored bytes changed")
			}
			stages, e := os.ReadDir(filepath.Join(p.Directory, "staging"))
			must(t, e)
			if len(stages) != 0 {
				t.Fatal("replay copied plaintext again")
			}
			replica, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
			must(t, e)
			defer replica.Close()
			st, e := replica.Status(ctx)
			must(t, e)
			if len(st.Pins) != 0 {
				t.Fatal("original pin retained")
			}
		})
	}
}
func TestWorkerRecoveryWithdrawalRetainsStageAndCleansOnlyOwnPin(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	cfg, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	x, p := recoveryFixture(t, f)
	w.recovery = x
	raw := makeCommand("restore", f.generation, 1)
	env, _, e := command.VerifyEnvelope(raw, w.owner)
	must(t, e)
	reached := make(chan struct{})
	unblock := make(chan struct{})
	x.Fault = func(point string) error {
		if point == "recovery-before-publish" {
			close(reached)
			<-unblock
		}
		return nil
	}
	replica, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	foreign := storage.Hash([]byte("unrelated restore"))
	must(t, replica.Pin(ctx, foreign, f.generation, "restore"))
	_, e = w.ExecuteCommand(ctx, raw)
	must(t, e)
	stop := start(t, w)
	select {
	case <-reached:
	case <-time.After(8 * time.Second):
		t.Fatal("restore not ready")
	}
	cfg.Revision++
	cfg.Commands = nil
	policy, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, w.Accept(ctx, policy))
	close(unblock)
	after := waitAction(t, w, raw)
	wait(t, func() bool { return !actionRecord(t, w, raw).Work.CleanupPending })
	stop()
	if verifyWorkerAck(t, w, raw, after.Ack).State != "FAILED" {
		t.Fatal("withdrawn restore completed")
	}
	if _, e = os.Stat(filepath.Join(p.Directory, "results", env.Request.Operation)); !os.IsNotExist(e) {
		t.Fatal("withdrawn output published", e)
	}
	stages, e := os.ReadDir(filepath.Join(p.Directory, "staging"))
	must(t, e)
	if len(stages) != 1 {
		t.Fatal("retained data erased")
	}
	st, e := replica.Status(ctx)
	must(t, e)
	if len(st.Pins) != 1 || st.Pins[foreign].Generation != f.generation {
		t.Fatal("wrong pin cleanup", st.Pins)
	}
	if _, e = x.Outcome(ctx, recoveryRequest(env, raw)); e != recovery.ErrStopped {
		t.Fatal("terminal attempt not fenced", e)
	}
}
