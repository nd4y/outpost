package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
)

func workerCommandFixture(t *testing.T, f *fixture, index int, jobs []control.Job) (control.Config, func(string, string, uint64) []byte) {
	t.Helper()
	w := f.nodes[index]
	service, signer := key(t)
	c := f.cfg
	c.Node = w.node
	c.Domains = []control.Domain{f.domain}
	c.Jobs = jobs
	grant, e := command.SignAuthority(command.Authority{Format: command.AuthorityFormat, Service: service, Node: w.node, Tenant: storage.Hash([]byte("tenant")), Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, WriterEpoch: 1, AuthorityEpoch: 1, Kinds: []string{"pause", "resume"}, NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix}, f.owner)
	must(t, e)
	c.Commands = []json.RawMessage{grant}
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, w.Accept(context.Background(), raw))
	return c, func(kind, job string, seq uint64) []byte {
		now := time.Now().Unix()
		env := command.Envelope{Format: command.EnvelopeFormat, Actor: storage.Hash([]byte("operator")), Service: command.Identity(service), Node: w.node, Sequence: seq, ConfigurationDigest: storage.Hash(raw), AdmittedUnix: now, Request: command.Request{Operation: storage.Hash([]byte(kind + "/" + job + "/" + string(rune(seq)))), Reason: "OPERATOR_REQUEST", Tenant: storage.Hash([]byte("tenant")), Domain: f.domain.Trust.Domain, Kind: kind, Job: job, ExpectedRevision: c.Revision, Authority: grant, ExpiresUnix: now + 120}}
		out, e := command.SignEnvelope(env, f.owner.Public().(ed25519.PublicKey), signer)
		must(t, e)
		return out
	}
}
func verifyWorkerAck(t *testing.T, w *Worker, envelope, raw []byte) command.Ack {
	t.Helper()
	ack, e := command.VerifyAck(raw, envelope, w.owner, w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), time.Now())
	must(t, e)
	return ack
}
func TestWorkerCommandPauseSurvivesRestartAndPolicyThenResumeAndReplay(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, _ := f.jobs()
	c, makeCommand := workerCommandFixture(t, f, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push})
	w := f.nodes[0]
	ctx := context.Background()
	pause := makeCommand("pause", "", 1)
	ack, e := w.ExecuteCommand(ctx, pause)
	must(t, e)
	if a := verifyWorkerAck(t, w, pause, ack); a.State != "COMPLETE" || a.ControlRevision != 2 {
		t.Fatal(a)
	}
	other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer other.Close()
	start(t, f.nodes[1])
	stop := start(t, other)
	wait(t, func() bool { s, e := other.Status(ctx); return e == nil && s.Phase == "ACTIVE" })
	time.Sleep(150 * time.Millisecond)
	if complete(other, push.Operation) {
		t.Fatal("restarted worker ignored pause")
	}
	stop()
	// A fresh policy must not silently remove a durable operator hold.
	c.Revision++
	next, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, other.Accept(ctx, next))
	stop = start(t, other)
	wait(t, func() bool { s, e := other.Status(ctx); return e == nil && s.Revision == 2 })
	s, e := other.Status(ctx)
	must(t, e)
	if !s.Controls.Domains[f.domain.Trust.Domain] || s.Jobs[push.Operation].Attempts != 0 {
		t.Fatal("policy cleared hold", s)
	}
	stop()
	// Replay acknowledges the old result even under a newer policy; it does not
	// apply the old mutation. A new command needs the new exact configuration.
	same, e := other.ExecuteCommand(ctx, pause)
	must(t, e)
	if !bytes.Equal(same, ack) {
		t.Fatal("historical ack changed")
	}
	fresh := f.cfg
	fresh.Revision = 3
	f.cfg = fresh
	_, makeCommand = workerCommandFixture(t, f, 0, []control.Job{push})
	resume := makeCommand("resume", "", 2)
	out, e := other.ExecuteCommand(ctx, resume)
	must(t, e)
	if verifyWorkerAck(t, other, resume, out).State != "COMPLETE" {
		t.Fatal("resume failed")
	}
	same, e = other.ExecuteCommand(ctx, pause)
	must(t, e)
	if !bytes.Equal(same, ack) {
		t.Fatal("replay changed")
	}
	s, e = other.Status(ctx)
	must(t, e)
	if s.Controls.Domains[f.domain.Trust.Domain] {
		t.Fatal("old pause replayed its effect")
	}
	stop = start(t, other)
	wait(t, func() bool { return complete(other, push.Operation) })
	stop()
}
func TestWorkerCommandIntentRestartAndNoFalseFailureOnCancellation(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	_, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	raw := makeCommand("pause", "", 1)
	w.Fault = func(p string) error {
		if p == "worker-command-intent-durable" {
			return errors.New("crash")
		}
		return nil
	}
	if _, e := w.ExecuteCommand(ctx, raw); e == nil {
		t.Fatal("fault absent")
	}
	w.Fault = nil
	s, e := w.Status(ctx)
	must(t, e)
	if !s.Controls.Domains[f.domain.Trust.Domain] || s.Controls.Applied == s.Controls.Revision {
		t.Fatal("intent not durable or falsely applied")
	}
	other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer other.Close()
	out, e := other.ExecuteCommand(ctx, raw)
	must(t, e)
	if verifyWorkerAck(t, w, raw, out).State != "COMPLETE" {
		t.Fatal("restart did not settle")
	}
	if e = other.MigrateControls(ctx, true); !errors.Is(e, ErrDenied) {
		t.Fatal("rollback discarded hold or command history", e)
	}
}
func TestWorkerCommandRejectsUnknownJobAndRemovedGrantWithoutChangingHolds(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	c, makeCommand := workerCommandFixture(t, f, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	unknown := makeCommand("pause", storage.Hash([]byte("unknown-job")), 1)
	out, e := w.ExecuteCommand(ctx, unknown)
	must(t, e)
	if verifyWorkerAck(t, w, unknown, out).State != "FAILED" {
		t.Fatal("unknown job accepted")
	}
	removed := makeCommand("pause", "", 2)
	c.Revision++
	c.Commands = nil
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, w.Accept(ctx, raw))
	out, e = w.ExecuteCommand(ctx, removed)
	must(t, e)
	if verifyWorkerAck(t, w, removed, out).State != "FAILED" {
		t.Fatal("removed grant accepted")
	}
	s, e := w.Status(ctx)
	must(t, e)
	if len(s.Controls.Domains) != 0 || len(s.Controls.Jobs) != 0 || s.Controls.Revision != 1 {
		t.Fatal("denied command changed holds")
	}
	if _, e = w.ExecuteCommand(ctx, []byte("{}")); e == nil {
		t.Fatal("invalid unsigned command")
	}
}
func TestWorkerControlsMigrationBackupRollbackAndCorruption(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.config(t, 0, nil)
	w := f.nodes[0]
	ctx := context.Background()
	must(t, w.MigrateControls(ctx, true))
	s, e := w.Status(ctx)
	must(t, e)
	if s.Format != LegacyFormat || s.Controls != nil {
		t.Fatal("not legacy")
	}
	w.Fault = func(p string) error {
		if p == "worker-controls-directory-durable" {
			return errors.New("crash")
		}
		return nil
	}
	if e = w.MigrateControls(ctx, false); e == nil {
		t.Fatal("fault absent")
	}
	w.Fault = nil
	s, e = w.Status(ctx)
	must(t, e)
	if s.Format != LegacyFormat {
		t.Fatal("premature format switch")
	}
	must(t, w.MigrateControls(ctx, false))
	s, e = w.Status(ctx)
	must(t, e)
	if s.Format != Format || s.Controls == nil {
		t.Fatal("migration incomplete")
	}
	// Existing empty controls preserve current jobs when rolling back; an old
	// format reader would reject the format-2 state before reading these fields.
	must(t, w.MigrateControls(ctx, true))
	must(t, w.MigrateControls(ctx, false))
	must(t, w.state.WithLock(ctx, func() error {
		raw, e := w.state.Read("worker.json")
		if e != nil {
			return e
		}
		var s Status
		if e = json.Unmarshal(raw, &s); e != nil {
			return e
		}
		s.Controls.Domains[f.domain.Trust.Domain] = true
		raw, e = json.Marshal(s)
		if e != nil {
			return e
		}
		return w.state.Write("worker.json", raw)
	}))
	if _, e = w.Status(ctx); e == nil {
		t.Fatal("tampered holds accepted")
	}
}
