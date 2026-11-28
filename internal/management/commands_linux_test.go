package management

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
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func commandFixture(t *testing.T, f *fixture) (control.Config, command.Request, Principal) {
	t.Helper()
	f.enroll(t)
	c := configFixture(t, f)
	d := c.Domains[0].Trust
	a := command.Authority{Format: command.AuthorityFormat, Service: f.options.Signer.Public().(ed25519.PublicKey), Node: c.Node, Tenant: f.e.Tenant, Domain: d.Domain, Repository: d.Repository, WriterEpoch: d.Epoch, AuthorityEpoch: 1, Kinds: []string{"pause", "resume", "retry", "scrub", "restore", "maintenance"}, NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix}
	grant, e := command.SignAuthority(a, f.owner)
	must(t, e)
	c.Commands = []json.RawMessage{grant}
	input := configurationMutation(t, f, c, "command-policy", 0)
	preview, e := f.r.PreviewConfiguration(context.Background(), f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	input.PreviewDigest = preview.CandidateDigest
	_, e = f.r.ApplyConfiguration(context.Background(), f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	req := command.Request{Operation: id("pause"), Reason: "OPERATOR_REQUEST", Tenant: f.e.Tenant, Domain: d.Domain, Kind: "pause", ExpectedRevision: c.Revision, Authority: grant, ExpiresUnix: time.Now().Unix() + 600}
	return c, req, Principal{Actor: f.e.Node, Roles: []string{"node"}, Scopes: []Scope{{f.e.Tenant, d.Domain}}}
}
func commandAck(t *testing.T, f *fixture, raw []byte) []byte {
	t.Helper()
	envelope, _, e := command.VerifyEnvelope(raw, f.options.Owner)
	must(t, e)
	ack := command.Ack{Format: command.AckFormat, Node: f.e.Node, Operation: envelope.Request.Operation, EnvelopeDigest: storage.Hash(raw), State: "COMPLETE", StartedUnix: envelope.AdmittedUnix, ObservedUnix: time.Now().Unix(), ControlRevision: 1, ResultDigest: id("applied-controls")}
	out, e := command.SignAck(ack, raw, f.options.Owner, f.node, time.Now())
	must(t, e)
	return out
}
func TestManagementCommandAdmissionExecutionAckReplayAndAudit(t *testing.T) {
	f := newFixture(t)
	_, req, node := commandFixture(t, f)
	ctx := context.Background()
	first, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
	if first.State != "ADMITTED" || first.ResultDigest != "" {
		t.Fatal("admission claimed execution", first)
	}
	again, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
	if first != again {
		t.Fatal("admission replay differs")
	}
	items, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(items) != 1 {
		t.Fatal(items)
	}
	raw := items[0].Document
	envelope, _, e := command.VerifyEnvelope(raw, f.options.Owner)
	must(t, e)
	if envelope.Actor != f.p.Actor || envelope.Sequence != items[0].Sequence || envelope.Request.Digest() != req.Digest() {
		t.Fatal("envelope rebound")
	}
	ack := commandAck(t, f, raw)
	done, e := f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, f.e.Node, req.Operation, ack)
	must(t, e)
	if done.State != "COMPLETE" || done.ResultDigest != storage.Hash(ack) {
		t.Fatal(done)
	}
	f.reopen(t)
	same, e := f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, f.e.Node, req.Operation, ack)
	must(t, e)
	if same != done {
		t.Fatal("ack replay changed")
	}
	same, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
	if same != done {
		t.Fatal("completed command reenqueued")
	}
	items, _, e = f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(items) != 0 {
		t.Fatal("completed command available")
	}
	operation, e := f.r.Operation(ctx, f.p, f.e.Tenant, req.Operation)
	must(t, e)
	if operation != done {
		t.Fatal(operation)
	}
	audit, _, e := f.r.Audit(ctx, f.p, f.e.Tenant, 0, 256)
	must(t, e)
	if len(audit) != 3 || audit[2].Actor != f.p.Actor || audit[2].ObservedUnix != first.ObservedUnix || audit[2].State != "COMPLETE" || audit[2].ResultDigest != done.ResultDigest {
		t.Fatal(audit)
	}
	changed := req
	changed.Kind = "resume"
	if _, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("same operation rebound", e)
	}
}
func TestManagementCommandRejectsPrivilegeScopeStalePolicyAndForgedAck(t *testing.T) {
	f := newFixture(t)
	_, req, node := commandFixture(t, f)
	ctx := context.Background()
	viewer := f.p
	viewer.Roles = []string{"viewer"}
	if _, e := f.r.AdmitCommand(ctx, viewer, f.e.Tenant, f.e.Node, req); !errors.Is(e, ErrDenied) {
		t.Fatal("viewer command", e)
	}
	recovery := f.p
	recovery.Roles = []string{"recovery"}
	if _, e := f.r.AdmitCommand(ctx, recovery, f.e.Tenant, f.e.Node, req); !errors.Is(e, ErrDenied) {
		t.Fatal("recovery pause", e)
	}
	stale := req
	stale.ExpectedRevision++
	if _, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, stale); !errors.Is(e, ErrConflict) {
		t.Fatal("stale config admitted", e)
	}
	foreign := req
	foreign.Tenant = id("other")
	if _, e := f.r.AdmitCommand(ctx, f.p, foreign.Tenant, f.e.Node, foreign); !errors.Is(e, ErrDenied) {
		t.Fatal("foreign tenant", e)
	}
	operator := f.p
	operator.Roles = []string{"operator"}
	_, e := f.r.AdmitCommand(ctx, operator, f.e.Tenant, f.e.Node, req)
	must(t, e)
	items, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if _, _, e = f.r.Commands(ctx, f.p, f.e.Tenant, f.e.Node, 0, 32); !errors.Is(e, ErrDenied) {
		t.Fatal("owner fetched node queue", e)
	}
	ack := commandAck(t, f, items[0].Document)
	var forged command.Ack
	must(t, json.Unmarshal(ack, &forged))
	forged.Signature[0] ^= 1
	bad, _ := json.Marshal(forged)
	if _, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, f.e.Node, req.Operation, bad); !errors.Is(e, ErrDenied) {
		t.Fatal("forged ack", e)
	}
	if _, e = f.r.AcknowledgeCommand(ctx, f.p, f.e.Tenant, f.e.Node, req.Operation, ack); !errors.Is(e, ErrDenied) {
		t.Fatal("controller acknowledged worker", e)
	}
	original, e := f.r.Operation(ctx, f.p, f.e.Tenant, req.Operation)
	must(t, e)
	if original.State != "ADMITTED" {
		t.Fatal(original)
	}
	enrollment, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	if _, e = f.r.ApplyEnrollment(ctx, f.p, req.Operation, "POLICY_CHANGE", enrollment, 1); !errors.Is(e, ErrConflict) {
		t.Fatal("enrollment reused command ID", e)
	}
}
func TestManagementCommandIntentBlocksLaterDeliveryAndQuota(t *testing.T) {
	f := newFixture(t)
	c, req, node := commandFixture(t, f)
	ctx := context.Background()
	f.r.Fault = func(p string) error {
		if p == "management-command-intent-durable" {
			return errors.New("crash")
		}
		return nil
	}
	if _, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req); e == nil {
		t.Fatal("no fault")
	}
	f.reopen(t)
	later := req
	later.Operation = id("resume")
	later.Kind = "resume"
	_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, later)
	must(t, e)
	items, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(items) != 0 {
		t.Fatal("later command overtook durable intent")
	}
	_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
	items, _, e = f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(items) != 2 || items[0].Sequence >= items[1].Sequence {
		t.Fatal("wrong command order", items)
	}
	c.Revision++
	input := configurationMutation(t, f, c, "next-config", 1)
	input.Operation = req.Operation
	preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	input.PreviewDigest = preview.CandidateDigest
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input); !errors.Is(e, ErrConflict) {
		t.Fatal("config reused command ID", e)
	}
	next := req
	next.Operation = id("quota")
	f.r.blobs.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if _, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, next); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("blob quota ignored", e)
	}
	if _, e = f.r.Operation(ctx, f.p, f.e.Tenant, next.Operation); !errors.Is(e, ErrUnavailable) {
		t.Fatal("failed blob write admitted", e)
	}
}

type commandCrash struct {
	Directory, Point         string
	Owner                    ed25519.PublicKey
	Signer                   ed25519.PrivateKey
	Principal, NodePrincipal Principal
	Request                  command.Request
	Node                     string
	Ack                      []byte
}

func TestManagementCommandSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_COMMAND_KILL")
	if file == "" {
		return
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var in commandCrash
	must(t, json.Unmarshal(raw, &in))
	r, e := Open(Options{Directory: in.Directory, Owner: in.Owner, Signer: in.Signer})
	must(t, e)
	defer r.Close()
	r.Fault = func(p string) error {
		if p == in.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	if in.Ack != nil {
		_, e = r.AcknowledgeCommand(context.Background(), in.NodePrincipal, in.Request.Tenant, in.Node, in.Request.Operation, in.Ack)
	} else {
		_, e = r.AdmitCommand(context.Background(), in.Principal, in.Request.Tenant, in.Node, in.Request)
	}
	must(t, e)
	t.Fatal("kill point absent")
}
func TestManagementCommandSIGKILLCommitBoundaries(t *testing.T) {
	for _, point := range []string{"management-command-intent-durable", "management-command-envelope-durable", "management-command-published-durable", "management-command-ack-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			_, req, node := commandFixture(t, f)
			ctx := context.Background()
			in := commandCrash{Directory: f.dir, Point: point, Owner: f.options.Owner, Signer: f.options.Signer, Principal: f.p, NodePrincipal: node, Request: req, Node: f.e.Node}
			var original []byte
			if point == "management-command-ack-durable" {
				_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
				must(t, e)
				items, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
				must(t, e)
				original = items[0].Document
				in.Ack = commandAck(t, f, original)
			}
			must(t, f.r.Close())
			f.r = nil
			raw, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(filepath.Dir(f.dir), "command-child.json")
			must(t, os.WriteFile(file, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestManagementCommandSIGKILLChild$")
			child.Env = append(os.Environ(), "OUTPOST_COMMAND_KILL="+file)
			output, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("child did not terminate %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong signal %v %s", e, output)
			}
			f.r, e = Open(f.options)
			must(t, e)
			items, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
			must(t, e)
			want := 0
			if point == "management-command-published-durable" {
				want = 1
			}
			if len(items) != want {
				t.Fatal("wrong publication boundary", len(items), want)
			}
			receipt, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
			must(t, e)
			if in.Ack != nil {
				if receipt.State != "COMPLETE" {
					t.Fatal(receipt)
				}
				again, e := f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, f.e.Node, req.Operation, in.Ack)
				must(t, e)
				if again != receipt {
					t.Fatal("ack replay changed")
				}
			} else {
				if receipt.State != "ADMITTED" {
					t.Fatal(receipt)
				}
				items, _, e = f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
				must(t, e)
				if len(items) != 1 {
					t.Fatal(items)
				}
				original = items[0].Document
				f.reopen(t)
				items, _, e = f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
				must(t, e)
				if !bytes.Equal(original, items[0].Document) {
					t.Fatal("signed envelope changed after restart")
				}
			}
			audit, _, e := f.r.Audit(ctx, f.p, f.e.Tenant, 0, 256)
			must(t, e)
			if len(audit) != 3 || audit[2].Actor != f.p.Actor {
				t.Fatal("duplicate or rebound audit", audit)
			}
		})
	}
}
