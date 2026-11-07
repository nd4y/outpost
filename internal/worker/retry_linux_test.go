package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/upload"
)

func blockedUploadCommand(t *testing.T) (*fixture, control.Config, control.Job, func(string, string, uint64) []byte, *atomic.Bool) {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	pub, planner := key(t)
	f.domain.Planner = pub
	f.domain.Placement.Edges = nil
	f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
	w := f.nodes[0]
	var full atomic.Bool
	full.Store(true)
	server := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)), Logins: map[string]teststore.Login{w.node: {Secret: "isolated-retry-secret"}}, Before: func(rw http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
		if full.Load() {
			rw.WriteHeader(507)
			return true
		}
		return false
	}})
	p := storage.Profile{Kind: "webdav", Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 2000, CredentialScope: "namespace", NoDelete: true}
	f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
	f.domain.Placement.Targets = []string{p.ID()}
	f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
	replica, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	op := storage.Hash([]byte("retry upload"))
	plan, e := upload.Build(ctx, replica, f.generation, upload.Plan{Format: upload.Format, Operation: op, Profile: p, AllowExternal: true, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}}, StartMillis: time.Now().UnixMilli(), ExpiresUnix: time.Now().Add(3 * time.Minute).Unix(), SlotMillis: 500}, planner)
	must(t, e)
	job := control.Job{Operation: op, Executor: w.node, Kind: "upload", Domain: f.domain.Trust.Domain, Generation: f.generation, Target: p.ID(), Plan: plan}
	w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
		return storage.New(p, storage.Credentials{Access: w.node, Secret: server.Options.Logins[w.node].Secret, ExpiresUnix: time.Now().Add(time.Minute).Unix()}, server.Roots)
	}
	cfg, command := workerCommandFixture(t, f, 0, []control.Job{job})
	stop := start(t, w)
	wait(t, func() bool { s, e := w.Status(ctx); return e == nil && s.Jobs[op].Phase == "BLOCKED" })
	stop()
	return f, cfg, job, command, &full
}

func TestWorkerCommandRetrySIGKILLBetweenQueueAndWorkerReceipt(t *testing.T) {
	for _, point := range []string{"worker-command-intent-durable", "worker-command-retry-queue-durable", "worker-command-ack-durable"} {
		t.Run(point, func(t *testing.T) {
			f, _, job, makeCommand, full := blockedUploadCommand(t)
			w := f.nodes[0]
			ctx := context.Background()
			envelope := makeCommand("retry", job.Operation, 1)
			in := commandChild{planningChild: planningChild{Directory: w.dir, Node: w.node, Point: point, Owner: w.owner, Certificate: w.cert.Certificate[0], CA: f.ca.cert.Raw, Key: w.cert.PrivateKey.(ed25519.PrivateKey)}, Envelope: envelope}
			raw, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(f.base, "retry-child.json")
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
			other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots, Resolve: w.resolve})
			must(t, e)
			defer other.Close()
			ack, e := other.ExecuteCommand(ctx, envelope)
			must(t, e)
			if verifyWorkerAck(t, other, envelope, ack).State != "COMPLETE" {
				t.Fatal("retry not acknowledged")
			}
			full.Store(false)
			stop := start(t, other)
			wait(t, func() bool { return complete(other, job.Operation) })
			stop()
			before, e := other.Status(ctx)
			must(t, e)
			same, e := other.ExecuteCommand(ctx, envelope)
			must(t, e)
			after, e := other.Status(ctx)
			must(t, e)
			if !bytes.Equal(same, ack) || after.Jobs[job.Operation].Attempts != before.Jobs[job.Operation].Attempts || after.Jobs[job.Operation].Phase != "COMPLETE" {
				t.Fatal("retry replayed completed upload")
			}
			denied := makeCommand("retry", job.Operation, 2)
			out, e := other.ExecuteCommand(ctx, denied)
			must(t, e)
			if verifyWorkerAck(t, other, denied, out).State != "FAILED" {
				t.Fatal("complete job resurrected")
			}
		})
	}
}

func TestWorkerCommandRetryRechecksPolicyAndPreservesHolds(t *testing.T) {
	f, cfg, job, makeCommand, _ := blockedUploadCommand(t)
	w := f.nodes[0]
	ctx := context.Background()
	pause := makeCommand("pause", "", 1)
	_, e := w.ExecuteCommand(ctx, pause)
	must(t, e)
	retry := makeCommand("retry", job.Operation, 2)
	cut := errors.New("intent interrupted")
	w.Fault = func(point string) error {
		if point == "worker-command-intent-durable" {
			return cut
		}
		return nil
	}
	if _, e = w.ExecuteCommand(ctx, retry); !errors.Is(e, cut) {
		t.Fatal(e)
	}
	w.Fault = nil
	if e = w.Retry(ctx, job.Operation); !errors.Is(e, ErrDenied) {
		t.Fatal("local retry stole pending command", e)
	}
	cfg.Revision++
	cfg.Jobs = nil
	raw, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, w.Accept(ctx, raw))
	ack, e := w.ExecuteCommand(ctx, retry)
	must(t, e)
	if verifyWorkerAck(t, w, retry, ack).State != "FAILED" {
		t.Fatal("withdrawn retry admitted")
	}
	s, e := w.Status(ctx)
	must(t, e)
	if !s.Controls.Domains[job.Domain] || s.Jobs[job.Operation].Phase != "BLOCKED" {
		t.Fatal("policy denial changed hold or job")
	}
}

func TestWorkerLocalRetryRecoversQueueCommitAndDoesNotRepeat(t *testing.T) {
	f, _, job, _, full := blockedUploadCommand(t)
	w := f.nodes[0]
	ctx := context.Background()
	cut := errors.New("interrupted")
	w.Fault = func(point string) error {
		if point == "worker-local-retry-queue-durable" {
			return cut
		}
		return nil
	}
	if e := w.Retry(ctx, job.Operation); !errors.Is(e, cut) {
		t.Fatal(e)
	}
	w.Fault = nil
	other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots, Resolve: w.resolve})
	must(t, e)
	defer other.Close()
	must(t, other.Retry(ctx, job.Operation))
	full.Store(false)
	stop := start(t, other)
	wait(t, func() bool { return complete(other, job.Operation) })
	stop()
	if e = other.Retry(ctx, job.Operation); !errors.Is(e, ErrDenied) {
		t.Fatal("local completed job retried", e)
	}
}
