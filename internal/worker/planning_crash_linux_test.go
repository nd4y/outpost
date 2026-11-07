package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

type planningChild struct {
	Directory, Node, Point string
	Owner                  ed25519.PublicKey
	Certificate, CA        []byte
	Key                    ed25519.PrivateKey
}

func TestUploadPlanningCrashProcess(t *testing.T) {
	file := os.Getenv("OUTPOST_PLANNING_CHILD")
	if file == "" {
		return
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var c planningChild
	must(t, json.Unmarshal(raw, &c))
	roots := x509.NewCertPool()
	ca, e := x509.ParseCertificate(c.CA)
	must(t, e)
	roots.AddCert(ca)
	w, e := Open(Options{Directory: c.Directory, Node: c.Node, Owner: c.Owner, Certificate: tls.Certificate{Certificate: [][]byte{c.Certificate}, PrivateKey: c.Key}, Roots: roots, Resolve: func(context.Context, storage.Profile) (*storage.Backend, error) { return nil, ErrDenied }})
	must(t, e)
	defer w.Close()
	w.Fault = func(point string) error {
		if point == c.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = w.Run(ctx)
	t.Fatal("child did not reach planning boundary")
}
func TestUploadPlanningSIGKILLKeepsProtectionAcrossQueueHandoff(t *testing.T) {
	for _, point := range []string{"upload-planning-pin-durable", "upload-plan-durable", "upload-queue-admitted", "upload-planning-pin-released"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			w := f.nodes[0]
			pub, planner := key(t)
			f.domain.Planner = pub
			f.domain.Placement.Edges = nil
			f.domain.Placement.AllowedClasses = append(f.domain.Placement.AllowedClasses, "external")
			target := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte(f.domain.Trust.Domain + "/" + f.domain.Trust.Repository)), Logins: map[string]teststore.Login{w.node: {Secret: "synthetic-planning-crash"}}})
			p := storage.Profile{Kind: "webdav", Endpoint: target.Endpoint(), Namespace: target.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 1, TimeoutMillis: 1000, CredentialScope: "namespace", NoDelete: true}
			f.cfg.Targets = []control.Target{{ID: p.ID(), Profile: p}}
			f.domain.Placement.Targets = []string{p.ID()}
			f.domain.Placement.CloudEdges = []policy.CloudEdge{{Node: w.node, Target: p.ID()}}
			grant, e := upload.SignDelegation(upload.Delegation{Format: upload.DelegationFormat, Trust: f.domain.Trust, Epoch: 1, Profile: p, AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: w.node, Class: "trusted", PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)}}, StartMillis: f.cfg.NotBefore * 1000, ExpiresUnix: f.cfg.ExpiresUnix, SlotMillis: 1000}, planner)
			must(t, e)
			f.cfg.Uploads = []json.RawMessage{grant}
			c := f.config(t, 0, nil)
			child := planningChild{Directory: w.dir, Node: w.node, Point: point, Owner: w.owner, Certificate: w.cert.Certificate[0], CA: f.ca.cert.Raw, Key: w.cert.PrivateKey.(ed25519.PrivateKey)}
			raw, e := json.Marshal(child)
			must(t, e)
			input := filepath.Join(f.base, "planning-child.json")
			must(t, os.WriteFile(input, raw, 0600))
			run, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(run, os.Args[0], "-test.run=^TestUploadPlanningCrashProcess$")
			cmd.Env = append(os.Environ(), "OUTPOST_PLANNING_CHILD="+input)
			output, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL || run.Err() != nil {
				t.Fatalf("expected owned child SIGKILL: %v %s", e, output)
			}
			r, e := generation.Open(filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica"), f.domain.Trust, false)
			must(t, e)
			defer r.Close()
			status, e := r.Status(ctx)
			must(t, e)
			_, g, ok := c.UploadDelegation(storage.Hash(grant))
			if !ok {
				t.Fatal("delegation missing")
			}
			job := control.UploadJob(grant, g, f.generation, w.node)
			_, planning := status.Pins[planningPin(job)]
			if planning != (point != "upload-planning-pin-released") || len(status.Pins) == 0 || status.LatestComplete != f.generation {
				t.Fatal("lost generation protection at handoff", status)
			}
			w.resolve = func(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
				return storage.New(p, storage.Credentials{Access: w.node, Secret: target.Options.Logins[w.node].Secret, ExpiresUnix: f.cfg.ExpiresUnix}, target.Roots)
			}
			stop := start(t, w)
			wait(t, func() bool { return complete(w, job.Operation) })
			stop()
			must(t, r.VerifyComplete(ctx, f.generation))
			status, e = r.Status(ctx)
			must(t, e)
			if len(status.Pins) != 0 {
				t.Fatal("owned planning or queue pin leaked after success", status.Pins)
			}
		})
	}
}
