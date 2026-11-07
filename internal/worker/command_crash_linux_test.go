package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
)

func TestWorkerCommandPauseCancelsTransferWhileConfigurationFetchIsBlocked(t *testing.T) {
	f := newFixture(t)
	transferStarted, transferStopped := make(chan struct{}), make(chan struct{})
	var first sync.Once
	f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				blocked := false
				first.Do(func() { blocked = true })
				if blocked {
					_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, generation.MaxCatalog))
					close(transferStarted)
					<-r.Context().Done()
					close(transferStopped)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	push, _ := f.jobs()
	_, makeCommand := workerCommandFixture(t, f, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push})
	w := f.nodes[0]
	ctx := context.Background()
	raw, e := w.cache.Raw(ctx)
	must(t, e)
	cert, target := f.ca.node(t)
	serverTLS, e := control.ServerTLS(cert, f.ca.pool, target)
	must(t, e)
	fetchStarted := make(chan struct{})
	var entered sync.Once
	var count atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			out.Header().Set("Content-Type", "application/json")
			out.Write(raw)
			return
		}
		entered.Do(func() { close(fetchStarted) })
		<-r.Context().Done()
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	w.fetcher, e = control.NewFetcher(server.URL, target, w.node, w.cert, w.roots, 5*time.Second)
	must(t, e)
	defer w.fetcher.Close()
	start(t, f.nodes[1])
	stop := start(t, w)
	defer stop()
	select {
	case <-transferStarted:
	case <-time.After(6 * time.Second):
		t.Fatal("transfer not started")
	}
	select {
	case <-fetchStarted:
	case <-time.After(6 * time.Second):
		t.Fatal("fetch not blocked")
	}
	pause := makeCommand("pause", "", 1)
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ack, e := w.ExecuteCommand(bounded, pause)
	must(t, e)
	if verifyWorkerAck(t, w, pause, ack).State != "COMPLETE" {
		t.Fatal("pause did not complete")
	}
	select {
	case <-transferStopped:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("ack preceded transfer cancellation")
	}
	s, e := w.Status(ctx)
	must(t, e)
	if s.Jobs[push.Operation].Phase == "RUNNING" || !s.Controls.Domains[f.domain.Trust.Domain] || s.Controls.Applied != s.Controls.Revision {
		t.Fatal("ack preceded joined state", s)
	}
}

type commandChild struct {
	planningChild
	Envelope  []byte
	Migration bool
	Run       bool
}

func TestWorkerCommandSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_WORKER_COMMAND_CHILD")
	if file == "" {
		return
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var in commandChild
	must(t, json.Unmarshal(raw, &in))
	roots := x509.NewCertPool()
	ca, e := x509.ParseCertificate(in.CA)
	must(t, e)
	roots.AddCert(ca)
	w, e := Open(Options{Directory: in.Directory, Node: in.Node, Owner: in.Owner, Certificate: tls.Certificate{Certificate: [][]byte{in.Certificate}, PrivateKey: in.Key}, Roots: roots})
	must(t, e)
	defer w.Close()
	w.Fault = func(p string) error {
		if p == in.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	if in.Migration {
		e = w.MigrateControls(context.Background(), false)
	} else {
		_, e = w.ExecuteCommand(context.Background(), in.Envelope)
		if e == nil && in.Run {
			e = w.Run(context.Background())
		}
	}
	must(t, e)
	t.Fatal("kill point absent")
}
func TestWorkerCommandSIGKILLKeepsFormatIntentHoldAndAckBoundaries(t *testing.T) {
	points := []string{"worker-controls-backup-durable", "worker-controls-directory-durable", "worker-controls-format-durable", "worker-command-envelope-durable", "worker-command-intent-durable", "worker-command-applied-durable", "worker-command-ack-durable"}
	for n, point := range points {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			f.endpoint(t, nil)
			_, makeCommand := workerCommandFixture(t, f, 0, nil)
			w := f.nodes[0]
			ctx := context.Background()
			envelope := makeCommand("pause", "", 1)
			migration := n < 3
			if migration {
				must(t, w.MigrateControls(ctx, true))
			}
			in := commandChild{planningChild: planningChild{Directory: w.dir, Node: w.node, Point: point, Owner: w.owner, Certificate: w.cert.Certificate[0], CA: f.ca.cert.Raw, Key: w.cert.PrivateKey.(ed25519.PrivateKey)}, Envelope: envelope, Migration: migration}
			raw, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(f.base, "command-child.json")
			must(t, os.WriteFile(file, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestWorkerCommandSIGKILLChild$")
			child.Env = append(os.Environ(), "OUTPOST_WORKER_COMMAND_CHILD="+file)
			output, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("child did not terminate %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong termination %v %s", e, output)
			}
			other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
			must(t, e)
			defer other.Close()
			s, e := other.Status(ctx)
			must(t, e)
			if migration {
				want := LegacyFormat
				if n == 2 {
					want = Format
				}
				if s.Format != want {
					t.Fatal("wrong migration boundary", s.Format, want)
				}
				must(t, other.MigrateControls(ctx, false))
				return
			}
			hold := s.Controls.Domains[f.domain.Trust.Domain]
			if hold != (n >= 4) {
				t.Fatal("wrong hold boundary", hold)
			}
			var previous []byte
			for _, op := range s.Controls.Operations {
				previous = op.Ack
			}
			if (len(previous) > 0) != (n == 6) {
				t.Fatal("wrong acknowledgement boundary")
			}
			ack, e := other.ExecuteCommand(ctx, envelope)
			must(t, e)
			if verifyWorkerAck(t, other, envelope, ack).State != "COMPLETE" {
				t.Fatal("restart did not complete")
			}
			if len(previous) > 0 && !bytes.Equal(previous, ack) {
				t.Fatal("replay changed durable ack")
			}
			s, e = other.Status(ctx)
			must(t, e)
			if len(s.Controls.Operations) != 1 || !s.Controls.Domains[f.domain.Trust.Domain] || s.Controls.Applied != s.Controls.Revision {
				t.Fatal("duplicate or lost command")
			}
		})
	}
}
