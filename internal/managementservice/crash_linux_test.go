package managementservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func TestManagementServiceCrashChild(t *testing.T) {
	path := os.Getenv("OUTPOST_MANAGEMENT_SERVICE_KILL")
	if path == "" {
		t.Skip("child only")
	}
	p, e := Load(path)
	must(t, e)
	s, e := Open(context.Background(), p, false)
	must(t, e)
	defer s.Close()
	point := os.Getenv("OUTPOST_MANAGEMENT_SERVICE_POINT")
	s.registry.Fault = func(name string) error {
		if name == point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	must(t, s.Run(context.Background()))
}
func TestManagementServiceSIGKILLRestartCompletesOriginalHTTPSIntent(t *testing.T) {
	for _, point := range []string{"management-enrollment-intent-durable", "management-enrollment-result-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			s, e := Open(ctx, f.p, true)
			must(t, e)
			must(t, s.Close())
			profile := filepath.Join(f.root, "profile.json")
			raw, e := json.Marshal(f.p)
			must(t, e)
			must(t, os.WriteFile(profile, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestManagementServiceCrashChild$")
			child.Env = append(os.Environ(), "OUTPOST_MANAGEMENT_SERVICE_KILL="+profile, "OUTPOST_MANAGEMENT_SERVICE_POINT="+point)
			var log bytes.Buffer
			child.Stdout = &log
			child.Stderr = &log
			must(t, child.Start())
			// Always reap the owned child, including failed readiness paths.
			waited := false
			defer func() {
				if !waited {
					_ = child.Process.Kill()
					_ = child.Wait()
				}
			}()
			ready := false
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				response, e := f.client.Get(f.p.Origin + "/api/v1/session")
				if e == nil {
					response.Body.Close()
					ready = response.StatusCode == 200
					if ready {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Fatal("child listener not ready")
			}
			pub, _, e := ed25519.GenerateKey(rand.Reader)
			must(t, e)
			now := time.Now().Unix()
			enrollment := management.Enrollment{Format: management.EnrollmentFormat, Tenant: id("tenant"), Node: command.Identity(pub), PublicKey: pub, Class: "trusted", Revision: 1, NotBefore: now - 30, ExpiresUnix: now + 3600, Domains: []management.DomainAdmission{{Domain: id("domain"), Repository: id("repo"), Epoch: 1}}}
			document, e := management.SignEnrollment(enrollment, f.owner)
			must(t, e)
			input := management.SignedMutation{Operation: id("crash-enroll"), Reason: "INITIAL_ENROLLMENT", Document: document}
			body, e := json.Marshal(input)
			must(t, e)
			request, e := http.NewRequest("PUT", f.p.Origin+"/api/v1/tenants/"+id("tenant")+"/nodes/"+enrollment.Node+"/enrollment", bytes.NewReader(body))
			must(t, e)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Outpost-Request", "1")
			request.Header.Set("Origin", f.p.Origin)
			if response, e := f.client.Do(request); e == nil {
				response.Body.Close()
				t.Fatal("killed request acknowledged")
			}
			e = child.Wait()
			waited = true
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("child did not crash: %v %s", e, log.String())
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("wrong crash signal")
			}
			s, e = Open(ctx, f.p, false)
			must(t, e)
			defer s.Close()
			stopRun, done := start(t, s, f.client)
			defer stop(t, stopRun, done)
			deadline = time.Now().Add(4 * time.Second)
			var receipt management.Receipt
			for time.Now().Before(deadline) {
				response, e := f.client.Get(f.p.Origin + "/api/v1/tenants/" + id("tenant") + "/operations/" + input.Operation)
				must(t, e)
				raw, e := io.ReadAll(response.Body)
				response.Body.Close()
				must(t, e)
				must(t, json.Unmarshal(raw, &receipt))
				if receipt.State == "COMPLETE" {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if receipt.State != "COMPLETE" || receipt.ResultDigest != storage.Hash(document) {
				t.Fatal("restart did not reconcile exact original intent", receipt)
			}
			original := receipt
			time.Sleep(20 * time.Millisecond)
			again, e := s.registry.Operation(ctx, f.p.Principals[0], id("tenant"), input.Operation)
			must(t, e)
			if again != original {
				t.Fatal("historical receipt refreshed")
			}
		})
	}
}

func TestManagementServiceSocketLimitRejectsBeforeTLSAndReleasesOnce(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	must(t, e)
	defer raw.Close()
	listener := &limitedListener{Listener: raw, slots: make(chan struct{}, 2)}
	accepted := make(chan net.Conn, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			accepted <- c
		}
	}()
	defer func() {
		raw.Close()
		<-done
		close(accepted)
		for c := range accepted {
			c.Close()
		}
	}()
	dial := func() net.Conn {
		c, e := net.DialTimeout("tcp", raw.Addr().String(), time.Second)
		must(t, e)
		t.Cleanup(func() { c.Close() })
		return c
	}
	_ = dial()
	first := <-accepted
	defer first.Close()
	_ = dial()
	second := <-accepted
	defer second.Close()
	overflow := dial()
	must(t, overflow.SetReadDeadline(time.Now().Add(time.Second)))
	var b [1]byte
	if n, e := overflow.Read(b[:]); n != 0 || e != io.EOF {
		t.Fatalf("over-limit socket not immediately closed: %d %v", n, e)
	}
	must(t, first.Close())
	_ = first.Close()
	_ = dial()
	select {
	case next := <-accepted:
		next.Close()
	case <-time.After(time.Second):
		t.Fatal("released slot not reusable")
	}
	if len(listener.slots) != 1 {
		t.Fatal("double close released another connection")
	}
}
