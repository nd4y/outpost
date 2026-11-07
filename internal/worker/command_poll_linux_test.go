package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerCommandRealManagementLostAckAndPersistedPollDeadline(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	ctx := context.Background()
	cert, target := f.ca.node(t)
	signer := cert.PrivateKey.(ed25519.PrivateKey)
	tenant := storage.Hash([]byte("command-tenant"))
	domain := f.domain.Trust.Domain
	principal := management.Principal{Actor: storage.Hash([]byte("operator")), Roles: []string{"owner"}, Scopes: []management.Scope{{Tenant: tenant, Domain: domain}}}
	registry, e := management.Open(management.Options{Directory: filepath.Join(f.base, "management"), Owner: w.owner, Signer: signer, Initialize: true})
	must(t, e)
	defer registry.Close()
	enrollment := management.Enrollment{Format: management.EnrollmentFormat, Tenant: tenant, Node: w.node, PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), Class: "trusted", Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Domains: []management.DomainAdmission{{Domain: domain, Repository: f.domain.Trust.Repository, Epoch: 1}}}
	enrolled, e := management.SignEnrollment(enrollment, f.owner)
	must(t, e)
	_, e = registry.ApplyEnrollment(ctx, principal, storage.Hash([]byte("enroll")), "INITIAL_ENROLLMENT", enrolled, 0)
	must(t, e)
	c := f.cfg
	c.Node = w.node
	c.Nodes = []policy.Node{f.cfg.Nodes[0]}
	d := f.domain
	d.Placement.Holders = []string{w.node}
	d.Placement.Edges = nil
	c.Domains = []control.Domain{d}
	authority, e := command.SignAuthority(command.Authority{Format: command.AuthorityFormat, Service: signer.Public().(ed25519.PublicKey), Node: w.node, Tenant: tenant, Domain: domain, Repository: d.Trust.Repository, WriterEpoch: 1, AuthorityEpoch: 1, Kinds: []string{"pause", "resume"}, NotBefore: c.NotBefore, ExpiresUnix: c.ExpiresUnix}, f.owner)
	must(t, e)
	c.Commands = []json.RawMessage{authority}
	config, e := control.Sign(c, f.owner)
	must(t, e)
	mutation := management.SignedMutation{Operation: storage.Hash([]byte("config")), Reason: "POLICY_CHANGE", Document: config}
	preview, e := registry.PreviewConfiguration(ctx, principal, tenant, w.node, mutation)
	must(t, e)
	mutation.PreviewDigest = preview.CandidateDigest
	_, e = registry.ApplyConfiguration(ctx, principal, tenant, w.node, mutation)
	must(t, e)
	must(t, w.Accept(ctx, config))
	req := command.Request{Operation: storage.Hash([]byte("pause")), Reason: "OPERATOR_REQUEST", Tenant: tenant, Domain: domain, Kind: "pause", ExpectedRevision: 1, Authority: authority, ExpiresUnix: time.Now().Unix() + 120}
	_, e = registry.AdmitCommand(ctx, principal, tenant, w.node, req)
	must(t, e)
	handler, e := management.Handler(registry, management.HTTPOptions{Principals: []management.Principal{principal}, Origin: "https://management.invalid", Concurrency: 2, Timeout: time.Second, ReportMaxAge: time.Minute})
	must(t, e)
	var ackBodies [][]byte
	var mu sync.Mutex
	var calls atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodPut {
			raw, e := io.ReadAll(io.LimitReader(r.Body, 128<<10))
			if e != nil {
				http.Error(out, "unavailable", 503)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			mu.Lock()
			ackBodies = append(ackBodies, append([]byte(nil), raw...))
			first := len(ackBodies) == 1
			mu.Unlock()
			if first {
				http.Error(out, "unavailable", 503)
				return
			}
		}
		handler.ServeHTTP(out, r)
	}))
	server.TLS, e = control.ServerTLS(cert, w.roots, target)
	must(t, e)
	server.StartTLS()
	defer server.Close()
	client, e := management.NewReportClient(server.URL, target, w.node, w.cert, w.roots, time.Second)
	must(t, e)
	defer client.Close()
	result, e := w.CommandOnce(ctx, client, enrolled)
	if e == nil || result.State != "ACK_PENDING" {
		t.Fatal("lost acknowledgement hidden", result, e)
	}
	first, e := w.Status(ctx)
	must(t, e)
	var saved []byte
	for _, op := range first.Controls.Operations {
		saved = op.Ack
	}
	if len(saved) == 0 || !first.Controls.Domains[domain] {
		t.Fatal("worker result not durable")
	}
	other, e := Open(Options{Directory: w.dir, Node: w.node, Owner: w.owner, Certificate: w.cert, Roots: w.roots})
	must(t, e)
	defer other.Close()
	result, e = other.CommandOnce(ctx, client, enrolled)
	must(t, e)
	if result.State != "COMPLETE" {
		t.Fatal(result)
	}
	mu.Lock()
	same := len(ackBodies) == 2 && bytes.Equal(ackBodies[0], ackBodies[1])
	mu.Unlock()
	if !same {
		t.Fatal("retry changed acknowledgement")
	}
	receipt, e := registry.Operation(ctx, principal, tenant, req.Operation)
	must(t, e)
	if receipt.State != "COMPLETE" {
		t.Fatal(receipt)
	}
	profile := CommandProfile{Format: CommandProfileFormat, Endpoint: server.URL, Identity: target, EnrollmentFile: filepath.Join(f.base, "enrollment.json"), PollSeconds: 5, RetrySeconds: 5, AttemptSeconds: 2}
	bounded, cancel := context.WithTimeout(ctx, 180*time.Millisecond)
	e = other.RunCommands(bounded, profile, enrolled, client)
	cancel()
	must(t, e)
	state, e := other.Status(ctx)
	must(t, e)
	if state.Controls.Delivery == nil || state.Controls.Delivery.Phase != "IDLE" {
		t.Fatal("poll state absent")
	}
	deadline := state.Controls.Delivery.NextUnix
	before := calls.Load()
	bounded, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
	e = w.RunCommands(bounded, profile, enrolled, client)
	cancel()
	must(t, e)
	state, e = w.Status(ctx)
	must(t, e)
	if calls.Load() != before || state.Controls.Delivery.NextUnix != deadline {
		t.Fatal("restart bypassed durable poll deadline")
	}
}
