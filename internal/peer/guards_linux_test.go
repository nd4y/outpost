package peer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

func TestPrematurePublicationAndInvalidObject(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), nil)
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	op := generation.Hash([]byte("publication boundary"))
	raw, e := f.b.replica.Catalog(testContext, id)
	must(t, e)
	_, e = client.request(testContext, op, id, "push", http.MethodPut, "catalog", raw, 1024, nil)
	must(t, e)
	if e = f.a.replica.VerifyComplete(testContext, id); !errors.Is(e, generation.ErrIncomplete) {
		t.Fatal("pending status published generation", e)
	}
	if _, e = client.request(testContext, op, id, "push", http.MethodPost, "complete", nil, 4096, nil); e == nil {
		t.Fatal("premature publication")
	}
	refs, e := generation.Dependencies(raw, f.trust)
	must(t, e)
	data, e := f.b.replica.ReadObject(testContext, id, refs[0])
	must(t, e)
	data[0] ^= 1
	if _, e = client.request(testContext, op, id, "push", http.MethodPut, "objects/"+refs[0].ID, data, 1024, nil); e == nil {
		t.Fatal("wrong checksum accepted")
	}
	if _, e = client.request(testContext, op, id, "push", http.MethodPut, "objects/"+refs[0].ID, make([]byte, generation.MaxObject+1), 1024, nil); e == nil {
		t.Fatal("oversize object accepted")
	}
	state, e := f.a.replica.Status(testContext)
	must(t, e)
	if state.LatestComplete != "" {
		t.Fatal("invalid reception became latest")
	}
	_, e = client.Push(testContext, op, id, f.b.replica)
	must(t, e)
	must(t, f.a.replica.VerifyComplete(testContext, id))
	job, e := f.a.journal.Read(testContext, Binding{op, "receive", f.trust.Domain, f.trust.Repository, f.trust.Epoch, id, f.b.id, f.a.id, id})
	must(t, e)
	if job.Phase != "COMPLETE" || job.LastReceipt == nil || job.LastReceipt.Verification != "target-full-read" {
		t.Fatal("missing persisted target evidence", job)
	}
}

func TestTLSClientCertificateAndOperationGrants(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	policy := f.policy(f.a, f.b)
	grant := policy.Peers[f.b.id]
	grant.Push = false
	policy.Peers[f.b.id] = grant
	server := f.endpoint(t, f.a, policy, nil)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.roots}}
	unauthenticated := &http.Client{Transport: transport, Timeout: time.Second}
	defer transport.CloseIdleConnections()
	if res, e := unauthenticated.Get(server.URL); e == nil {
		res.Body.Close()
		t.Fatal("client without a certificate reached handler")
	}
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	if _, e := client.Push(testContext, generation.Hash([]byte("read-only grant")), id, f.b.replica); !errors.Is(e, ErrDenied) {
		t.Fatal("pull grant allowed push", e)
	}
	// Expiry is enforced by the receiver, independent of a still-valid sender policy.
	expired := f.policy(f.a, f.b)
	grant = expired.Peers[f.b.id]
	grant.ExpiresUnix = time.Now().Unix() - 1
	expired.Peers[f.b.id] = grant
	server = f.endpoint(t, f.a, expired, nil)
	client = f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	if _, e := client.Push(testContext, generation.Hash([]byte("server expiry")), id, f.b.replica); !errors.Is(e, ErrDenied) {
		t.Fatal("receiver accepted expired grant", e)
	}
	status, e := f.a.replica.Status(testContext)
	must(t, e)
	if status.LatestComplete != "" {
		t.Fatal("denied request mutated completeness")
	}
}

func TestRetryBudgetAndCancellation(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	var attempts atomic.Int64
	var slow atomic.Bool
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			if slow.Load() {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(time.Second):
				}
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		})
	})
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	op := generation.Hash([]byte("retry budget"))
	_, e := client.Push(testContext, op, id, f.b.replica)
	if !errors.Is(e, ErrUnavailable) || attempts.Load() != int64(testLimits.Attempts) {
		t.Fatal("unbounded or missing retry", e, attempts.Load())
	}
	job, e := f.b.journal.Read(testContext, client.binding(op, id, "push"))
	must(t, e)
	if job.Phase != "RETRYABLE" || job.LastReceipt != nil {
		t.Fatal(job)
	}
	attempts.Store(0)
	slow.Store(true)
	ctx, cancel := context.WithTimeout(testContext, 50*time.Millisecond)
	defer cancel()
	_, e = client.Push(ctx, generation.Hash([]byte("cancel")), id, f.b.replica)
	if e == nil || attempts.Load() > 1 {
		t.Fatal("cancellation did not bound attempts", e, attempts.Load())
	}
}

func TestJournalBoundsAndInterruptedSave(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	j := f.b.journal
	b := Binding{generation.Hash([]byte("journal limits")), "push", f.trust.Domain, f.trust.Repository, f.trust.Epoch, id, f.a.id, f.b.id, id}
	_, e := j.Begin(testContext, b)
	must(t, e)
	s, e := j.load()
	must(t, e)
	job := s.Jobs[jobKey(b)]
	job.Attempt = ^uint64(0)
	s.Jobs[jobKey(b)] = job
	must(t, j.save(s))
	before, e := regularRead(j.root, "jobs.json", maxJournal)
	must(t, e)
	if _, e = j.Begin(testContext, b); !errors.Is(e, ErrUnavailable) {
		t.Fatal("attempt overflow", e)
	}
	after, e := regularRead(j.root, "jobs.json", maxJournal)
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("overflow rewrote journal")
	}
	// A crash before rename leaves an uncommitted scratch file; only jobs.json is authoritative.
	fp, e := j.root.OpenFile(".pending-interrupted", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, e)
	_, e = fp.Write([]byte("incomplete"))
	must(t, e)
	must(t, fp.Close())
	must(t, j.Close())
	f.b.journal, e = OpenJournal(f.b.dir+"/journal", f.b.id, f.trust, false)
	must(t, e)
	read, e := f.b.journal.Read(testContext, b)
	must(t, e)
	if read.Attempt != ^uint64(0) {
		t.Fatal("loaded scratch instead of committed journal")
	}
}
