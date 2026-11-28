package peer

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
)

func TestHTTPSRetainedHistoryRequiresGrantAndPreservesNewerHead(t *testing.T) {
	for _, mode := range []string{"push", "pull"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			first, v1 := f.seal(t, 1, "")
			changed := bytes.Repeat([]byte("updated"), 32768)
			must(t, os.WriteFile(f.input, changed, 0640))
			second, v2 := f.seal(t, 2, first)
			from, to := f.b, f.a
			if mode == "pull" {
				from, to = f.a, f.b
			}
			incoming := f.policy(to, from)
			grant := incoming.Peers[from.id]
			grant.History = true
			incoming.Peers[from.id] = grant
			s := f.endpoint(t, to, incoming, nil)
			client := f.client(t, from, to, s.URL, f.policy(from, to))
			transfer := func(op, id string) error {
				var e error
				if mode == "push" {
					_, e = client.Push(testContext, op, id, f.b.replica)
				} else {
					_, e = client.Pull(testContext, op, id, f.a.replica)
				}
				return e
			}
			must(t, transfer(generation.Hash([]byte("latest op")), second))
			op := generation.Hash([]byte("historical op"))
			if e := transfer(op, first); e == nil {
				t.Fatal("history admitted without sender/receiver local grant")
			}
			grant = client.policy.Peers[to.id]
			grant.History = true
			client.policy.Peers[to.id] = grant
			must(t, transfer(op, first))
			status, e := f.a.replica.Status(testContext)
			must(t, e)
			if status.HighestSequence != 2 || status.LatestComplete != second || len(status.Complete) != 2 {
				t.Fatal("history changed head", status)
			}
			restore(t, f, f.a, first, v1, f.old)
			restore(t, f, f.a, second, v2, changed)
		})
	}
}

func TestHistoryHeaderCannotExpandReceiverAuthority(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	s := f.endpoint(t, f.a, f.policy(f.a, f.b), nil)
	p := f.policy(f.b, f.a)
	grant := p.Peers[f.a.id]
	grant.History = true
	p.Peers[f.a.id] = grant
	client := f.client(t, f.b, f.a, s.URL, p)
	if _, e := client.Push(testContext, generation.Hash([]byte("unauthorized history")), id, f.b.replica); !errors.Is(e, ErrDenied) {
		t.Fatal("unilateral history grant accepted", e)
	}
	status, e := f.a.replica.Status(testContext)
	must(t, e)
	if len(status.Receiving) != 0 || len(status.Complete) != 0 {
		t.Fatal("unauthorized history wrote state", status)
	}
}

func TestRetiredHistoricalPullReleasesOnlyItsBoundLease(t *testing.T) {
	f := newFixture(t)
	old, _ := f.seal(t, 1, "")
	changed := bytes.Repeat([]byte("new head"), 32768)
	must(t, os.WriteFile(f.input, changed, 0640))
	head, version := f.seal(t, 2, old)
	op := generation.Hash([]byte("known retired pull"))
	var releaseUnavailable, induceLocalUncertainty, localCommitUncertain atomic.Bool
	var requests, objectReads atomic.Int64
	server := f.endpoint(t, f.b, f.policy(f.b, f.a), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Outpost-Operation") == op {
				requests.Add(1)
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/objects/") {
					objectReads.Add(1)
				}
				if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/lease") {
					if releaseUnavailable.Load() {
						http.Error(w, "fixture lease release unavailable", http.StatusServiceUnavailable)
						return
					}
					if induceLocalUncertainty.CompareAndSwap(true, false) {
						localCommitUncertain.Store(true)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	p := f.policy(f.a, f.b)
	grant := p.Peers[f.b.id]
	grant.History = true
	p.Peers[f.b.id] = grant
	client := f.client(t, f.a, f.b, server.URL, p)
	for _, id := range []string{old, head} {
		_, err := client.Pull(testContext, generation.Hash([]byte("initial pull/"+id)), id, f.a.replica)
		must(t, err)
	}
	state, err := f.a.replica.Status(testContext)
	must(t, err)
	permit, err := generation.SignPermit(generation.Permit{
		Format: generation.Format, Domain: f.trust.Domain, Repository: f.trust.Repository, Epoch: f.trust.Epoch,
		Revision: state.Revision, Operation: generation.Hash([]byte("retire old on recipient")), Retire: []string{old},
	}, f.maintenance)
	must(t, err)
	_, err = f.a.replica.Maintain(testContext, permit)
	must(t, err)
	before, err := f.a.replica.Status(testContext)
	must(t, err)
	otherPin := generation.Hash([]byte("unrelated holder pin"))
	must(t, f.b.replica.Pin(testContext, otherPin, old, "generation"))
	binding := Binding{Operation: op, Kind: "serve", Domain: f.trust.Domain, Repository: f.trust.Repository, Epoch: f.trust.Epoch,
		Generation: old, Peer: f.a.id, Executor: f.b.id, Expected: old}
	ownPin := leasePin(binding)
	assertPins := func(wantOwn bool) {
		t.Helper()
		origin, err := f.b.replica.Status(testContext)
		must(t, err)
		other, hasOther := origin.Pins[otherPin]
		own, hasOwn := origin.Pins[ownPin]
		wantPins := 1
		if wantOwn {
			wantPins++
		}
		if !hasOther || other.Generation != old || hasOwn != wantOwn ||
			hasOwn && own.Generation != old || len(origin.Pins) != wantPins {
			t.Fatalf("unexpected holder pins: %+v", origin.Pins)
		}
	}

	releaseUnavailable.Store(true)
	result, err := client.Pull(testContext, op, old, f.a.replica)
	if !errors.Is(err, generation.ErrProtected) || !errors.Is(err, ErrUnavailable) || IsConflict(err) || !result.CleanupPending {
		t.Fatalf("uncertain release did not preserve retry and retirement evidence: %+v %v", result, err)
	}
	assertPins(true)
	localJob, err := f.a.journal.Read(testContext, client.binding(op, old, "pull"))
	must(t, err)
	if localJob.Phase != "RETRYABLE" || localJob.LastReceipt != nil {
		t.Fatal("uncertain retirement became complete", localJob)
	}

	releaseUnavailable.Store(false)
	induceLocalUncertainty.Store(true)
	lostLocalResult := errors.New("fixture lost the result of the durable local release marker")
	f.a.journal.Admit = func(string, int) (func(bool) error, error) {
		return func(written bool) error {
			if written && localCommitUncertain.CompareAndSwap(true, false) {
				return lostLocalResult
			}
			return nil
		}, nil
	}
	result, err = client.Pull(testContext, op, old, f.a.replica)
	if !errors.Is(err, generation.ErrProtected) || !errors.Is(err, lostLocalResult) || IsConflict(err) || result.CleanupPending {
		t.Fatalf("uncertain local commit did not retain the original retirement and confirmed remote release: %+v %v", result, err)
	}
	assertPins(false)
	remoteJob, err := f.b.journal.Read(testContext, binding)
	must(t, err)
	if remoteJob.Phase != "RELEASED" {
		t.Fatal("holder did not durably release the matching lease", remoteJob)
	}
	localJob, err = f.a.journal.Read(testContext, client.binding(op, old, "pull"))
	must(t, err)
	if localJob.Phase != "RELEASED" || localJob.LastReceipt != nil {
		t.Fatal("local release was overwritten or reported as a complete transfer", localJob)
	}
	client.Close()
	must(t, f.a.journal.Close())
	f.a.journal, err = OpenJournal(filepath.Join(f.a.dir, "journal"), f.a.id, f.trust, false)
	must(t, err)
	client = f.client(t, f.a, f.b, server.URL, p)
	callCount := requests.Load()
	result, err = client.Pull(testContext, op, old, f.a.replica)
	if !errors.Is(err, generation.ErrProtected) || !IsConflict(err) || result.CleanupPending || requests.Load() != callCount {
		t.Fatalf("replay reacquired the confirmed released lease: %+v %v", result, err)
	}
	assertPins(false)
	after, err := f.a.replica.Status(testContext)
	must(t, err)
	if after.Revision != before.Revision || after.HighestSequence != 2 || after.LatestComplete != head ||
		len(after.Receiving) != 0 || len(after.Complete) != 1 || objectReads.Load() != 0 {
		t.Fatalf("retired pull altered the saved head or read a payload: %+v", after)
	}
	restore(t, f, f.a, head, version, changed)
}
