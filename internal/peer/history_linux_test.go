package peer

import (
	"bytes"
	"errors"
	"os"
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
