package peer

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/generation"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func withRepair(p Policy) Policy {
	for id, g := range p.Peers {
		g.Repair = true
		p.Peers[id] = g
	}
	return p
}

func TestIntegrityRepairRejectsMalformedMissingBeforeSourceRead(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	raw, e := f.b.replica.Catalog(testContext, id)
	must(t, e)
	refs, e := generation.Dependencies(raw, f.trust)
	must(t, e)
	for _, missing := range [][]generation.Object{{{}}, {{ID: generation.Hash([]byte("unknown")), Bytes: 1}}, {refs[0], refs[0]}} {
		t.Run(generation.Hash(mustJSON(t, missing)), func(t *testing.T) {
			server := f.endpoint(t, f.a, withRepair(f.policy(f.a, f.b)), func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						t.Error("invalid missing response caused payload request")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(mustJSON(t, missing))
				})
			})
			client := f.client(t, f.b, f.a, server.URL, withRepair(f.policy(f.b, f.a)))
			binding := client.binding(generation.Hash([]byte("invalid missing")), id, "push")
			// A nil source proves validation runs before any source object access.
			if _, e := client.sendRepairMissing(testContext, binding, nil, refs, &atomic.Int64{}); !errors.Is(e, ErrProtocol) {
				t.Fatal("invalid response accepted", e)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, e := json.Marshal(value)
	must(t, e)
	return b
}

func TestIntegrityRepairPeerPushPullPreserveHistoryAndFenceOldIncarnation(t *testing.T) {
	for _, mode := range []string{"push", "pull"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			id, version := f.seal(t, 1, "")
			from, to, target := f.b, f.a, f.a
			if mode == "pull" {
				from, to, target = f.c, f.b, f.c
			}
			server := f.endpoint(t, to, withRepair(f.policy(to, from)), nil)
			client := f.client(t, from, to, server.URL, withRepair(f.policy(from, to)))
			op := generation.Hash([]byte("original " + mode))
			if mode == "push" {
				_, e := client.Push(testContext, op, id, from.replica)
				must(t, e)
			} else {
				_, e := client.Pull(testContext, op, id, target.replica)
				must(t, e)
			}
			original, e := client.journal.Read(testContext, client.binding(op, id, mode))
			must(t, e)
			before, _ := json.Marshal(original)
			raw, e := f.b.replica.Catalog(testContext, id)
			must(t, e)
			refs, e := generation.Dependencies(raw, f.trust)
			must(t, e)
			if len(refs) < 2 {
				t.Fatal("fixture needs two dependencies")
			}
			bad := map[string][]byte{}
			var changed int64
			for index, ref := range refs[:2] {
				name := filepath.Join(target.dir, "replica/objects", ref.ID)
				data, e := os.ReadFile(name)
				must(t, e)
				data[0] ^= 1
				if index == 1 {
					data = data[:len(data)-1]
				}
				bad[ref.ID] = data
				changed += int64(ref.Bytes)
				must(t, os.WriteFile(name, data, 0600))
			}
			if e = target.replica.Complete(testContext, id); !errors.Is(e, generation.ErrIncomplete) {
				t.Fatal("no detected corruption", e)
			}
			needs, e := target.replica.RepairNeeds(testContext)
			must(t, e)
			if len(needs) != 1 {
				t.Fatal("no repair incarnation", needs)
			}
			token := needs[0].Token
			repairOp := generation.Hash([]byte("repair " + mode + token))
			var result Result
			if mode == "push" {
				result, e = client.RepairPush(testContext, repairOp, id, token, f.b.replica)
			} else {
				result, e = client.RepairPull(testContext, repairOp, id, token, target.replica)
			}
			must(t, e)
			must(t, target.replica.VerifyComplete(testContext, id))
			if mode == "push" && result.Counters.ObjectBytesSubmitted != changed || mode == "pull" && result.Counters.ObjectBytesReceived != changed {
				t.Fatal("repair transfer did not send exactly damaged objects", result.Counters, changed)
			}
			journal, e := target.replica.Integrity(testContext)
			must(t, e)
			if len(journal.Repairs) != 2 || len(journal.Damage) != 0 {
				t.Fatal("incomplete quarantine", journal)
			}
			for caseID, receipt := range journal.Repairs {
				saved, e := os.ReadFile(filepath.Join(target.dir, "replica/quarantine/objects", caseID))
				must(t, e)
				if !bytes.Equal(saved, bad[receipt.Object.ID]) {
					t.Fatal("wire repair lost bad bytes")
				}
			}
			original, e = client.journal.Read(testContext, client.binding(op, id, mode))
			must(t, e)
			after, _ := json.Marshal(original)
			if !bytes.Equal(before, after) {
				t.Fatal("repair rewrote original transfer history")
			}
			restore(t, f, target, id, version, f.old)
			ref := refs[0]
			name := filepath.Join(target.dir, "replica/objects", ref.ID)
			must(t, os.WriteFile(name, bad[ref.ID], 0600))
			if e = target.replica.Complete(testContext, id); !errors.Is(e, generation.ErrIncomplete) {
				t.Fatal(e)
			}
			newer, e := target.replica.RepairNeeds(testContext)
			must(t, e)
			if len(newer) != 1 || newer[0].Token == token {
				t.Fatal("new damage reused old incarnation")
			}
			if mode == "push" {
				_, e = client.RepairPush(testContext, repairOp, id, token, f.b.replica)
			} else {
				_, e = client.RepairPull(testContext, repairOp, id, token, target.replica)
			}
			if !errors.Is(e, ErrConflict) && !errors.Is(e, generation.ErrConflict) {
				t.Fatal("old repair replay changed new damage", e)
			}
			preserved, e := os.ReadFile(name)
			must(t, e)
			if !bytes.Equal(preserved, bad[ref.ID]) {
				t.Fatal("stale repair replaced payload")
			}
		})
	}
}

func TestIntegrityRepairRequiresBothExplicitPeerGrants(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			f := newFixture(t)
			id, _ := f.seal(t, 1, "")
			normal := f.endpoint(t, f.a, f.policy(f.a, f.b), nil)
			client := f.client(t, f.b, f.a, normal.URL, f.policy(f.b, f.a))
			_, e := client.Push(testContext, generation.Hash([]byte("normal")), id, f.b.replica)
			must(t, e)
			raw, e := f.b.replica.Catalog(testContext, id)
			must(t, e)
			refs, e := generation.Dependencies(raw, f.trust)
			must(t, e)
			name := filepath.Join(f.a.dir, "replica/objects", refs[0].ID)
			bad, e := os.ReadFile(name)
			must(t, e)
			bad[0] ^= 1
			must(t, os.WriteFile(name, bad, 0600))
			if e = f.a.replica.Complete(testContext, id); !errors.Is(e, generation.ErrIncomplete) {
				t.Fatal(e)
			}
			needs, e := f.a.replica.RepairNeeds(testContext)
			must(t, e)
			local, remote := withRepair(f.policy(f.b, f.a)), withRepair(f.policy(f.a, f.b))
			if side == "client" {
				local = f.policy(f.b, f.a)
			} else {
				remote = f.policy(f.a, f.b)
			}
			endpoint := f.endpoint(t, f.a, remote, nil)
			repair := f.client(t, f.b, f.a, endpoint.URL, local)
			_, e = repair.RepairPush(testContext, generation.Hash([]byte("unauthorized repair")), id, needs[0].Token, f.b.replica)
			if !errors.Is(e, ErrDenied) {
				t.Fatal("ordinary edge granted repair", e)
			}
			preserved, e := os.ReadFile(name)
			must(t, e)
			if !bytes.Equal(preserved, bad) {
				t.Fatal("denied repair changed bytes")
			}
		})
	}
}
