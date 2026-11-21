package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func TestSignedClaimBatchesKeepLegacyAuthorityAndBounds(t *testing.T) {
	f := fixtureBytes(t, 2<<20)
	target := f.server(t, "webdav", 0, nil)
	rawPlan := f.plan(t, target, 1, 10000)
	p, err := Verify(rawPlan, f.authority)
	must(t, err)
	j := &Journal{plan: p, planID: storage.Hash(rawPlan), worker: f.workers[0].ID}
	tasks, err := p.Tasks()
	must(t, err)
	if len(tasks) < maxClaimBatchMembers+1 {
		t.Fatal("bound control needs33 distinct legitimate members")
	}
	end := time.UnixMilli(p.StartMillis + p.SlotMillis)
	members := make([]Claim, maxClaimBatchMembers+1)
	for i := range members {
		members[i], err = signedPartClaim(j, tasks[i].Part, 0, end, f.keys[0])
		must(t, err)
	}
	legacy, err := json.Marshal(members[0])
	must(t, err)
	must(t, VerifyClaim(legacy, p, j.planID))
	makeBatch := func(count int) claimBatch {
		return claimBatch{Format: claimBatchFormat, Plan: j.planID, Worker: j.worker, Round: 0, ExpiresMillis: end.UnixMilli(), Claims: append([]Claim(nil), members[:count]...)}
	}
	seal := func(batch claimBatch) []byte {
		batch.Signature = nil
		unsigned, err := json.Marshal(batch)
		must(t, err)
		batch.Signature = ed25519.Sign(f.keys[0], append([]byte(claimBatchFormat+"\x00"), unsigned...))
		raw, err := json.Marshal(batch)
		must(t, err)
		return raw
	}
	for _, count := range []int{1, maxClaimBatchMembers} {
		must(t, VerifyClaim(seal(makeBatch(count)), p, j.planID))
	}
	valid := seal(makeBatch(2))
	reject := func(t *testing.T, raw []byte, plan Plan, id string) {
		t.Helper()
		if VerifyClaim(raw, plan, id) == nil {
			t.Fatal("invalid batch widened single-claim authority")
		}
	}
	for name, mutate := range map[string]func(*claimBatch){
		"empty":               func(b *claimBatch) { b.Claims = nil },
		"33-legitimate-parts": func(b *claimBatch) { b.Claims = append([]Claim(nil), members...) },
		"duplicate-member":    func(b *claimBatch) { b.Claims[1] = b.Claims[0] },
		"member-signature":    func(b *claimBatch) { b.Claims[0].Signature = make([]byte, ed25519.SignatureSize) },
		"mixed-plan":          func(b *claimBatch) { b.Claims[1].Plan = storage.Hash([]byte("different signed plan")) },
		"mixed-worker":        func(b *claimBatch) { b.Claims[1].Worker = f.workers[1].ID },
		"mixed-expiry":        func(b *claimBatch) { b.Claims[1].ExpiresMillis++ },
		"container-expiry":    func(b *claimBatch) { b.ExpiresMillis++ },
		"container-worker":    func(b *claimBatch) { b.Worker = f.workers[1].ID },
		"mixed-valid-round": func(b *claimBatch) {
			var e error
			b.Claims[1], e = signedPartClaim(j, tasks[1].Part, 1, end.Add(time.Duration(p.SlotMillis)*time.Millisecond), f.keys[0])
			must(t, e)
			raw, e := json.Marshal(b.Claims[1])
			must(t, e)
			must(t, VerifyClaim(raw, p, j.planID))
		},
	} {
		t.Run(name, func(t *testing.T) {
			batch := makeBatch(2)
			mutate(&batch)
			// A valid root signature must never excuse invalid member authority.
			reject(t, seal(batch), p, j.planID)
		})
	}
	t.Run("root-signature", func(t *testing.T) {
		var batch claimBatch
		must(t, json.Unmarshal(valid, &batch))
		batch.Signature = make([]byte, ed25519.SignatureSize)
		raw, err := json.Marshal(batch)
		must(t, err)
		reject(t, raw, p, j.planID)
	})
	for _, name := range []string{"truncate", "reorder", "splice"} {
		t.Run(name, func(t *testing.T) {
			var batch claimBatch
			must(t, json.Unmarshal(valid, &batch))
			switch name {
			case "truncate":
				batch.Claims = batch.Claims[:1]
			case "reorder":
				batch.Claims[0], batch.Claims[1] = batch.Claims[1], batch.Claims[0]
			case "splice":
				batch.Claims[1] = members[2]
			}
			raw, err := json.Marshal(batch)
			must(t, err)
			reject(t, raw, p, j.planID)
		})
	}
	for name, raw := range map[string][]byte{
		"unknown-field":   append(append([]byte(nil), valid[:len(valid)-1]...), []byte(",\"unknown\":true}")...),
		"duplicate-field": bytes.Replace(valid, []byte(`"round":0`), []byte(`"round":0,"round":0`), 1),
		"whitespace":      append([]byte(" "), valid...),
		"trailing":        append(append([]byte(nil), valid...), []byte(" {}")...),
		"oversize":        bytes.Repeat([]byte(" "), maxClaimBatchBytes+1),
	} {
		t.Run(name, func(t *testing.T) { reject(t, raw, p, j.planID) })
	}
	t.Run("different-plan-selection", func(t *testing.T) { reject(t, valid, p, storage.Hash([]byte("another plan"))) })
	t.Run("separate-missing-repair", func(t *testing.T) {
		repair := p
		repair.MissingRepair = &MissingRepair{}
		reject(t, valid, repair, j.planID)
	})
}

func TestPreparedPartRetryRechecksGuardAndCancelsQuotaReservation(t *testing.T) {
	f := fixtureBytes(t, 4096)
	target := f.server(t, "webdav", 0, nil)
	raw := f.plan(t, target, 1, 10000)
	dir := filepath.Join(f.base, "prepared-journal")
	must(t, os.Mkdir(dir, 0700))
	j, err := Open(dir, raw, f.workers[0].ID, f.authority, true)
	must(t, err)
	defer j.Close()
	tasks, err := j.plan.Tasks()
	must(t, err)
	ctx := t.Context()
	part := tasks[0].Part.ID
	must(t, j.beginPart(ctx, part, 0))
	before, err := j.Status(ctx)
	must(t, err)
	j.Guard = func(context.Context) error { return ErrDenied }
	if !errors.Is(j.checkPreparedPart(ctx, part, 1), ErrDenied) {
		t.Fatal("prepared retry bypassed its live guard")
	}
	j.Guard = nil
	j.Admit = func(string, int) (func(bool) error, error) { return nil, storage.ErrDenied }
	if !errors.Is(j.checkPreparedPart(ctx, part, 1), storage.ErrDenied) {
		t.Fatal("prepared retry bypassed quota admission")
	}
	released := false
	j.Admit = func(name string, size int) (func(bool) error, error) {
		if name != "state.json" || size < 1 {
			t.Fatal("wrong pending metadata admission")
		}
		return func(committed bool) error {
			if committed {
				t.Fatal("readiness check committed an unwritten file")
			}
			released = true
			return nil
		}, nil
	}
	must(t, j.checkPreparedPart(ctx, part, 1))
	after, err := j.Status(ctx)
	must(t, err)
	if !released || before.Revision != after.Revision || before.Parts[part] != after.Parts[part] {
		t.Fatal("retry changed its durable preparation instead of rechecking admission")
	}
}

func TestClaimBatchCacheRequiresActualReadbackAndCurrentLease(t *testing.T) {
	f := fixtureBytes(t, 2<<20)
	target := f.server(t, "webdav", 0, nil)
	raw := f.plan(t, target, 1, 10000)
	dir := filepath.Join(f.base, "batch-journal")
	must(t, os.Mkdir(dir, 0700))
	j, err := Open(dir, raw, f.workers[0].ID, f.authority, true)
	must(t, err)
	defer j.Close()
	backend := f.backend(t, target, 0)
	defer backend.Close()
	ctx := t.Context()
	must(t, sleep(ctx, max(time.Until(time.UnixMilli(j.plan.StartMillis)), 0)))
	tasks, err := j.plan.Tasks()
	must(t, err)
	if len(tasks) <= maxClaimBatchMembers {
		t.Fatal("cache control needs more than one bounded batch")
	}
	round, end := j.plan.round(time.Now())
	var cache partClaimCache
	target.Options.Before = func(w http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
		if r.Method == http.MethodGet && strings.HasPrefix(key, "claim-") {
			_, _ = w.Write([]byte("wrong claim readback"))
			return true
		}
		return false
	}
	err = cache.ensure(ctx, backend, j, tasks, State{}, tasks[0].Part, round, end, f.keys[0])
	if !errors.Is(err, storage.ErrConflict) || len(cache.ready) != 0 {
		t.Fatal("false readback populated the claim cache", err)
	}
	target.Options.Before = nil
	must(t, cache.ensure(ctx, backend, j, tasks, State{}, tasks[0].Part, round, end, f.keys[0]))
	requests := target.Snapshot().Requests
	must(t, cache.ensure(ctx, backend, j, tasks, State{}, tasks[1].Part, round, end, f.keys[0]))
	if target.Snapshot().Requests != requests || len(cache.ready) != maxClaimBatchMembers {
		t.Fatal("one verified batch was not reused within its exact lease")
	}
	must(t, cache.ensure(ctx, backend, j, tasks, State{}, tasks[maxClaimBatchMembers].Part, round, end, f.keys[0]))
	claims := 0
	for key, count := range target.Snapshot().Writes {
		if !strings.HasPrefix(key, "claim-") {
			continue
		}
		claims++
		if count != 1 {
			t.Fatal("immutable claim body was rewritten")
		}
		body, err := backend.Get(ctx, key)
		must(t, err)
		must(t, VerifyClaim(body, j.plan, j.planID))
	}
	if claims != 2 || len(target.Snapshot().Events) != 0 {
		t.Fatal("batch count or no-payload control differs", claims)
	}
	requests = target.Snapshot().Requests
	for name, attempt := range map[string]func() error{
		"future-round": func() error {
			return cache.ensure(ctx, backend, j, tasks, State{}, tasks[0].Part, round+1, end.Add(time.Duration(j.plan.SlotMillis)*time.Millisecond), f.keys[0])
		},
		"extended-expiry": func() error {
			return cache.ensure(ctx, backend, j, tasks, State{}, tasks[0].Part, round, end.Add(time.Second), f.keys[0])
		},
		"missing-repair": func() error {
			repair := *j
			repair.plan.MissingRepair = &MissingRepair{}
			return cache.ensure(ctx, backend, &repair, tasks, State{}, tasks[0].Part, round, end, f.keys[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			if attempt() == nil || target.Snapshot().Requests != requests {
				t.Fatal("invalid scope or lease reached the target")
			}
		})
	}
}
