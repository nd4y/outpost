package upload

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const claimBatchFormat = "outpost-external-claims-1"
const maxClaimBatchMembers = 32
const maxClaimBatchBytes = 32 << 10

// The extra signature binds the exact list and order. Each member remains an
// unchanged, independently signed claim with its original scope and expiry.
type claimBatch struct {
	Format        string  `json:"format"`
	Plan          string  `json:"plan"`
	Worker        string  `json:"worker"`
	Round         int64   `json:"round"`
	ExpiresMillis int64   `json:"expiresMillis"`
	Claims        []Claim `json:"claims"`
	Signature     []byte  `json:"signature,omitempty"`
}

func verifyClaimBatch(raw []byte, p Plan, planID string) error {
	var batch claimBatch
	if p.MissingRepair != nil || storage.Decode(raw, &batch, maxClaimBatchBytes) != nil || batch.Format != claimBatchFormat || batch.Plan != planID || len(batch.Claims) < 1 || len(batch.Claims) > maxClaimBatchMembers {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, member := range batch.Claims {
		if member.Plan != batch.Plan || member.Worker != batch.Worker || member.Round != batch.Round || member.ExpiresMillis != batch.ExpiresMillis || seen[member.Object] {
			return ErrDenied
		}
		seen[member.Object] = true
		encoded, err := json.Marshal(member)
		if err != nil || verifyPartClaim(encoded, p, planID) != nil {
			return ErrDenied
		}
	}
	worker, ok := p.worker(batch.Worker)
	if !ok {
		return ErrDenied
	}
	signature := batch.Signature
	batch.Signature = nil
	unsigned, err := json.Marshal(batch)
	if err != nil || !ed25519.Verify(worker.PublicKey, append([]byte(claimBatchFormat+"\x00"), unsigned...), signature) {
		return ErrDenied
	}
	return nil
}

func signedPartClaim(j *Journal, part generation.Object, round int64, end time.Time, key ed25519.PrivateKey) (Claim, error) {
	c := Claim{Format: Format, Plan: j.planID, Object: part.ID, Worker: j.worker, Round: round, ExpiresMillis: end.UnixMilli()}
	if len(key) != ed25519.PrivateKeySize || Identity(key.Public().(ed25519.PublicKey)) != j.worker {
		return c, ErrDenied
	}
	unsigned, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	c.Signature = ed25519.Sign(key, append([]byte(Format+"/claim\x00"), unsigned...))
	return c, nil
}

type partClaimCache struct {
	round int64
	ready map[string]bool
}

// ensure records only intentions for the current round, never completion. The
// caller still starts every part's wire IO under that original bounded lease.
func (cache *partClaimCache) ensure(ctx context.Context, b *storage.Backend, j *Journal, tasks []Task, state State, current generation.Object, round int64, end time.Time, key ed25519.PrivateKey) error {
	if j.plan.MissingRepair != nil || !j.tasks[current.ID] || j.plan.owner(current.ID, round) != j.worker || end.UnixMilli() != j.plan.StartMillis+(round+1)*j.plan.SlotMillis {
		return ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	actualRound, _ := j.plan.round(now)
	if now.UnixMilli() < j.plan.StartMillis || actualRound != round || !now.Before(end) {
		return context.DeadlineExceeded
	}
	if cache.ready == nil || cache.round != round {
		cache.round, cache.ready = round, map[string]bool{}
	}
	if cache.ready[current.ID] {
		return nil
	}
	batch := claimBatch{Format: claimBatchFormat, Plan: j.planID, Worker: j.worker, Round: round, ExpiresMillis: end.UnixMilli()}
	appendPart := func(part generation.Object) error {
		member, err := signedPartClaim(j, part, round, end, key)
		if err == nil {
			batch.Claims = append(batch.Claims, member)
		}
		return err
	}
	if err := appendPart(current); err != nil {
		return err
	}
	for _, task := range tasks {
		if len(batch.Claims) == maxClaimBatchMembers {
			break
		}
		if task.Part.ID == current.ID || state.Parts[task.Part.ID].Complete || cache.ready[task.Part.ID] || j.plan.owner(task.Part.ID, round) != j.worker {
			continue
		}
		if !j.tasks[task.Part.ID] {
			return ErrDenied
		}
		if err := appendPart(task.Part); err != nil {
			return err
		}
	}
	unsigned, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	batch.Signature = ed25519.Sign(key, append([]byte(claimBatchFormat+"\x00"), unsigned...))
	raw, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if len(raw) > maxClaimBatchBytes || len(raw) > b.Profile().MaxObjectBytes {
		return ErrDenied
	}
	id := storage.Hash([]byte(claimBatchFormat + "/" + j.planID + "/" + j.worker + "/" + strconv.FormatInt(round, 10) + "/" + storage.Hash(raw)))
	bounded, stop := context.WithDeadline(ctx, end)
	defer stop()
	if err = b.Put(bounded, "claim-"+id, raw); err != nil {
		return err
	}
	for _, member := range batch.Claims {
		cache.ready[member.Object] = true
	}
	return nil
}
