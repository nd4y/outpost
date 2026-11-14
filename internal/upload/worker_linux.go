package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

type Claim struct {
	Format        string `json:"format"`
	Plan          string `json:"plan"`
	Object        string `json:"part"`
	Worker        string `json:"worker"`
	Round         int64  `json:"round"`
	ExpiresMillis int64  `json:"expiresMillis"`
	Signature     []byte `json:"signature,omitempty"`
}
type Result struct {
	Receipt        Receipt
	CleanupPending bool
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func claim(ctx context.Context, b *storage.Backend, j *Journal, part generation.Object, round int64, end time.Time, key ed25519.PrivateKey) error {
	c := Claim{Format: Format, Plan: j.planID, Object: part.ID, Worker: j.worker, Round: round, ExpiresMillis: end.UnixMilli()}
	unsigned, _ := json.Marshal(c)
	c.Signature = ed25519.Sign(key, append([]byte(Format+"/claim\x00"), unsigned...))
	raw, _ := json.Marshal(c)
	id := storage.Hash([]byte(j.planID + "/" + part.ID + "/" + strconv.FormatInt(round, 10)))
	return b.Put(ctx, "claim-"+id, raw)
}
func VerifyClaim(raw []byte, p Plan, planID string) error {
	if p.policy() != nil || !storage.ID(planID) {
		return ErrDenied
	}
	var c Claim
	if storage.Decode(raw, &c, 4096) != nil || c.Format != Format || c.Plan != planID || !storage.ID(c.Object) || c.Round < 0 || c.Round > (p.ExpiresUnix*1000-p.StartMillis)/p.SlotMillis || c.Worker != p.owner(c.Object, c.Round) || c.ExpiresMillis != p.StartMillis+(c.Round+1)*p.SlotMillis {
		return ErrDenied
	}
	if p.MissingRepair != nil && c.Object != p.MissingRepair.Part {
		return ErrDenied
	}
	tasks, e := p.Tasks()
	if e != nil {
		return e
	}
	member := false
	for _, task := range tasks {
		if task.Part.ID == c.Object {
			member = true
			break
		}
	}
	if !member {
		return ErrDenied
	}
	w, ok := p.worker(c.Worker)
	if !ok {
		return ErrDenied
	}
	signature := c.Signature
	c.Signature = nil
	unsigned, _ := json.Marshal(c)
	if !ed25519.Verify(w.PublicKey, append([]byte(Format+"/claim\x00"), unsigned...), signature) {
		return ErrDenied
	}
	return nil
}
func (j *Journal) verifyComplete(ctx context.Context, b *storage.Backend, audit *cloudAudit) error {
	if err := j.readTargetClosure(ctx, b, audit); err != nil {
		return err
	}
	if audit != nil {
		_, _, err := audit.evidence(ctx)
		return err
	}
	return nil
}

func (j *Journal) readTargetClosure(ctx context.Context, b *storage.Backend, audit *cloudAudit) error {
	raw, e := b.Catalog(ctx, j.plan.Generation, j.authority.Generation)
	if storage.Missing(e) {
		// Catalog parts are outside the payload task map and cannot authorize its repair.
		return storage.ErrNotFound
	}
	if e != nil {
		return e
	}
	if !bytes.Equal(raw, j.plan.Catalog) {
		return storage.ErrIntegrity
	}
	for _, blob := range j.plan.Blobs {
		if audit != nil {
			e = audit.verify(ctx, blob.Object.ID, false)
		} else {
			var actual storage.Blob
			actual, e = b.Descriptor(ctx, blob.Object)
			if e == nil {
				expectedRaw, _ := json.Marshal(blob)
				actualRaw, _ := json.Marshal(actual)
				if !bytes.Equal(expectedRaw, actualRaw) {
					e = storage.ErrConflict
				} else {
					_, e = b.ReadDescribed(ctx, actual)
				}
			}
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func (j *Journal) publish(ctx context.Context, b *storage.Backend) error {
	for _, blob := range j.plan.Blobs {
		if e := b.SealBlob(ctx, blob); e != nil {
			return e
		}
	}
	return b.Publish(ctx, j.plan.Catalog, j.authority.Generation)
}

// sourceObjectCache retains one verified object between assignment slots.
type sourceObjectCache struct {
	object generation.Object
	data   []byte
}

func (c *sourceObjectCache) read(ctx context.Context, source *generation.Replica, id string, ref generation.Object) ([]byte, error) {
	if c.object != ref {
		// A cancelled read may return no bytes. Clear the previous identity
		// before replacing its buffer so later slots cannot reuse a false hit.
		c.object, c.data = generation.Object{}, nil
		var err error
		c.data, err = source.ReadObject(ctx, id, ref)
		if err != nil {
			return nil, err
		}
		c.object = ref
	}
	return c.data, nil
}

// Run consumes a cached signed plan. Each worker has its own journal, complete
// keyless replica and identity key. No controller or peer RPC is needed at run time.
func (j *Journal) Run(ctx context.Context, source *generation.Replica, b *storage.Backend, key ed25519.PrivateKey) (result Result, err error) {
	if source == nil || b == nil || len(key) != ed25519.PrivateKeySize || Identity(key.Public().(ed25519.PublicKey)) != j.worker || b.Profile().ID() != j.plan.Profile.ID() || !sameTrust(source.Trust(), j.authority.Generation) || time.Now().Unix() >= j.plan.ExpiresUnix {
		return result, ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(j.plan.ExpiresUnix, 0))
	defer cancel()
	unlock, e := lock(ctx, j.root, "worker.lock")
	if e != nil {
		return result, e
	}
	defer unlock()
	if j.plan.Profile.WriteMode == storage.WebDAVMoveMode {
		book, e := j.openMoveBook(ctx)
		if e != nil {
			return result, e
		}
		defer book.Close()
		ctx = storage.WithWriteAttempts(ctx, book)
	}
	if delay := time.Until(time.UnixMilli(j.plan.StartMillis)); delay > 0 {
		if e = sleep(ctx, delay); e != nil {
			return result, e
		}
	}
	// Require the exact recorded complete catalog and protect it before IO.
	// Payloads are verified when read or when auditing the target. A separate
	// full source scrub cannot be a prerequisite for every bounded retry.
	catalog, e := source.Catalog(ctx, j.plan.Generation)
	if e != nil {
		return result, e
	}
	if !bytes.Equal(catalog, j.plan.Catalog) {
		return result, storage.ErrIntegrity
	}
	pin := workerPin(j.planID, j.worker)
	if e = source.Pin(ctx, pin, j.plan.Generation, "generation"); e != nil {
		return result, e
	}
	defer func() {
		if err != nil {
			short, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			_ = j.edit(short, func(s *State) error { s.Phase = "RETRYABLE"; return nil })
		}
	}()
	if j.plan.MissingRepair != nil {
		if e = j.repairMissingPart(ctx, source, b, key); e != nil {
			return result, e
		}
		return j.completeTarget(ctx, source, b, pin, nil)
	}
	if e = b.Probe(ctx); e != nil {
		return result, e
	}
	binding, _ := json.Marshal(struct {
		Plan       string `json:"plan"`
		Operation  string `json:"operation"`
		Generation string `json:"generation"`
		Target     string `json:"target"`
	}{j.planID, j.plan.Operation, j.plan.Generation, j.plan.Profile.ID()})
	if e = b.Put(ctx, "plan-"+j.plan.Operation, binding); e != nil {
		return result, e
	}
	audit, e := j.newAudit(ctx, b)
	if e != nil {
		return result, e
	}
	defer audit.close()
	tasks, e := j.plan.Tasks()
	if e != nil {
		return result, e
	}
	if e = j.edit(ctx, func(s *State) error { s.Phase = "TRANSFERRING"; return nil }); e != nil {
		return result, e
	}
	var cache sourceObjectCache
	idleDelay := 50 * time.Millisecond
	previousRound := int64(-1)
	for {
		if e = ctx.Err(); e != nil {
			return result, e
		}
		// A target marker is only a hint until the whole generation is read back.
		if e = j.verifyComplete(ctx, b, audit); e == nil {
			return j.completeTarget(ctx, source, b, pin, audit)
		} else if !storage.Missing(e) && !errors.Is(e, storage.ErrUnavailable) {
			return result, e
		}
		state, e := j.Status(ctx)
		if e != nil {
			return result, e
		}
		round, end := j.plan.round(time.Now())
		if round != previousRound {
			idleDelay, previousRound = 50*time.Millisecond, round
		}
		madeProgress := false
		for _, task := range tasks {
			progress := state.Parts[task.Part.ID]
			if progress.Complete || j.plan.owner(task.Part.ID, round) != j.worker {
				continue
			}
			if audit != nil {
				reuse, e := audit.reusable(ctx, task.Object.ID)
				if e != nil {
					return result, e
				}
				if reuse {
					continue
				}
			}
			// Completion belongs to immutable bytes, not to an assignment slot.
			// Rechecking every completed prefix on slot rotation can starve the
			// remaining parts on slow links. Publication detects vanished parts.
			if e = ctx.Err(); e != nil {
				return result, e
			}
			if !time.Now().Before(end) {
				break
			}
			bounded, stop := context.WithDeadline(ctx, end)
			e = j.beginPart(bounded, task.Part.ID, round)
			sent := int64(0)
			if e == nil {
				_, e = b.ReadPart(bounded, task.Part)
			}
			if storage.Missing(e) {
				e = claim(bounded, b, j, task.Part, round, end, key)
				if e == nil {
					var data []byte
					data, e = cache.read(bounded, source, j.plan.Generation, task.Object)
					if e == nil {
						endOffset := task.Offset + task.Part.Bytes
						if task.Offset < 0 || endOffset > len(data) {
							e = ErrDenied
						} else {
							part := data[task.Offset:endOffset]
							if storage.Hash(part) != task.Part.ID {
								e = storage.ErrIntegrity
							} else {
								sent = int64(len(part))
								e = b.PutPart(bounded, task.Part, part)
							}
						}
					}
				}
			}
			if e == nil {
				e = j.donePart(bounded, task.Part.ID, sent)
				madeProgress = madeProgress || e == nil
			}
			stop()
			if e != nil && !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, context.Canceled) && !errors.Is(e, storage.ErrUnavailable) {
				return result, e
			}
		}
		round, end = j.plan.round(time.Now())
		if round != previousRound {
			idleDelay, previousRound = 50*time.Millisecond, round
		}
		if j.plan.owner("publication", round) == j.worker {
			// Full-generation audit may outlive a part slot. A successor can
			// audit concurrently; immutable publication makes the duplicate safe.
			if audit != nil {
				e = audit.publish(ctx, j.plan.Catalog, j.authority.Generation)
			} else {
				e = j.publish(ctx, b)
			}
			madeProgress = madeProgress || e == nil
			if e != nil && !storage.Missing(e) && !errors.Is(e, storage.ErrUnavailable) && !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, context.Canceled) {
				return result, e
			}
			// If previously acknowledged parts disappeared, retrying their immutable
			// uploads is safe. Never clear source pins or claim COMPLETE on this path.
			var absent *storage.MissingPart
			if errors.As(e, &absent) {
				if e = j.edit(ctx, func(s *State) error {
					if p, ok := s.Parts[absent.Part.ID]; ok {
						p.Complete = false
						s.Parts[absent.Part.ID] = p
					}
					return nil
				}); e != nil {
					return result, e
				}
			}
		}
		// Workers waiting for peers must not poll the target at the active-work
		// cadence indefinitely. No completion evidence is cached or weakened:
		// the next iteration still verifies the full closure before COMPLETE.
		if madeProgress {
			idleDelay = 50 * time.Millisecond
		} else {
			idleDelay = min(2*idleDelay, time.Second)
		}
		// Wake at the next assignment boundary even after a long idle period.
		// Cancellation and the plan deadline interrupt the bounded wait.
		pause := min(idleDelay, time.Until(end))
		if pause <= 0 {
			continue
		}
		if e = sleep(ctx, pause); e != nil {
			return result, e
		}
	}
}

func workerPin(plan, worker string) string {
	return storage.Hash([]byte(Format + "/pin/" + plan + "/" + worker))
}

func (j *Journal) completeTarget(ctx context.Context, source *generation.Replica, b *storage.Backend, pin string, audit *cloudAudit) (Result, error) {
	receipt := Receipt{b.Profile().ID(), j.plan.Generation, j.plan.Operation, j.worker, "full-target-readback", time.Now().Unix()}
	if audit != nil {
		var err error
		receipt.Verification, receipt.ObservedUnix, err = audit.evidence(ctx)
		if err != nil {
			return Result{}, err
		}
	}
	if err := j.edit(ctx, func(s *State) error {
		// Whole-target evidence resolves parts whose acknowledgment missed the slot.
		for id, p := range s.Parts {
			p.Complete = true
			s.Parts[id] = p
		}
		s.Phase = "COMPLETE"
		s.Receipt = &receipt
		return nil
	}); err != nil {
		return Result{}, err
	}
	return Result{Receipt: receipt, CleanupPending: source.ReleasePin(ctx, pin) != nil}, nil
}
