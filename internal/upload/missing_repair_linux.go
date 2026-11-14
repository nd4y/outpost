package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

// repairMissingPart never republishes the catalog or writes a second payload.
// The original marker and exact catalog must still be readable.
func (j *Journal) repairMissingPart(ctx context.Context, source *generation.Replica, b *storage.Backend, key ed25519.PrivateKey) error {
	if j.Readback.MaxAgeSeconds != 0 {
		return ErrDenied
	}
	raw, err := b.Catalog(ctx, j.plan.Generation, j.authority.Generation)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, j.plan.Catalog) {
		return storage.ErrIntegrity
	}
	tasks, err := j.plan.Tasks()
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if task.Part.ID != j.plan.MissingRepair.Part {
			continue
		}
		if err = j.restorePart(ctx, source, b, key, task); err != nil {
			return err
		}
		err = j.verifyComplete(ctx, b, nil)
		if storage.Missing(err) {
			// Another scheduled observation can authorize a different missing part.
			return errors.Join(storage.ErrUnavailable, err)
		}
		return err
	}
	return ErrDenied
}

func (j *Journal) restorePart(ctx context.Context, source *generation.Replica, b *storage.Backend, key ed25519.PrivateKey, task Task) error {
	for {
		_, err := b.ReadPart(ctx, task.Part)
		if !storage.Missing(err) {
			return err
		}
		round, end := j.plan.round(time.Now())
		if j.plan.owner(task.Part.ID, round) != j.worker {
			if err := sleep(ctx, time.Until(end)); err != nil {
				return err
			}
			continue
		}
		// Probe and validate source bytes before spending the assignment slot.
		data, err := source.ReadObject(ctx, j.plan.Generation, task.Object)
		if err != nil {
			return err
		}
		last := task.Offset + task.Part.Bytes
		if task.Offset < 0 || last > len(data) || storage.Hash(data[task.Offset:last]) != task.Part.ID {
			return storage.ErrIntegrity
		}
		if err = b.Probe(ctx); err != nil {
			return err
		}
		bounded, stop := context.WithDeadline(ctx, end)
		err = j.beginPart(bounded, task.Part.ID, round)
		if err == nil {
			err = claim(bounded, b, j, task.Part, round, end, key)
		}
		if err == nil {
			err = b.PutPart(bounded, task.Part, data[task.Offset:last])
		}
		if err == nil {
			err = j.donePart(bounded, task.Part.ID, int64(task.Part.Bytes))
		}
		stop()
		if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return err
		}
	}
}
