package storage

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

func moveTemporary(key string) bool {
	for _, prefix := range []string{"attempt-", "probe-stage-"} {
		if id, ok := strings.CutPrefix(key, prefix); ok && ID(id) {
			return true
		}
	}
	return false
}

func (b *Backend) stage(ctx context.Context, key string, data []byte, objectPart bool) error {
	_, _, err := b.requestWith(ctx, http.MethodPut, key, data, requestOptions{stage: true, objectStage: objectPart})
	return err
}

func (b *Backend) move(ctx context.Context, temporary, destination string) (int, error) {
	_, status, err := b.requestWith(ctx, "MOVE", temporary, nil, requestOptions{destination: destination})
	return status, err
}

func (b *Backend) exact(ctx context.Context, key string, data []byte) error {
	got, err := b.Get(ctx, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, data) {
		return ErrConflict
	}
	return nil
}

func (b *Backend) putMove(ctx context.Context, key string, data []byte) error {
	book, ok := ctx.Value(writeAttemptsKey{}).(WriteAttempts)
	if !ok || !safeName(key, 170) || strings.HasPrefix(key, "attempt-") || strings.HasPrefix(key, "probe-stage-") {
		return ErrDenied
	}
	if len(data) < 1 || len(data) > b.profile.MaxObjectBytes {
		return ErrCapacity
	}
	data = bytes.Clone(data)
	return book.WithRecord(ctx, b.profile.ID(), key, Hash(data), len(data), func(tx MoveTransaction) error {
		record := tx.State()
		var attempt MoveAttempt
		if len(record.Attempts) > 0 {
			attempt = record.Attempts[len(record.Attempts)-1]
		}
		err := b.exact(ctx, key, data)
		if err == nil {
			return acceptMove(tx, attempt)
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if attempt.Phase == "WRITING" || attempt.Phase == "STAGED" {
			temporary, err := tx.Temporary(attempt)
			if err != nil {
				return err
			}
			err = b.exact(ctx, temporary, data)
			if err == nil {
				return b.publishMove(ctx, tx, attempt, temporary, key, data)
			}
			if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrConflict) {
				return err
			}
			// The old request may still complete. Preserve its name and give
			// readback one request window before reserving a different name.
			if time.Now().UnixMilli()-attempt.WriteStartedMillis < int64(b.profile.TimeoutMillis) {
				return ErrUnavailable
			}
			if err = tx.Transition(attempt.Nonce, "ABANDONED"); err != nil {
				return err
			}
			attempt.Phase = "ABANDONED"
		}
		if attempt.Phase != "ALLOCATED" {
			attempt, err = tx.Allocate()
			if err != nil {
				return err
			}
		}
		temporary, err := tx.Temporary(attempt)
		if err != nil {
			return err
		}
		if err = tx.Transition(attempt.Nonce, "WRITING"); err != nil {
			return err
		}
		if err = b.stage(ctx, temporary, data, strings.HasPrefix(key, "part-")); err != nil {
			return err
		}
		if err = b.exact(ctx, temporary, data); err != nil {
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
				return ErrUnavailable
			}
			return err
		}
		return b.publishMove(ctx, tx, attempt, temporary, key, data)
	})
}

func acceptMove(tx MoveTransaction, attempt MoveAttempt) error {
	switch attempt.Phase {
	case "ALLOCATED", "WRITING", "STAGED":
		return tx.Transition(attempt.Nonce, "PUBLISHED")
	default:
		return nil
	}
}

func (b *Backend) publishMove(ctx context.Context, tx MoveTransaction, attempt MoveAttempt, temporary, key string, data []byte) error {
	if err := tx.Transition(attempt.Nonce, "STAGED"); err != nil {
		return err
	}
	_, moveErr := b.move(ctx, temporary, key)
	if errors.Is(moveErr, ErrDenied) || errors.Is(moveErr, ErrUnsupported) || errors.Is(moveErr, ErrCapacity) {
		return moveErr
	}
	if err := b.exact(ctx, key, data); err != nil {
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if moveErr != nil && !errors.Is(moveErr, ErrNotFound) && !errors.Is(moveErr, ErrConflict) {
			return moveErr
		}
		return ErrUnavailable
	}
	return tx.Transition(attempt.Nonce, "PUBLISHED")
}

func (b *Backend) probeMove(ctx context.Context) error {
	// Stable, public diagnostic bytes and names keep probe residue bounded.
	data := []byte(Hash([]byte("outpost-webdav-move-probe-1/" + b.profile.Namespace)))
	key := "move-probe-" + Hash(data)
	if err := b.Put(ctx, key, data); err != nil {
		return err
	}
	other := bytes.Clone(data)
	other[0] ^= 1
	temporary := "probe-stage-" + Hash(other)
	if err := b.exact(ctx, temporary, other); err != nil {
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if err = b.stage(ctx, temporary, other, false); err != nil {
			return err
		}
		if err = b.exact(ctx, temporary, other); err != nil {
			return err
		}
	}
	status, err := b.move(ctx, temporary, key)
	if status != http.StatusPreconditionFailed || !errors.Is(err, ErrConflict) {
		if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrUnsupported) {
			return err
		}
		return ErrUnsupported
	}
	if err = b.exact(ctx, key, data); err != nil {
		return err
	}
	if err = b.exact(ctx, temporary, other); err != nil {
		return err
	}
	return b.checkLayout(ctx)
}
