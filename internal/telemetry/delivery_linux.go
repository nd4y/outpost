package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

type Outcome struct {
	State      string
	Code       string
	RetryAfter time.Duration
	Rejected   int64
	Warning    bool
}
type Sender interface {
	Send(context.Context, Message) Outcome
}

func retryDelay(attempt uint64) time.Duration {
	if attempt > 12 {
		attempt = 12
	}
	base := uint64(1) << attempt
	var random [8]byte
	if _, e := rand.Read(random[:]); e != nil {
		return time.Duration(base) * time.Second
	}
	return time.Duration(base/2+binary.LittleEndian.Uint64(random[:])%(base/2+1)) * time.Second
}

// Deliver sends at most one immutable request. The delivery lease spans network
// IO, while the journal lock does not: producers and status remain independent.
// A retry deadline is durable before sending, including an uncertain crash.
func (q *Outbox) Deliver(ctx context.Context, sender Sender) (Status, error) {
	if sender == nil {
		return Status{}, ErrInvalid
	}
	e := q.delivery.WithLock(ctx, func() error {
		var message Message
		var position, attempt uint64
		err := q.transaction(ctx, func(s *journal) error {
			if e := q.authorize(ctx, *s); e != nil {
				return e
			}
			if len(s.Frames) == 0 {
				return nil
			}
			f := &s.Frames[0]
			if f.Blocked != "" {
				return ErrBlocked
			}
			if time.Now().Unix() < f.NotBefore {
				return nil
			}
			if f.Attempts == math.MaxUint64 {
				return ErrConflict
			}
			f.Attempts++
			f.NotBefore = time.Now().Add(retryDelay(f.Attempts)).Unix()
			if e := q.save(*s); e != nil {
				return e
			}
			message = f.Messages[f.Next]
			position = f.Position
			attempt = f.Attempts
			return nil
		})
		if err != nil || message.Signal == "" {
			return err
		}
		if err = q.point("before-send"); err != nil {
			return err
		}
		if err = q.check(ctx); err != nil {
			return err
		}
		if err = q.transaction(ctx, func(s *journal) error { return q.authorize(ctx, *s) }); err != nil {
			return err
		}
		result := sender.Send(ctx, message)
		if err = q.point("after-send"); err != nil {
			return err
		}
		return q.transaction(ctx, func(s *journal) error {
			if len(s.Frames) == 0 {
				return ErrConflict
			}
			f := &s.Frames[0]
			if f.Position != position || f.Attempts != attempt || f.Messages[f.Next].Digest != message.Digest {
				return ErrConflict
			}
			switch result.State {
			case "ACCEPTED":
				if result.Rejected != 0 {
					return ErrInvalid
				}
				if s.Accepted == math.MaxUint64 {
					return ErrConflict
				}
				s.Accepted++
				if result.Warning {
					if s.Warnings == math.MaxUint64 {
						return ErrConflict
					}
					s.Warnings++
				}
				advance(s)
			case "RETRY_WAIT":
				wait := result.RetryAfter
				if wait < 0 || wait > 24*time.Hour {
					return ErrInvalid
				}
				deadline := time.Now().Add(wait).Unix()
				if deadline > f.NotBefore {
					f.NotBefore = deadline
				}
			case "BLOCKED":
				if !member(result.Code, "PARTIAL_REJECTION", "PERMANENT_REJECTION", "INVALID_RESPONSE") {
					return ErrInvalid
				}
				f.Blocked = result.Code
				if result.Rejected < 0 {
					return ErrInvalid
				}
				f.Rejected = result.Rejected
			default:
				return ErrInvalid
			}
			if e := q.save(*s); e != nil {
				return e
			}
			return q.point("settled")
		})
	})
	status, se := q.Status(ctx)
	if e != nil {
		return status, e
	}
	return status, se
}
