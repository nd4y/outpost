package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func (q *Outbox) grant(raw []byte) (management.Enrollment, error) {
	if len(q.opts.Owner) == 0 {
		if len(raw) != 0 {
			return management.Enrollment{}, ErrInvalid
		}
		return management.Enrollment{}, nil
	}
	g, e := management.VerifyEnrollment(raw, q.opts.Owner)
	if e != nil {
		return g, e
	}
	if g.Node != q.node {
		return g, management.ErrDenied
	}
	if _, ok := g.Domain(q.opts.Domain); !ok {
		return g, management.ErrDenied
	}
	return g, nil
}
func (q *Outbox) authorize(ctx context.Context, s journal) error {
	g, e := q.grant(s.Enrollment)
	if e != nil {
		return e
	}
	if len(q.opts.Owner) == 0 {
		return nil
	}
	if !g.Active(time.Now()) {
		return management.ErrDenied
	}
	if q.opts.Authorize != nil {
		return q.opts.Authorize(ctx, g)
	}
	return nil
}

// Enrollment returns only the current verified signed grant. Callers cannot
// substitute a file's older grant for the durable monotonic enrollment.
func (q *Outbox) Enrollment(ctx context.Context) ([]byte, error) {
	var raw []byte
	e := q.transaction(ctx, func(s *journal) error { raw = append([]byte(nil), s.Enrollment...); return nil })
	return raw, e
}
func (q *Outbox) Renew(ctx context.Context, raw []byte) error {
	next, e := q.grant(raw)
	if e != nil || len(q.opts.Owner) == 0 {
		if e != nil {
			return e
		}
		return ErrInvalid
	}
	return q.transaction(ctx, func(s *journal) error {
		old, e := q.grant(s.Enrollment)
		if e != nil {
			return e
		}
		if next.Revision == old.Revision && bytes.Equal(raw, s.Enrollment) {
			return nil
		}
		previous, _ := old.Domain(q.opts.Domain)
		current, _ := next.Domain(q.opts.Domain)
		if next.Revision <= old.Revision || next.Tenant != old.Tenant || next.Class != old.Class || previous != current {
			return ErrConflict
		}
		// Revocation and expiry are durable transitions too, not validation failures.
		s.Enrollment = append([]byte(nil), raw...)
		return q.save(*s)
	})
}

// Observe uses a journal-owned source position. Event deduplication and the next
// metric heartbeat commit in the same transaction as admission. A rejected
// sample does not consume a position or suppress the next valid observation.
func (q *Outbox) Observe(ctx context.Context, r Record, interval time.Duration) (bool, error) {
	if interval < time.Second || interval > 24*time.Hour || interval%time.Second != 0 {
		return false, ErrInvalid
	}
	if e := r.Validate(); e != nil {
		return false, e
	}
	emitted := false
	e := q.transaction(ctx, func(s *journal) error {
		if e := q.authorize(ctx, *s); e != nil {
			return e
		}
		now := time.Now().Unix()
		if r.ObservedUnix > now {
			return ErrConflict
		}
		events, _ := json.Marshal(r.Events)
		digest := storage.Hash(events)
		if digest == s.EventsDigest {
			r.Events = nil
		}
		if now < s.NextSample {
			r.Metrics = nil
		}
		if len(r.Events)+len(r.Metrics) == 0 {
			return nil
		}
		if len(s.Frames) >= s.MaxItems || s.Cursor == math.MaxUint64 {
			return ErrCapacity
		}
		messages, e := Encode(q.node, q.opts.Domain, r)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(r)
		s.Cursor++
		s.LastDigest = storage.Hash(raw)
		s.Frames = append(s.Frames, frame{Position: s.Cursor, Record: r, Messages: messages})
		s.EventsDigest = digest
		if len(r.Metrics) > 0 {
			s.NextSample = now + int64(interval/time.Second)
		}
		if e = q.saveAdmission(*s); e != nil {
			return e
		}
		emitted = true
		return q.point("enqueued")
	})
	return emitted, e
}
