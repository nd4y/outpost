package generation

import (
	"context"
	"encoding/json"
)

// PublicationEvidence is historical local evidence, not a fresh scrub or a
// network attestation. Its original time is never advanced by reading it.
type PublicationEvidence struct {
	Generation   string `json:"generation"`
	Verification string `json:"verification"`
	VerifiedAt   int64  `json:"verifiedAt"`
	Objects      int    `json:"objects"`
	Bytes        int64  `json:"bytes"`
}

// PublishedEvidence requires a durable complete generation, its original full
// verification journal and unchanged identities of every referenced object.
// Missing or changed evidence is refused without repair, publication, pins or
// persisted catalog-damage diagnosis. Callers still need independent authority
// for any subsequent mutation; this result itself grants no permission.
func (r *Replica) PublishedEvidence(ctx context.Context, id string) (PublicationEvidence, error) {
	var result PublicationEvidence
	if !validID(id) {
		return result, ErrInvalid
	}
	e := r.exclusive(ctx, func() error { var e error; result, e = r.publishedEvidenceLocked(ctx, id); return e })
	return result, e
}

func (r *Replica) publishedEvidenceLocked(ctx context.Context, id string) (PublicationEvidence, error) {
	var result PublicationEvidence
	if !validID(id) {
		return result, ErrInvalid
	}
	e := func() error {
		s, e := r.load()
		if e != nil {
			return e
		}
		item, exists := s.Generations[id]
		if !exists || !item.Complete || item.Damaged {
			return ErrIncomplete
		}
		if _, bad := s.CatalogDamage[id]; bad {
			return ErrIncomplete
		}
		// Avoid locked/get: their normal integrity path can write a diagnosis.
		_, refs, e := r.catalogEntry(id, item, true)
		if e != nil {
			return e
		}
		v, _, e := r.verification(id, "", refs)
		if e != nil {
			return e
		}
		if v.CompletedAt <= 0 || len(v.Objects) != len(refs) {
			return ErrIncomplete
		}
		var total int64
		for key, ref := range refs {
			if e := ctx.Err(); e != nil {
				return e
			}
			if _, bad := s.Damage[key]; bad {
				return ErrIncomplete
			}
			checked, found := v.Objects[key]
			if !found {
				return ErrIncomplete
			}
			stamp, e := r.objectStamp(ref)
			if e != nil || stamp != checked.Stamp {
				return ErrIncomplete
			}
			total += int64(ref.Bytes)
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		raw, e := json.Marshal(v)
		if e != nil {
			return e
		}
		result = PublicationEvidence{Generation: id, Verification: Hash(raw), VerifiedAt: v.CompletedAt, Objects: len(refs), Bytes: total}
		return nil
	}()
	if e != nil {
		return PublicationEvidence{}, e
	}
	return result, nil
}

// WithProtectedPublication revalidates expected historical evidence, retains a
// generation pin, and excludes replica writers until the caller's local receipt
// commit returns. The caller supplies current authority and quota admission.
// fn and admit must not re-enter this replica or perform network operations.
// Failure preserves any already durable pin; it never deletes or publishes.
func (r *Replica) WithProtectedPublication(ctx context.Context, pin string, expected PublicationEvidence, admit func() error, fn func() error) error {
	if !validID(pin) || !validID(expected.Generation) || admit == nil || fn == nil {
		return ErrInvalid
	}
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return admit()
	}
	if e := check(); e != nil {
		return e
	}
	return r.exclusive(ctx, func() error {
		if e := check(); e != nil {
			return e
		}
		proof, e := r.publishedEvidenceLocked(ctx, expected.Generation)
		if e != nil {
			return e
		}
		if proof != expected {
			return ErrConflict
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		wanted := Pin{Generation: expected.Generation, Kind: "generation"}
		old, exists := s.Pins[pin]
		if exists && old != wanted {
			return ErrConflict
		}
		if !exists {
			if len(s.Pins) >= MaxPins {
				return ErrInvalid
			}
			if e := check(); e != nil {
				return e
			}
			s.Pins[pin] = wanted
			s.Revision++
			if e := r.save(s); e != nil {
				return e
			}
		}
		if e := check(); e != nil {
			return e
		}
		if e := fn(); e != nil {
			return e
		}
		return check()
	})
}
