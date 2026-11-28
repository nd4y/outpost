package generation

import (
	"context"
	"errors"
	"time"
)

const CatalogStateFormat = "outpost-replica-state-5"

var ErrCatalogUnavailable = errors.New("generation catalog unavailable")

func integrityState(format string) bool {
	return format == IntegrityStateFormat || format == CatalogStateFormat
}
func validateCatalogDamage(s state) error {
	if (len(s.CatalogDamage) > 0 || len(s.CatalogRepairs) > 0) && s.Format != CatalogStateFormat || len(s.CatalogDamage) > MaxGenerations || len(s.CatalogRepairs) > MaxPins {
		return ErrInvalid
	}
	for id, d := range s.CatalogDamage {
		item, ok := s.Generations[id]
		if !ok || !item.Damaged || id != d.Object.ID || !validID(id) || d.Object.Bytes != item.Bytes || d.DetectedUnix < 1 || d.Repair != "" && (!validID(d.Repair) || s.CatalogRepairs[d.Repair].Object != d.Object || s.CatalogRepairs[d.Repair].CompletedUnix != 0) {
			return ErrInvalid
		}
	}
	for id, v := range s.CatalogRepairs {
		if !validID(id) || !v.valid() || v.CompletedUnix == 0 && s.CatalogDamage[v.Object.ID].Repair != id {
			return ErrInvalid
		}
	}
	return nil
}

// The caller holds the replica lock. Unknown closure blocks every GC plan;
// other authenticated catalogs remain usable and independently reportable.
func (r *Replica) recordCatalogDamage(s *state, id string) error {
	item, ok := s.Generations[id]
	if !ok {
		return ErrInvalid
	}
	if _, known := s.CatalogDamage[id]; known {
		return nil
	}
	nonce, e := randomID()
	if e != nil {
		return e
	}
	if s.CatalogDamage == nil {
		s.CatalogDamage = map[string]DamageRecord{}
	}
	s.CatalogDamage[id] = DamageRecord{Object: Object{id, item.Bytes}, DetectedUnix: time.Now().Unix()}
	item.Damaged = true
	item.RepairToken = Hash([]byte("catalog/" + id + "/" + nonce))
	s.Generations[id] = item
	s.Format = CatalogStateFormat
	s.Latest = ""
	highest := uint64(0)
	for key, v := range s.Generations {
		if v.Complete && !v.Damaged && v.Sequence > highest {
			s.Latest = key
			highest = v.Sequence
		}
	}
	s.Revision++
	if e = r.save(*s); e != nil {
		return e
	}
	return r.point("catalog-corruption-durable")
}

// RepairCatalogFor accepts only an already admitted exact checkpoint, size,
// sequence and writer signature under the current repair incarnation. It
// preserves unreadable bytes first and never republishes payload readiness.
func (r *Replica) RepairCatalogFor(ctx context.Context, id, token string, raw []byte) error {
	if !validID(id) || !validID(token) || len(raw) > MaxCatalog || Hash(raw) != id {
		return ErrInvalid
	}
	c, e := VerifyCatalog(raw, r.trust)
	if e != nil {
		return e
	}
	return r.locked(ctx, func(s *state) error {
		if e := checkRepair(s, id, token); e != nil {
			return e
		}
		item := s.Generations[id]
		if item.Sequence != c.Sequence || item.Bytes != len(raw) {
			return ErrConflict
		}
		_, bad := s.CatalogDamage[id]
		if !bad {
			if _, e := r.catalogRaw(id, item); e == nil {
				return nil
			}
			if e := r.recordCatalogDamage(s, id); e != nil {
				return e
			}
			// Discovery of a new catalog incident invalidates the old token.
			return ErrConflict
		}
		return r.replaceDamagedEntry(ctx, s, Object{id, item.Bytes}, raw, "catalogs", s.CatalogDamage, &s.CatalogRepairs, func() error { _, e := r.catalogRaw(id, item); return e })
	})
}

func (r *Replica) applyCatalogDiagnosis(ctx context.Context, s *state) error {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	for _, id := range sortedIDs(r.pendingCatalogs) {
		if e := ctx.Err(); e != nil {
			return e
		}
		if item, exists := s.Generations[id]; exists {
			if _, _, e := r.catalogEntry(id, item, true); e != nil {
				if e = r.recordCatalogDamage(s, id); e != nil {
					return e
				}
			}
		}
	}
	r.pendingCatalogs = nil
	return nil
}
