package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/nd4y/outpost/internal/statefile"
)

const RetentionFormat = "outpost-retention-ledger-1"

// The sidecar preserves signed retirement authority without changing the
// state2 reader contract. Older binaries cannot admit historical generations.
// Any maintenance they perform without this ledger is detected by its receipt
// coverage check; missing history never silently authorizes re-admission.
type retentionLedger struct {
	Format  string                     `json:"format"`
	Records map[string]json.RawMessage `json:"records"`
}

func (r *Replica) retention(s *state) (retentionLedger, map[string]bool, error) {
	ledger := retentionLedger{Format: RetentionFormat, Records: map[string]json.RawMessage{}}
	retired := map[string]bool{}
	raw, e := read(r.root, "retention.json", MaxState)
	if errors.Is(e, os.ErrNotExist) {
		if len(s.Receipts) > 0 {
			return ledger, nil, ErrMigrationRequired
		}
		return ledger, retired, nil
	}
	if e != nil {
		return ledger, nil, e
	}
	if canonical(raw, &ledger, MaxState) != nil || ledger.Format != RetentionFormat || ledger.Records == nil || len(ledger.Records) > MaxPins {
		return ledger, nil, ErrInvalid
	}
	for op, raw := range ledger.Records {
		p, e := verifyPermit(raw, r.trust)
		if e != nil || p.Operation != op || p.Revision > s.Revision {
			return ledger, nil, ErrInvalid
		}
		for _, id := range p.Retire {
			retired[id] = true
		}
	}
	for op, digest := range s.Receipts {
		if raw, ok := ledger.Records[op]; !ok || Hash(raw) != digest {
			return ledger, nil, ErrMigrationRequired
		}
	}
	return ledger, retired, nil
}

func (r *Replica) recordRetirement(s *state, raw []byte) error {
	ledger, _, e := r.retention(s)
	if e != nil {
		return e
	}
	p, e := verifyPermit(raw, r.trust)
	if e != nil {
		return e
	}
	if old, ok := ledger.Records[p.Operation]; ok {
		if !bytes.Equal(old, raw) {
			return ErrConflict
		}
		return nil
	}
	if len(ledger.Records) >= MaxPins {
		return statefile.ErrCapacity
	}
	ledger.Records[p.Operation] = bytes.Clone(raw)
	b, e := json.Marshal(ledger)
	if e != nil {
		return e
	}
	if len(b) > MaxState {
		return statefile.ErrCapacity
	}
	if e = r.write("retention.json", b); e != nil {
		return e
	}
	return r.point("retirement-authority-durable")
}

// RestoreRetentionLedger is explicit reconstruction from retained signed
// permits. Every committed maintenance digest must be covered exactly. It
// cannot replace a present ledger, reinterpret receipts or clear tombstones.
func (r *Replica) RestoreRetentionLedger(ctx context.Context, permits [][]byte) error {
	if len(permits) > MaxPins {
		return statefile.ErrCapacity
	}
	return r.locked(ctx, func(s *state) error {
		if _, e := read(r.root, "retention.json", MaxState); !errors.Is(e, os.ErrNotExist) {
			if e != nil {
				return e
			}
			return ErrConflict
		}
		ledger := retentionLedger{Format: RetentionFormat, Records: map[string]json.RawMessage{}}
		for _, raw := range permits {
			p, e := verifyPermit(raw, r.trust)
			if e != nil || p.Revision > s.Revision || s.Receipts[p.Operation] != Hash(raw) || ledger.Records[p.Operation] != nil {
				return ErrInvalid
			}
			ledger.Records[p.Operation] = bytes.Clone(raw)
		}
		if len(ledger.Records) != len(s.Receipts) {
			return ErrMigrationRequired
		}
		raw, e := json.Marshal(ledger)
		if e != nil {
			return e
		}
		if len(raw) > MaxState {
			return statefile.ErrCapacity
		}
		return r.write("retention.json", raw)
	})
}

// BeginHistorical requires separate owner-authorized retained-history routing
// in its caller. It never lowers the highest accepted sequence or changes the
// latest complete pointer. Ordinary Begin retains its strict rollback guard.
// Catch-up verifies each complete catalog independently and does not require
// every intervening catalog to remain available.
func (r *Replica) BeginHistorical(ctx context.Context, raw []byte) (string, error) {
	c, e := VerifyCatalog(raw, r.trust)
	if e != nil {
		return "", e
	}
	id := Hash(raw)
	e = r.locked(ctx, func(s *state) error {
		if _, ok := s.Generations[id]; ok {
			_, _, e := r.get(s, id, true)
			return e
		}
		if c.Sequence >= s.HighestSequence {
			return ErrRollback
		}
		_, retired, e := r.retention(s)
		if e != nil {
			return e
		}
		if retired[id] {
			return ErrProtected
		}
		for existing, item := range s.Generations {
			if item.Sequence == c.Sequence && existing != id {
				return ErrConflict
			}
		}
		if len(s.Generations) >= MaxGenerations {
			return statefile.ErrCapacity
		}
		if e = r.putCatalog(id, raw); e != nil {
			return e
		}
		s.Generations[id] = entry{Sequence: c.Sequence, Bytes: len(raw)}
		s.Revision++
		if e = r.save(*s); e != nil {
			return e
		}
		return r.point("historical-catalog-durable")
	})
	return id, e
}

// Inventory describes recorded publications, not a fresh ciphertext scrub.
// Clients must authenticate each fetched catalog and its dependency closure.
type InventoryEntry struct {
	Generation string `json:"generation"`
	Sequence   uint64 `json:"sequence"`
}

func (r *Replica) Inventory(ctx context.Context) ([]InventoryEntry, error) {
	out := []InventoryEntry{}
	e := r.locked(ctx, func(s *state) error {
		for id, item := range s.Generations {
			if item.Complete {
				out = append(out, InventoryEntry{id, item.Sequence})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
		return ctx.Err()
	})
	return out, e
}
