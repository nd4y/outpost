package generation

import (
	"context"
	"errors"
	"sort"
	"time"
)

const RetentionSelectionFormat = "outpost-retention-selection-1"

type RetentionSelection struct {
	Format        string `json:"format"`
	Operation     string `json:"operation"`
	KeepLatest    int    `json:"keepLatest"`
	OlderThanUnix int64  `json:"olderThanUnix"`
	MaxRetire     int    `json:"maxRetire"`
	StartUnix     int64  `json:"startUnix"`
	ExpiresUnix   int64  `json:"expiresUnix"`
}

// PreviewRetention uses the accepted local index and signed catalog ages.
// A returned permit is unsigned. It cannot authorize physical maintenance.
func (r *Replica) PreviewRetention(ctx context.Context, node string, selection RetentionSelection) (*Permit, error) {
	now := time.Now().Unix()
	p := Permit{Format: PermitWindowFormat, Domain: r.trust.Domain, Repository: r.trust.Repository, Epoch: r.trust.Epoch, Operation: selection.Operation,
		Window: &PermitWindow{Node: node, StartUnix: selection.StartUnix, ExpiresUnix: selection.ExpiresUnix}}
	if !validPermit(p) || selection.Format != RetentionSelectionFormat || selection.KeepLatest < 1 || selection.KeepLatest > MaxGenerations || selection.MaxRetire < 1 || selection.MaxRetire > MaxGenerations || selection.OlderThanUnix < 1 || selection.OlderThanUnix > now || selection.ExpiresUnix <= now {
		return nil, ErrInvalid
	}
	e := r.exclusive(ctx, func() error {
		s, e := r.load()
		if e != nil {
			return e
		}
		if _, _, e = r.retention(&s); e != nil {
			return e
		}
		if len(s.CatalogDamage) > 0 {
			return ErrCatalogUnavailable
		}
		complete := make([]string, 0, len(s.Generations))
		for id, item := range s.Generations {
			if item.Damaged {
				return ErrIncomplete
			}
			if item.Complete {
				complete = append(complete, id)
			}
		}
		sort.Slice(complete, func(i, j int) bool { return s.Generations[complete[i]].Sequence > s.Generations[complete[j]].Sequence })
		pins := map[string]bool{}
		for _, pin := range s.Pins {
			pins[pin.Generation] = true
		}
		p.Revision = s.Revision
		for i := len(complete) - 1; i >= selection.KeepLatest && len(p.Retire) < selection.MaxRetire; i-- {
			if e = ctx.Err(); e != nil {
				return e
			}
			id := complete[i]
			if pins[id] {
				continue
			}
			catalog, _, e := r.catalogEntry(id, s.Generations[id], true)
			if e != nil {
				return errors.Join(ErrCatalogUnavailable, e)
			}
			if catalog.SnapshotUnix < selection.OlderThanUnix {
				p.Retire = append(p.Retire, id)
			}
		}
		sort.Strings(p.Retire)
		return nil
	})
	if e != nil || len(p.Retire) == 0 {
		return nil, e
	}
	return &p, nil
}
