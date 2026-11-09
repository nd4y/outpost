package ingress

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func (r Receipt) matches(i Intent) bool {
	return r.Operation == i.Operation && r.Ingress == i.Ingress && r.Tenant == i.Tenant && r.Domain == i.Domain && storage.ID(r.Generation) && r.NewBytes >= 0 && r.NewBytes <= i.MaxBytes && r.NewObjects >= 0 && r.NewObjects <= i.MaxObjects && r.VerifiedAt >= i.NotBefore
}

// VerifyReceipt retains the real verification timestamp and requires the
// original owner grant for a publication completed after capture expiry.
func VerifyReceipt(r Receipt, i Intent, authority, intent []byte, owner ed25519.PublicKey) bool {
	if !r.matches(i) {
		return false
	}
	if r.VerifiedAt < i.ExpiresUnix {
		return r.PublishedWith == ""
	}
	g, err := VerifySettlement([]byte(r.PublishedWith), authority, intent, owner, time.Unix(r.VerifiedAt, 0))
	return err == nil && g.Purpose == SettlementPublish && g.Generation == r.Generation
}

// Acknowledgement is administrative progress, never a new verification receipt.
// A source must fsync its receipt and recovery checkpoint before acknowledging.
// Cleanup only releases this session's pins and staged copies; generation
// retirement still requires the separate signed maintenance authority.
type Acknowledgement struct {
	Receipt          Receipt `json:"receipt"`
	RemainingObjects int     `json:"remainingObjects"`
	RemainingBytes   int64   `json:"remainingBytes"`
	Clean            bool    `json:"clean"`
}

func (s *Session) Acknowledge(ctx context.Context, receipt Receipt, maxObjects int) (Acknowledgement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Acknowledgement
	if maxObjects < 1 || maxObjects > 256 {
		return result, ErrDenied
	}
	if !s.state.Complete || s.state.Receipt == nil || receipt != *s.state.Receipt {
		return result, ErrConflict
	}
	if e := s.guardMode(ctx, true); e != nil {
		return result, e
	}
	if !s.state.Acknowledged {
		old := s.state
		s.state.Acknowledged = true
		s.state.Catalog = nil
		s.state.Coverage = nil
		s.state.CoveragePeer = nil
		s.state.PublicationGrants = nil
		if e := s.save(); e != nil {
			s.state = old
			return result, e
		}
		if e := s.point("capture-ack-durable"); e != nil {
			return result, e
		}
	}
	return s.cleanupAcknowledged(ctx, maxObjects)
}

// Caller holds the session lock (or exclusively owns this not-yet-served slot).
func (s *Session) cleanupAcknowledged(ctx context.Context, maxObjects int) (Acknowledgement, error) {
	var result Acknowledgement
	if !s.state.Acknowledged || s.state.Receipt == nil {
		return result, ErrConflict
	}
	for _, kind := range []string{"base", "receipt"} {
		if e := s.replica.ReleasePin(ctx, s.pin(kind)); e != nil {
			return result, e
		}
	}
	if e := s.point("capture-ack-unpinned"); e != nil {
		return result, e
	}
	ids := make([]string, 0, len(s.refs))
	for id := range s.refs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > maxObjects {
		ids = ids[:maxObjects]
	}
	for _, id := range ids {
		if e := ctx.Err(); e != nil {
			return result, e
		}
		// Never follow a substituted link, recurse or remove unknown names.
		info, e := s.objectRoot.Lstat(id)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return result, e
		}
		if e == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != int64(s.refs[id].Bytes) {
				return result, ErrConflict
			}
			if s.removeObject != nil {
				e = s.removeObject(ctx, id, info.Size())
			} else {
				e = s.objectRoot.Remove(id)
			}
			if e != nil {
				return result, e
			}
		}
		s.bytes -= int64(s.refs[id].Bytes)
		delete(s.refs, id)
		if e = s.point("capture-staged-object-removed"); e != nil {
			return result, e
		}
	}
	d, e := s.objectRoot.Open(".")
	if e != nil {
		return result, e
	}
	e = errors.Join(d.Sync(), d.Close())
	if e != nil {
		return result, e
	}
	// Interrupted atomic writes are not accepted objects. They remain visible
	// to shared budget reconciliation until explicit orphan maintenance.
	result = Acknowledgement{Receipt: *s.state.Receipt, RemainingObjects: len(s.refs), RemainingBytes: s.bytes, Clean: len(s.refs) == 0}
	return result, nil
}
