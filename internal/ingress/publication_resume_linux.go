package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func (g *Registry) stagingIntent(now time.Time) (Intent, time.Time, error) {
	if g.settlementPurpose == SettlementPublish {
		grant, err := VerifySettlement(g.options.Settlement, g.options.Authority, g.options.SettlementIntent, g.options.Owner, now)
		var intent Intent
		if err != nil || !bytes.Equal(g.state.Intent, g.options.SettlementIntent) ||
			canonicalIntent(g.state.Intent, g.options.Authority, g.options.Owner, &intent) != nil {
			return Intent{}, time.Time{}, ErrDenied
		}
		return intent, time.Unix(grant.ExpiresUnix, 0), nil
	}
	intent, _, err := VerifyIntent(g.state.Intent, g.options.Authority, g.options.Owner, now)
	return intent, time.Unix(intent.ExpiresUnix, 0), err
}

func (s *Session) publicationGrant(now time.Time) (Settlement, error) {
	g, err := VerifySettlement(s.publishGrant, s.state.Authority, s.state.Intent, s.owner, now)
	if err != nil || g.Purpose != SettlementPublish || s.state.Acknowledged || len(s.state.Catalog) == 0 ||
		g.Generation != storage.Hash(s.state.Catalog) {
		return Settlement{}, ErrDenied
	}
	return g, nil
}

func (s *Session) recordPublicationGrant() error {
	if s.state.Complete {
		return nil
	}
	for _, raw := range s.state.PublicationGrants {
		if bytes.Equal(raw, s.publishGrant) {
			return nil
		}
	}
	if len(s.state.PublicationGrants) >= maxPublicationGrants {
		return ErrConflict
	}
	s.state.PublicationGrants = append(s.state.PublicationGrants, json.RawMessage(bytes.Clone(s.publishGrant)))
	if err := s.save(); err != nil {
		return err
	}
	return s.point("capture-publication-authority-durable")
}

func (s *Session) originalReceipt(id string, at int64) (Receipt, error) {
	r := Receipt{Operation: s.intent.Operation, Ingress: s.intent.Ingress, Tenant: s.intent.Tenant, Domain: s.intent.Domain,
		Generation: id, NewBytes: s.bytes, NewObjects: len(s.refs), VerifiedAt: at}
	if VerifyReceipt(r, s.intent, s.state.Authority, s.state.Intent, s.owner) {
		return r, nil
	}
	for _, grant := range s.state.PublicationGrants {
		r.PublishedWith = string(grant)
		if VerifyReceipt(r, s.intent, s.state.Authority, s.state.Intent, s.owner) {
			return r, nil
		}
	}
	return Receipt{}, ErrConflict
}

func (s *Session) permitsFinalizationRead(ctx context.Context, identity string, ref filekit.Object, grant []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	origin := s.state.CoveragePeer
	var peer Intent
	if origin == nil || canonicalIntent(origin.Intent, origin.Authority, s.owner, &peer) != nil ||
		peer.Ingress != identity || CoverageHolder(ref.ID, identity, s.intent.Ingress) != s.intent.Ingress {
		return ErrDenied
	}
	selected, err := VerifySettlement(grant, origin.Authority, origin.Intent, s.owner, time.Now())
	if err != nil || selected.Purpose != SettlementPublish || selected.Generation != s.state.Coverage.Generation {
		return ErrDenied
	}
	refs, err := s.catalogDependencies(ctx, s.state.Catalog)
	if err != nil {
		return err
	}
	idx, found := slices.BinarySearchFunc(refs, ref.ID, func(o generation.Object, id string) int {
		return strings.Compare(o.ID, id)
	})
	if !found || refs[idx].Bytes != ref.Bytes {
		return ErrDenied
	}
	return nil
}
