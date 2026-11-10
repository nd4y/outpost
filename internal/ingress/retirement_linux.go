package ingress

import (
	"bytes"
	"context"
	"net/http"
	"time"
)

const UnsealedRetired = "UNSEALED_RETIRED"

func (s *Session) unsealed() bool {
	return len(s.state.Catalog) == 0 && s.state.Coverage == nil && s.state.CoveragePeer == nil &&
		len(s.state.PublicationGrants) == 0 && !s.state.Complete && s.state.Receipt == nil &&
		!s.state.Acknowledged && len(s.state.Reclaimed) == 0
}

func (s *Session) validRetirement() bool {
	grant, err := VerifySettlement(s.state.Retired, s.state.Authority, s.state.Intent, s.owner, time.Unix(s.state.LastObserved, 0))
	return err == nil && grant.Purpose == SettlementRetireUnsealed && s.unsealed()
}

// The registry lease and request mutex exclude ordinary ingress while the
// exact unsealed slot is fenced. Keep its ciphertext and pins at this step.
func (g *Registry) retireUnsealed(ctx context.Context, i Intent, grant Settlement) (Reconciliation, error) {
	if grant.Purpose != SettlementRetireUnsealed {
		return Reconciliation{}, ErrDenied
	}
	if !bytes.Equal(g.state.Intent, g.options.SettlementIntent) {
		result, err := g.reconcile(ctx, i, grant)
		if err == nil && result.Phase != "NOT_ADMITTED" {
			err = ErrConflict
		}
		return result, err
	}
	if err := g.checkPredecessor(ctx, i); err != nil {
		return Reconciliation{}, err
	}
	options := g.sessionOptions(g.state.Intent)
	options.Initialize = false
	s, err := openSessionFor(ctx, options, sessionInspect)
	if err != nil {
		return Reconciliation{}, err
	}
	defer s.Close()
	now := time.Now()
	if !s.unsealed() || now.Unix() < s.state.LastObserved {
		return Reconciliation{}, ErrConflict
	}
	if ctx.Err() != nil || !active(now, grant.NotBefore, grant.ExpiresUnix) {
		return Reconciliation{}, ErrDenied
	}
	if len(s.state.Retired) == 0 {
		s.state.Retired = bytes.Clone(g.options.Settlement)
		s.state.PendingImport = nil
		s.state.LastObserved = now.Unix()
		if err = s.save(); err != nil {
			return Reconciliation{}, err
		}
		if err = g.point("capture-unsealed-retirement-durable"); err != nil {
			return Reconciliation{}, err
		}
	}
	now = time.Now()
	if ctx.Err() != nil || !active(now, grant.NotBefore, grant.ExpiresUnix) {
		return Reconciliation{}, ErrDenied
	}
	return Reconciliation{Grant: grant.ID, Intent: grant.Intent, Receiver: i.Ingress, Phase: UnsealedRetired, ObservedUnix: now.Unix()}, nil
}

func (c *Client) RetireUnsealed(ctx context.Context) (Reconciliation, error) {
	grant, err := VerifySettlement(c.settlement, c.authority, c.intentRaw, c.owner, time.Now())
	if err != nil || grant.Purpose != SettlementRetireUnsealed {
		return Reconciliation{}, ErrDenied
	}
	result, err := c.reconciliation(ctx, http.MethodPut, "retire")
	if err == nil && result.Phase != UnsealedRetired && result.Phase != "NOT_ADMITTED" {
		err = ErrProtocol
	}
	return result, err
}
