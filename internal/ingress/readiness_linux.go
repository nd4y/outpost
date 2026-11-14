package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

func (g *Registry) checkPredecessor(ctx context.Context, i Intent) error {
	status, err := g.options.Replica.Status(ctx)
	if err != nil {
		return err
	}
	if status.HighestSequence != i.Sequence-1 || status.LatestComplete != i.Parent {
		return ErrConflict
	}
	return nil
}

// checkAdmission is read-only. The actual admission repeats it under the
// registry mutex before committing the receiver's immutable intent fence.
func (g *Registry) checkAdmission(ctx context.Context, raw []byte, i Intent) error {
	now := time.Now().Unix()
	if g.poisoned || now < g.state.ObservedUnix {
		return ErrConflict
	}
	if bytes.Equal(g.state.Intent, raw) {
		fenced, err := g.slotFenced(raw)
		if fenced {
			return ErrConflict
		}
		return err
	}
	if err := g.checkNewIntent(ctx, i, now); err != nil {
		return err
	}
	if g.options.CheckRegistryWrite == nil {
		return nil
	}
	next, err := json.Marshal(g.nextRegistryState(raw))
	if err != nil {
		return err
	}
	return g.options.CheckRegistryWrite(ctx, len(next))
}

func (g *Registry) checkNewIntent(ctx context.Context, i Intent, now int64) error {
	if err := g.checkPredecessor(ctx, i); err != nil {
		return err
	}
	if len(g.state.Intent) == 0 {
		return nil
	}
	var previous Intent
	if canonicalIntent(g.state.Intent, g.intentAuthority(), g.options.Owner, &previous) != nil || i.Sequence < previous.Sequence {
		return ErrConflict
	}
	s := g.session
	if s == nil {
		options := g.sessionOptions(g.state.Intent)
		options.Initialize = false
		var err error
		s, err = openSessionFor(ctx, options, sessionInspect)
		if err != nil {
			return err
		}
		defer s.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Retired) != 0 {
		if i.Sequence != previous.Sequence || i.Parent != previous.Parent || i.Operation == previous.Operation ||
			now < s.state.LastObserved || !s.validRetirement() {
			return ErrConflict
		}
		return nil
	}
	if i.Sequence == previous.Sequence {
		return ErrConflict
	}
	if len(s.state.Reclaimed) != 0 {
		grant, err := verifyReclaim(s.state.Reclaimed, g.state.Intent, g.authority.Trust.Writer)
		if err != nil || now < s.state.LastObserved || i.Sequence == previous.Sequence+1 && i.Parent != grant.Generation {
			return ErrConflict
		}
		empty, err := s.slotEmpty()
		if err != nil || !empty {
			return errors.Join(ErrConflict, err)
		}
		return nil
	}
	if !s.state.Acknowledged || s.state.Receipt == nil || now < s.state.LastObserved ||
		i.Sequence == previous.Sequence+1 && i.Parent != s.state.Receipt.Generation {
		return ErrConflict
	}
	return nil
}

func (c *Client) Ready(ctx context.Context) error {
	status, _, raw, err := c.request(ctx, http.MethodPut, "readiness", nil, c.intentRaw, 4096)
	if err != nil {
		return err
	}
	var reply struct {
		Operation string
		Sequence  uint64
	}
	if status != http.StatusOK || decodeReply(raw, &reply) != nil || reply.Operation != c.intent.Operation || reply.Sequence != c.intent.Sequence {
		return ErrProtocol
	}
	return nil
}
