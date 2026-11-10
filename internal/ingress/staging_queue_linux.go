package ingress

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
)

type queuedStagingImport struct {
	Origin stagingOrigin  `json:"origin"`
	Object filekit.Object `json:"object"`
}

func (g *Registry) queueStagedImport(ctx context.Context, target Intent, raw []byte, origin stagingOrigin, ref filekit.Object) error {
	if _, _, err := g.stagingPeer(target, origin); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.withStagingSession(ctx, raw, func(s *Session) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.guard(ctx); err != nil {
			return err
		}
		if s.state.Complete || len(s.state.Catalog) != 0 {
			return ErrConflict
		}
		if _, err := s.read(ctx, ref); !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if pending := s.state.PendingImport; pending != nil {
			if pending.Object == ref && bytes.Equal(pending.Origin.Authority, origin.Authority) && bytes.Equal(pending.Origin.Intent, origin.Intent) {
				return nil
			}
			return ErrConflict
		}
		s.state.PendingImport = &queuedStagingImport{Origin: origin, Object: ref}
		if err := s.save(); err != nil {
			s.state.PendingImport = nil
			return err
		}
		return nil
	})
}

// AdvanceStagedImport executes one source-admitted request under the current
// worker view. Retrying after a lost response reuses the accepted object.
func (g *Registry) AdvanceStagedImport(ctx context.Context, paused func(string) bool) (bool, error) {
	if g.options.Staging == nil || len(g.options.Staging.Origins) == 0 || len(g.options.Settlement) != 0 || !g.mu.TryLock() {
		return false, nil
	}
	now := time.Now()
	intent, deadline, err := g.stagingIntent(now)
	if g.poisoned || err != nil || now.Unix() < g.state.ObservedUnix ||
		now.Before(g.leaf.NotBefore) || !now.Before(g.leaf.NotAfter) || paused(intent.Operation) {
		g.mu.Unlock()
		return false, nil
	}
	if g.leaf.NotAfter.Before(deadline) {
		deadline = g.leaf.NotAfter
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	s, err := g.stagingSession(bounded)
	if err != nil {
		g.mu.Unlock()
		return false, err
	}
	pending := s.state.PendingImport
	if pending == nil || s.state.Complete || len(s.state.Catalog) != 0 {
		g.mu.Unlock()
		return false, nil
	}
	select {
	case g.stageImports <- struct{}{}:
		defer func() { <-g.stageImports }()
	default:
		g.mu.Unlock()
		return false, nil
	}
	raw := bytes.Clone(g.state.Intent)
	g.mu.Unlock()

	if err = g.importStaged(bounded, intent, raw, pending.Origin, pending.Object, false); err != nil {
		return false, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	err = g.withStagingSession(bounded, raw, func(s *Session) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.state.PendingImport != pending {
			return nil
		}
		if err := s.guard(bounded); err != nil {
			return err
		}
		s.state.PendingImport = nil
		if err := s.save(); err != nil {
			s.state.PendingImport = pending
			return err
		}
		return nil
	})
	return err == nil, err
}
