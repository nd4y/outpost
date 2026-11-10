package ingress

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
)

type queuedStagingImport struct {
	Origin   stagingOrigin  `json:"origin"`
	Object   filekit.Object `json:"object"`
	Fallback *stagingOrigin `json:"fallback,omitempty"`
}

func (g *Registry) queueStagedImport(ctx context.Context, target Intent, raw []byte, request queuedStagingImport) error {
	primary, _, err := g.stagingPeer(target, request.Origin)
	if err != nil {
		return err
	}
	if request.Fallback != nil {
		fallback, _, err := g.stagingPeer(target, *request.Fallback)
		if err != nil || fallback.Ingress == primary.Ingress {
			return ErrDenied
		}
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
		if _, err := s.read(ctx, request.Object); !errors.Is(err, os.ErrNotExist) {
			return err
		}
		pending := s.state.PendingImport
		if pending != nil {
			if pending.Object != request.Object {
				return ErrConflict
			}
			if sameStagingOrigin(&pending.Origin, &request.Origin) && sameStagingOrigin(pending.Fallback, request.Fallback) {
				return nil
			}
			// The current view must withdraw the original origin before
			// the source can bind this exact object to another route.
			var previous Intent
			if canonicalIntent(pending.Origin.Intent, pending.Origin.Authority, g.options.Owner, &previous) != nil ||
				g.options.Staging.Origins[previous.Ingress] != "" {
				return ErrConflict
			}
		}
		s.state.PendingImport = &request
		if err := s.save(); err != nil {
			s.state.PendingImport = pending
			return err
		}
		return s.point("capture-staged-import-queued")
	})
}

// AdvanceStagedImport executes one source-admitted request under the current
// worker view. Retrying after a lost response reuses the accepted object.
func (g *Registry) AdvanceStagedImport(ctx context.Context, paused func(string) bool) (bool, error) {
	if g.options.Staging == nil || len(g.options.Settlement) != 0 || !g.mu.TryLock() {
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
	raw := bytes.Clone(g.state.Intent)
	// The previous attempt may have stored the object before losing its
	// reply or crashing. Completing that record needs no network route.
	err = os.ErrNotExist
	if s.has(generation.Object{ID: pending.Object.ID, Bytes: pending.Object.Bytes}) {
		_, err = s.Read(bounded, pending.Object)
	}
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			g.mu.Unlock()
			return false, err
		}
		if len(g.options.Staging.Origins) == 0 {
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
		g.mu.Unlock()
		if err = g.importStaged(bounded, intent, raw, pending.Origin, pending.Fallback, pending.Object, false); err != nil {
			return false, err
		}
		g.mu.Lock()
	}
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
