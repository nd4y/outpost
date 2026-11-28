package sourceagent

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
)

func reclaimTargets(s state) []string { return slices.Sorted(maps.Keys(s.Reclaims)) }

func (a *Agent) reclaimEndpoint(id string) string {
	switch {
	case id == a.anchor.Ingress:
		return a.b.Endpoint
	case a.b.Companion != nil && id == a.companion.Ingress:
		return a.b.Companion.Endpoint
	case a.b.Reserve != nil && id == a.reserve.Ingress:
		return a.b.Reserve.Endpoint
	}
	return ""
}

func (a *Agent) validateReclaims(s state) error {
	if len(s.Reclaims) > 3 || s.ReclaimRecorded && (s.Phase != "COMPLETE" || len(s.Superseded) == 0) ||
		len(s.Reclaims) != 0 && !a.routed() {
		return ErrInvalid
	}
	for id, request := range s.Reclaims {
		i, _, err := request.Verify(a.b.Local.Owner)
		g, grantErr := ingress.VerifyAuthorityDocument(request.Authority, a.b.Local.Owner)
		anchor := a.anchor
		anchor.Ingress = id
		if err != nil || grantErr != nil || !ingress.SameAuthorityScope(anchor, g) ||
			i.Ingress != id || i.Sequence > s.Sequence || a.reclaimEndpoint(id) == "" {
			return ErrInvalid
		}
	}
	return nil
}

func (a *Agent) queueReclaim(s *state) (bool, error) {
	if s.Phase != "COMPLETE" || s.ReclaimRecorded || len(s.Superseded) == 0 {
		return false, nil
	}
	i, err := a.stateIntent(*s)
	if err != nil {
		return false, err
	}
	for _, id := range s.Superseded {
		if slices.Contains(s.Route, id) {
			continue
		}
		old, err := a.routeReceiver(*s, i, id)
		if err != nil {
			return false, err
		}
		request, err := ingress.NewReclaimRequest(old.authority, old.raw, s.Generation, a.b.Local.Owner, a.writer)
		if err != nil {
			return false, err
		}
		if s.Reclaims == nil {
			s.Reclaims = make(map[string]ingress.ReclaimRequest)
		}
		s.Reclaims[id] = request
		s.ReclaimRecorded = true
		return true, nil
	}
	return false, ErrInvalid
}

// Save pending work before sending anything. Failure of this best-effort
// maintenance never withholds the signed source head or an accepted backup.
func (a *Agent) reconcileReclaims(ctx context.Context, s *state) error {
	added, err := a.queueReclaim(s)
	if err != nil {
		return err
	}
	if added {
		if err = a.save(*s); err != nil {
			return err
		}
	}
	changed := false
	for _, id := range reclaimTargets(*s) {
		if ctx.Err() != nil {
			break
		}
		request := s.Reclaims[id]
		client, err := ingress.NewCleanupClient(a.reclaimEndpoint(id), request.Authority, request.Intent,
			a.b.Local.Owner, a.cert, a.roots, peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1})
		if err != nil {
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		for range 8 {
			clean, err := client.ReclaimStep(bounded, request)
			if err != nil {
				break
			}
			if clean {
				delete(s.Reclaims, id)
				changed = true
				break
			}
		}
		cancel()
		client.Close()
	}
	if changed {
		return a.save(*s)
	}
	return nil
}

func (a *Agent) reclaimScheduled(ctx context.Context) error {
	status, err := a.ScheduleStatus(ctx)
	if err != nil || !status.Config.Enabled {
		return err
	}
	return a.lease.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		s, err := a.load()
		if err != nil {
			return err
		}
		return a.reconcileReclaims(ctx, &s)
	})
}
