package managementservice

import (
	"context"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/management"
)

const initializationFormat = "outpost-management-initialization-1"

// initialize runs under the service execution lease. Pending and admitted
// profiles share one atomic file but have separate signature purposes.
func (s *Service) initialize(ctx context.Context, options management.Options, fault func(string) error) error {
	if e := s.guard(ctx); e != nil {
		return e
	}
	var pending serviceState
	raw, e := s.state.Read("profile.json")
	switch {
	case errors.Is(e, os.ErrNotExist):
		if _, e = localfs.Stat(s.root, "registry"); !errors.Is(e, os.ErrNotExist) {
			return management.ErrConflict
		}
		capacity, e := s.budget.Status(ctx)
		if e != nil {
			return e
		}
		if len(capacity.Pending) > 0 {
			if e = s.budget.Reconcile(ctx, s.p.Limits); e != nil {
				return e
			}
		}
		pending = s.newProfileState(initializationFormat)
		if e = s.writeProfile(pending); e != nil {
			return e
		}
	case e != nil:
		return e
	default:
		pending, e = s.decodeProfile(raw, initializationFormat, true)
		if e != nil {
			return e
		}
		if e = s.budget.Reconcile(ctx, s.p.Limits); e != nil {
			return e
		}
	}
	if fault != nil {
		if e = fault("management-initialization-profile-durable"); e != nil {
			return e
		}
	}
	s.registry, e = management.InitializeRegistry(ctx, options)
	if e != nil {
		return e
	}
	if fault != nil {
		if e = fault("management-initialization-registry-durable"); e != nil {
			return e
		}
	}
	if e = s.guard(ctx); e != nil {
		return e
	}
	pending.Format = Format
	return s.writeProfile(pending)
}
