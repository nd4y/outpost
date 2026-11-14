package ingress

import (
	"bytes"
	"context"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

// The response advertises the exact durable candidate. A later empty request
// may name that same candidate; it grants neither publication nor verification.
const catalogResumeHeader = "Outpost-Catalog-Resume"

func (s *Session) resumeCatalog(ctx context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !storage.ID(id) {
		return nil, ErrProtocol
	}
	if err := s.guard(ctx); err != nil {
		return nil, err
	}
	if s.state.Acknowledged {
		return nil, ErrConflict
	}
	if len(s.state.Catalog) == 0 {
		return nil, ErrIncomplete
	}
	if len(s.state.Catalog) > generation.MaxCatalog || storage.Hash(s.state.Catalog) != id {
		return nil, ErrConflict
	}
	return bytes.Clone(s.state.Catalog), nil
}
