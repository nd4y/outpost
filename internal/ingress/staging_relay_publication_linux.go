package ingress

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const relayCatalogResource = "relay-catalog"
const relayObjectPrefix = "relay-objects/"

func (g *Registry) relayPayload(ctx context.Context, reader, operation, resource, size string) ([]byte, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	i, _, err := g.stagingIntent(now)
	if g.poisoned || err != nil || now.Unix() < g.state.ObservedUnix || operation != i.Operation {
		return nil, "", ErrDenied
	}
	s, err := g.stagingSession(ctx)
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.guard(ctx); err != nil {
		return nil, "", err
	}
	if _, ok := s.currentRelayOffer(reader, g.authority, time.Now()); !ok || !s.state.Complete || s.state.Receipt == nil {
		return nil, "", ErrDenied
	}
	id := s.state.Receipt.Generation
	if resource == relayCatalogResource {
		raw, err := s.replica.Catalog(ctx, id)
		return raw, "application/json", err
	}
	length, err := strconv.Atoi(size)
	ref := filekit.Object{ID: strings.TrimPrefix(resource, relayObjectPrefix), Bytes: length}
	if err != nil || strconv.Itoa(length) != size || !validObject(ref) {
		return nil, "", ErrDenied
	}
	raw, err := s.replica.ReadObject(ctx, id, generation.Object{ID: ref.ID, Bytes: ref.Bytes})
	return raw, "application/octet-stream", err
}

// AdvanceRelayedPublication imports only dependencies of the bridge's
// verified signed catalog and materializes the normal independent replica.
func (g *Registry) AdvanceRelayedPublication(ctx context.Context, paused func(string) bool) (bool, error) {
	if !g.options.RelayOnly || len(g.relayOrigins) == 0 || !g.mu.TryLock() {
		return false, nil
	}
	now := time.Now()
	i, deadline, err := g.stagingIntent(now)
	if g.poisoned || err != nil || now.Unix() < g.state.ObservedUnix || paused(i.Operation) || now.Before(g.leaf.NotBefore) || !now.Before(g.leaf.NotAfter) {
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
	if s.state.Acknowledged {
		defer g.mu.Unlock()
		if len(s.refs) == 0 {
			return false, nil
		}
		_, err := s.Acknowledge(bounded, *s.state.Receipt, 256)
		return err == nil, err
	}
	select {
	case g.stageImports <- struct{}{}:
		defer func() { <-g.stageImports }()
	default:
		g.mu.Unlock()
		return false, nil
	}
	origin := g.relayOrigins[g.nextRelayOrigin]
	g.nextRelayOrigin = (g.nextRelayOrigin + 1) % len(g.relayOrigins)
	intentRaw, catalog := bytes.Clone(g.state.Intent), s.state.Catalog
	g.mu.Unlock()
	relay, _, err := g.readRelayOffer(bounded, origin)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(relay.Offer.Intent, intentRaw) || relay.Generation == "" {
		return false, nil
	}
	if !storage.ID(relay.Generation) {
		return false, ErrProtocol
	}
	if len(catalog) == 0 {
		catalog, err = g.readStagingDocument(bounded, origin, route(i)+"/"+relayCatalogResource, nil, generation.MaxCatalog)
		if err != nil {
			return false, err
		}
	}
	if storage.Hash(catalog) != relay.Generation {
		return false, ErrConflict
	}
	var missing generation.Object
	advanced := false
	g.mu.Lock()
	err = g.withStagingSession(bounded, intentRaw, func(s *Session) error {
		if s.state.Acknowledged {
			return nil
		}
		if s.state.Complete {
			if !relay.Acknowledged {
				return nil
			}
			_, err := s.Acknowledge(bounded, *s.state.Receipt, 256)
			advanced = err == nil
			return err
		}
		missing, err = s.relayDependency(bounded, catalog)
		if err != nil || missing.ID != "" {
			return err
		}
		_, _, err = s.FinishBatch(bounded, catalog, 1, generation.MaxObject)
		advanced = err == nil
		return err
	})
	g.mu.Unlock()
	if err != nil || missing.ID == "" {
		return advanced, err
	}
	headers := http.Header{}
	headers.Set("Outpost-Bytes", strconv.Itoa(missing.Bytes))
	b, err := g.readStagingResponse(bounded, origin, route(i)+"/"+relayObjectPrefix+missing.ID, headers, "application/octet-stream", missing.Bytes)
	if err != nil {
		return false, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	err = g.withStagingSession(bounded, intentRaw, func(s *Session) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !bytes.Equal(s.state.Catalog, catalog) {
			return ErrConflict
		}
		_, err := s.write(bounded, filekit.Object{ID: missing.ID, Bytes: missing.Bytes}, b, true)
		return err
	})
	return err == nil, err
}

func (s *Session) relayDependency(ctx context.Context, catalog []byte) (generation.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs, err := s.catalogDependencies(ctx, catalog)
	if err != nil {
		return generation.Object{}, err
	}
	if err = s.checkPublication(ctx, catalog, refs); err != nil {
		return generation.Object{}, err
	}
	if len(s.state.Catalog) == 0 {
		s.state.Catalog, s.catalogRefs = bytes.Clone(catalog), refs
		if err = s.save(); err != nil {
			s.state.Catalog, s.catalogRefs = nil, nil
			return generation.Object{}, err
		}
		if err = s.point("capture-catalog-durable"); err != nil {
			return generation.Object{}, err
		}
	}
	for s.assemblyNext < len(refs) {
		ref := refs[s.assemblyNext]
		if !s.has(ref) {
			return ref, nil
		}
		s.assemblyNext++
	}
	return generation.Object{}, nil
}
