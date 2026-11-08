package ingress

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

// CoverageReceipt records durable staged dependency inventory. Publication
// still requires a full ciphertext readback through the replica verifier.
type CoverageReceipt struct {
	Holder       string `json:"holder"`
	Intent       string `json:"intent"`
	Generation   string `json:"generation"`
	Dependencies string `json:"dependencies"`
	Objects      int    `json:"objects"`
	AcceptedUnix int64  `json:"acceptedUnix"`
}

func DependencyDigest(refs []generation.Object) string {
	raw, _ := json.Marshal(refs)
	return storage.Hash(raw)
}

func (r CoverageReceipt) matches(i Intent, raw []byte) bool {
	return r.Holder == i.Ingress && r.Intent == storage.Hash(raw) &&
		storage.ID(r.Generation) && storage.ID(r.Dependencies) &&
		r.Objects >= 0 && r.Objects <= generation.MaxObjects &&
		r.AcceptedUnix >= i.NotBefore && r.AcceptedUnix < i.ExpiresUnix
}

func (s *Session) stageCoverage(ctx context.Context, raw []byte) (CoverageReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs, err := s.prepare(ctx, raw)
	if err != nil {
		return CoverageReceipt{}, err
	}
	for _, ref := range refs {
		if err = ctx.Err(); err != nil {
			return CoverageReceipt{}, err
		}
		if s.refs[ref.ID] != ref {
			continue // already protected by the independently accepted base pin
		}
		info, statErr := s.objectRoot.Lstat(ref.ID)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != int64(ref.Bytes) {
			return CoverageReceipt{}, ErrIncomplete
		}
	}
	if s.state.Coverage != nil {
		return *s.state.Coverage, nil
	}
	if err = s.guard(ctx); err != nil {
		return CoverageReceipt{}, err
	}
	// The catalog, fsynced staged objects and pinned predecessor together
	// form the dependency closure. This slot cannot be replaced or cleaned
	// until the full replica is independently accepted and acknowledged.
	receipt := CoverageReceipt{
		Holder: s.intent.Ingress, Intent: storage.Hash(s.state.Intent),
		Generation: storage.Hash(raw), Dependencies: DependencyDigest(refs),
		Objects: len(refs), AcceptedUnix: s.state.LastObserved,
	}
	s.state.Coverage = &receipt
	if err = s.save(); err != nil {
		s.state.Coverage = nil
		return CoverageReceipt{}, err
	}
	return receipt, s.point("capture-coverage-durable")
}

func (g *Registry) coverageEnabled() bool {
	if routes := g.options.Staging; routes != nil && len(g.options.Settlement) == 0 {
		for origin := range routes.Origins {
			if routes.Readers[origin] {
				return true
			}
		}
	}
	return false
}

// serveCoverage is called under the registry lock after source authentication.
func (g *Registry) serveCoverage(w http.ResponseWriter, r *http.Request, intent Intent, remoteExpiry time.Time) {
	if !g.coverageEnabled() {
		fail(w, ErrDenied)
		return
	}
	deadline, _ := r.Context().Deadline()
	for _, expiry := range []time.Time{g.leaf.NotAfter, remoteExpiry, time.Unix(intent.ExpiresUnix, 0)} {
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}
	ctx, stop, err := requestLifetime(w, r.Context(), deadline)
	if err != nil {
		fail(w, err)
		return
	}
	defer stop()
	raw, err := readBody(w, r, generation.MaxCatalog)
	if err != nil {
		fail(w, err)
		return
	}
	receipt, err := g.session.stageCoverage(ctx, raw)
	if err != nil {
		fail(w, err)
		return
	}
	jsonReply(w, http.StatusOK, receipt)
}

// StageCoverage accepts an mTLS observation bound to this holder's exact
// signed intent and catalog. It has no COMPLETE or cleanup authority.
func (c *Client) StageCoverage(ctx context.Context, raw []byte) (CoverageReceipt, error) {
	var receipt CoverageReceipt
	a, err := VerifyAuthority(c.authority, c.owner, time.Now())
	if err != nil {
		return receipt, err
	}
	catalog, err := generation.VerifyCatalog(raw, a.Trust)
	if err != nil || !c.intent.matches(catalog) {
		return receipt, ErrDenied
	}
	refs, err := generation.Dependencies(raw, a.Trust)
	if err != nil {
		return receipt, err
	}
	status, _, response, err := c.request(ctx, http.MethodPut, "coverage", nil, raw, 4096)
	if err != nil {
		return receipt, err
	}
	if status != http.StatusOK || decodeReply(response, &receipt) != nil ||
		!receipt.matches(c.intent, c.intentRaw) || receipt.AcceptedUnix > time.Now().Unix() ||
		receipt.Generation != storage.Hash(raw) || receipt.Objects != len(refs) ||
		receipt.Dependencies != DependencyDigest(refs) {
		return CoverageReceipt{}, ErrProtocol
	}
	return receipt, nil
}

// AdvanceCoverage resumes only an existing, staged catalog. It never admits
// an intent, opens a source view, or acknowledges a receipt.
func (g *Registry) AdvanceCoverage(ctx context.Context, paused func(string) bool) (bool, error) {
	if !g.coverageEnabled() || !g.mu.TryLock() {
		return false, nil
	}
	defer g.mu.Unlock()
	if g.poisoned || len(g.state.Intent) == 0 {
		return false, nil
	}
	now := time.Now()
	i, _, err := VerifyIntent(g.state.Intent, g.options.Authority, g.options.Owner, now)
	if err != nil || now.Unix() < g.state.ObservedUnix || paused(i.Operation) {
		return false, nil
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(i.ExpiresUnix, 0))
	defer cancel()
	s, err := g.stagingSession(bounded)
	if err != nil {
		return false, err
	}
	// All access to a registry-owned session is serialized by g.mu.
	if s.state.Coverage == nil || s.state.Complete || s.state.Acknowledged {
		return false, nil
	}
	_, _, err = s.FinishBatch(bounded, s.state.Catalog, 1, generation.MaxObject)
	return err == nil, err
}
