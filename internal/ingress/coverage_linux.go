package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
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

// CoverageHolder assigns an opaque object to one of two fixed holders. The
// order of bootstrap endpoints and retries cannot change ownership.
func CoverageHolder(id, first, second string) string {
	if first > second {
		first, second = second, first
	}
	if len(id) > 0 && strings.Contains("02468ace", id[:1]) {
		return first
	}
	return second
}

func CoverageDependencies(refs []generation.Object, holder, other string) []generation.Object {
	if other == "" {
		return refs
	}
	assigned := make([]generation.Object, 0, len(refs)/2)
	for _, ref := range refs {
		if CoverageHolder(ref.ID, holder, other) == holder {
			assigned = append(assigned, ref)
		}
	}
	return assigned
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

type partitionRequest struct {
	Catalog json.RawMessage `json:"catalog"`
	Origin  stagingOrigin   `json:"origin"`
}

func (s *Session) stageCoverage(ctx context.Context, raw []byte, origin *stagingOrigin, other string) (CoverageReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs, err := s.catalogDependencies(ctx, raw)
	if err != nil {
		return CoverageReceipt{}, err
	}
	refs = CoverageDependencies(refs, s.intent.Ingress, other)
	for _, ref := range refs {
		if !s.has(ref) {
			return CoverageReceipt{}, ErrIncomplete
		}
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
		previous, _ := json.Marshal(s.state.CoveragePeer)
		candidate, _ := json.Marshal(origin)
		if !bytes.Equal(previous, candidate) {
			return CoverageReceipt{}, ErrConflict
		}
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
	old := s.state
	s.state.Catalog = bytes.Clone(raw)
	s.state.Coverage, s.state.CoveragePeer = &receipt, origin
	if err = s.save(); err != nil {
		s.state = old
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
func (g *Registry) serveCoverage(w http.ResponseWriter, r *http.Request, intent Intent, remoteExpiry time.Time, partition bool) {
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
	max := generation.MaxCatalog
	if partition {
		max = maxSessionDocument
	}
	raw, err := readBody(w, r, max)
	if err != nil {
		fail(w, err)
		return
	}
	var origin *stagingOrigin
	var holder string
	if partition {
		var request partitionRequest
		if decodeReply(raw, &request) != nil {
			fail(w, ErrProtocol)
			return
		}
		i, _, err := g.stagingPeer(intent, request.Origin)
		if err != nil || !g.options.Staging.Readers[i.Ingress] {
			fail(w, ErrDenied)
			return
		}
		raw, origin, holder = request.Catalog, &request.Origin, i.Ingress
	}
	receipt, err := g.session.stageCoverage(ctx, raw, origin, holder)
	if err != nil {
		fail(w, err)
		return
	}
	jsonReply(w, http.StatusOK, receipt)
}

// StageCoverage accepts an mTLS observation bound to this holder's exact
// signed intent and catalog. It has no COMPLETE or cleanup authority.
func (c *Client) StageCoverage(ctx context.Context, raw []byte, other *Client) (CoverageReceipt, error) {
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
	payload, resource := raw, "coverage"
	if other != nil {
		if other.intent.Ingress == c.intent.Ingress || !sameCapture(c.intent, other.intent) {
			return receipt, ErrDenied
		}
		refs = CoverageDependencies(refs, c.intent.Ingress, other.intent.Ingress)
		payload, err = json.Marshal(partitionRequest{
			Catalog: raw, Origin: stagingOrigin{Authority: other.authority, Intent: other.intentRaw},
		})
		if err != nil {
			return receipt, err
		}
		resource = "partition"
	}
	status, _, response, err := c.request(ctx, http.MethodPut, resource, nil, payload, 4096)
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
	locked := true
	defer func() {
		if locked {
			g.mu.Unlock()
		}
	}()
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
	if origin := s.state.CoveragePeer; origin != nil {
		peer, _, err := g.stagingPeer(i, *origin)
		if err != nil || !g.options.Staging.Readers[peer.Ingress] {
			return false, ErrDenied
		}
		refs, err := s.catalogDependencies(bounded, s.state.Catalog)
		if err != nil {
			return false, err
		}
		for s.assemblyNext < len(refs) {
			object := refs[s.assemblyNext]
			if s.has(object) {
				s.assemblyNext++
				continue
			}
			if CoverageHolder(object.ID, i.Ingress, peer.Ingress) != peer.Ingress {
				return false, ErrIncomplete
			}
			intent := bytes.Clone(g.state.Intent)
			g.mu.Unlock()
			locked = false
			ref := filekit.Object{ID: object.ID, Bytes: object.Bytes}
			err = g.importStaged(bounded, i, intent, *origin, ref, true)
			return err == nil, err
		}
	}
	_, _, err = s.FinishBatch(bounded, s.state.Catalog, 1, generation.MaxObject)
	return err == nil, err
}
