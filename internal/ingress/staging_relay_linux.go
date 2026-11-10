package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/peer"
)

const maxRelayOffers = 4
const relayIntentResource = "relay-intent"
const maxRelayOffer = 2*MaxDocument + 1024
const maxRelayReply = 4*MaxDocument + 2048

type relayOffer struct {
	Recipient string `json:"recipient"`
	stagingOrigin
}

type relayedIntent struct {
	Origin       stagingOrigin `json:"origin"`
	Offer        relayOffer    `json:"offer"`
	Generation   string        `json:"generation,omitempty"`
	Acknowledged bool          `json:"acknowledged,omitempty"`
}

func (o relayOffer) matches(target Intent, authority Authority, owner ed25519.PublicKey, now time.Time) bool {
	i, a, err := VerifyIntent(o.Intent, o.Authority, owner, now)
	if err != nil || i.Ingress != o.Recipient || i.Ingress == target.Ingress || !sameCapture(i, target) {
		return false
	}
	a.Ingress = authority.Ingress
	return SameAuthorityScope(a, authority)
}

func validRelayOffers(offers []relayOffer, target Intent, authority Authority, owner ed25519.PublicKey) bool {
	if len(offers) > maxRelayOffers {
		return false
	}
	seen := make(map[string]bool, len(offers))
	for _, offer := range offers {
		if seen[offer.Recipient] || !offer.matches(target, authority, owner, time.Unix(target.NotBefore, 0)) {
			return false
		}
		seen[offer.Recipient] = true
	}
	return true
}

// OfferRelayIntent sends only the signed downstream admission documents. The
// bridge can retain them for the explicitly permitted recipient to fetch later.
func (c *Client) OfferRelayIntent(ctx context.Context, authority, raw []byte) error {
	i, _, err := VerifyIntent(raw, authority, c.owner, time.Now())
	if err != nil || i.Ingress == c.intent.Ingress || !sameCapture(i, c.intent) {
		return ErrDenied
	}
	offer := relayOffer{Recipient: i.Ingress, stagingOrigin: stagingOrigin{Authority: authority, Intent: raw}}
	payload, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	status, _, _, err := c.request(ctx, http.MethodPut, relayIntentResource, nil, payload, 0)
	if err == nil && status != http.StatusAccepted {
		return ErrProtocol
	}
	return err
}

func (g *Registry) relayPrefix() string {
	return route(Intent{Tenant: g.authority.Tenant, Domain: g.authority.Trust.Domain})
}

func (g *Registry) serveRelayIntent(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, g.relayPrefix()) {
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, g.relayPrefix())
	operation, suffix, put := strings.Cut(path, "/")
	payload := suffix == relayCatalogResource || strings.HasPrefix(suffix, relayObjectPrefix)
	get := path == relayIntentResource || payload
	if !get && (!put || suffix != relayIntentResource) {
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() ||
		r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		fail(w, ErrDenied)
		return true
	}
	remote := r.TLS.PeerCertificates[0]
	id := peer.Identity(remote)
	slots := g.stageImports
	if get {
		slots = g.stageReads
	}
	if get && (r.Method != http.MethodGet || r.ContentLength != 0 || !g.options.Staging.RelayReaders[id]) ||
		!get && (r.Method != http.MethodPut || id != g.authority.Source || g.options.RelayOnly) {
		fail(w, ErrDenied)
		return true
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "busy", http.StatusTooManyRequests)
		return true
	}
	now := time.Now()
	if now.Before(remote.NotBefore) || now.Before(g.leaf.NotBefore) {
		fail(w, ErrDenied)
		return true
	}
	deadline := now.Add(g.options.Limits.Timeout)
	for _, expiry := range []time.Time{remote.NotAfter, g.leaf.NotAfter, time.Unix(g.authority.ExpiresUnix, 0)} {
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}
	g.mu.Lock()
	_, expires, intentErr := g.stagingIntent(now)
	g.mu.Unlock()
	if intentErr == nil && expires.Before(deadline) {
		deadline = expires
	}
	ctx, stop, err := requestLifetime(w, r.Context(), deadline)
	if err != nil {
		fail(w, err)
		return true
	}
	defer stop()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if payload {
		raw, media, err := g.relayPayload(ctx, id, operation, suffix, r.Header.Get("Outpost-Bytes"))
		if err != nil {
			fail(w, err)
		} else {
			w.Header().Set("Content-Type", media)
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			_, _ = w.Write(raw)
		}
		return true
	}
	var offered relayOffer
	if !get {
		body, err := readBody(w, r, maxRelayOffer)
		if err != nil || decodeReply(body, &offered) != nil || !g.options.Staging.RelayReaders[offered.Recipient] {
			fail(w, ErrDenied)
			return true
		}
	}
	response, err := g.relayIntent(ctx, get, id, operation, r.Header.Get("Outpost-Authority"), offered)
	switch {
	case errors.Is(err, os.ErrNotExist):
		w.WriteHeader(http.StatusNoContent)
	case err != nil:
		fail(w, err)
	case get:
		jsonReply(w, http.StatusOK, response)
	default:
		w.WriteHeader(http.StatusAccepted)
	}
	return true
}

func (g *Registry) relayIntent(ctx context.Context, get bool, reader, operation, authority string, offered relayOffer) (relayedIntent, error) {
	var response relayedIntent
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if get && len(g.state.Intent) == 0 {
		return response, os.ErrNotExist
	}
	i, _, err := g.stagingIntent(now)
	if g.poisoned || err != nil || now.Unix() < g.state.ObservedUnix ||
		!get && (i.Operation != operation || i.Authority != authority || !offered.matches(i, g.authority, g.options.Owner, now)) {
		return response, ErrDenied
	}
	s, err := g.stagingSession(ctx)
	if err != nil {
		return response, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.guard(ctx); err != nil {
		return response, err
	}
	if get {
		previous, ok := s.currentRelayOffer(reader, g.authority, time.Now())
		if !ok {
			return response, os.ErrNotExist
		}
		response = relayedIntent{Origin: stagingOrigin{Authority: s.state.Authority, Intent: s.state.Intent}, Offer: previous, Acknowledged: s.state.Acknowledged}
		if s.state.Receipt != nil {
			response.Generation = s.state.Receipt.Generation
		}
		return response, nil
	}
	for _, previous := range s.state.RelayOffers {
		if previous.Recipient == offered.Recipient {
			if sameStagingOrigin(&previous.stagingOrigin, &offered.stagingOrigin) {
				return response, nil
			}
			return response, ErrConflict
		}
	}
	if s.state.Acknowledged || len(s.state.RelayOffers) >= maxRelayOffers {
		return response, ErrConflict
	}
	previous := s.state.RelayOffers
	s.state.RelayOffers = append(previous, offered)
	if err = s.save(); err != nil {
		s.state.RelayOffers = previous
		return response, err
	}
	return response, s.point("capture-relay-offer-durable")
}

func (s *Session) currentRelayOffer(reader string, authority Authority, now time.Time) (relayOffer, bool) {
	for _, offer := range s.state.RelayOffers {
		if offer.Recipient == reader && offer.matches(s.intent, authority, s.owner, now) {
			return offer, true
		}
	}
	return relayOffer{}, false
}

func (g *Registry) readRelayOffer(ctx context.Context, origin string) (relayedIntent, Intent, error) {
	var relay relayedIntent
	raw, err := g.readStagingDocument(ctx, origin, g.relayPrefix()+relayIntentResource, nil, maxRelayReply)
	if err != nil {
		return relay, Intent{}, err
	}
	if decodeReply(raw, &relay) != nil || relay.Offer.Recipient != g.authority.Ingress || !bytes.Equal(relay.Offer.Authority, g.options.Authority) {
		return relay, Intent{}, ErrDenied
	}
	target, _, err := VerifyIntent(relay.Offer.Intent, relay.Offer.Authority, g.options.Owner, time.Now())
	if err != nil {
		return relay, Intent{}, err
	}
	peerIntent, _, err := g.stagingPeer(target, relay.Origin)
	if err != nil || peerIntent.Ingress != origin {
		return relay, Intent{}, ErrDenied
	}
	return relay, target, nil
}

// AdvanceRelayedIntent performs initial admission under the same durable
// fence and predecessor rules as a direct source request.
func (g *Registry) AdvanceRelayedIntent(ctx context.Context, paused func(string) bool) (bool, error) {
	if len(g.relayOrigins) == 0 || len(g.options.Settlement) != 0 || !g.mu.TryLock() {
		return false, nil
	}
	now := time.Now()
	if g.poisoned || now.Unix() < g.state.ObservedUnix || now.Before(g.leaf.NotBefore) || !now.Before(g.leaf.NotAfter) {
		g.mu.Unlock()
		return false, nil
	}
	if len(g.state.Intent) != 0 {
		defer g.mu.Unlock()
		// Replay an already durable local fence without needing the bridge.
		if g.session == nil {
			i, _, err := g.stagingIntent(now)
			if err == nil && !paused(i.Operation) {
				if _, err = g.begin(ctx, g.state.Intent); err != nil && !errors.Is(err, ErrConflict) {
					return false, err
				}
			}
		}
		return false, nil
	}
	deadline := time.Unix(g.authority.ExpiresUnix, 0)
	if g.leaf.NotAfter.Before(deadline) {
		deadline = g.leaf.NotAfter
	}
	if !active(now, g.authority.NotBefore, g.authority.ExpiresUnix) {
		g.mu.Unlock()
		return false, nil
	}
	origin := g.relayOrigins[g.nextRelayOrigin]
	g.nextRelayOrigin = (g.nextRelayOrigin + 1) % len(g.relayOrigins)
	g.mu.Unlock()
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	relay, target, err := g.readRelayOffer(bounded, origin)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || paused(target.Operation) {
		return false, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.state.Intent) != 0 {
		return false, nil
	}
	_, err = g.begin(bounded, relay.Offer.Intent)
	return err == nil, err
}
