package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

// NewSettlementClient cannot begin capture, fetch ciphertext, upload or
// publish a catalog. Its owner capability is separate from the original intent.
func NewSettlementClient(endpoint string, authority, intent, grant []byte, owner ed25519.PublicKey, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits) (*Client, error) {
	selected, e := VerifySettlement(grant, authority, intent, owner, time.Now())
	if e != nil {
		return nil, e
	}
	c, e := newClient(endpoint, authority, intent, owner, cert, roots, limits, true)
	if e != nil {
		return nil, e
	}
	c.settlement = append([]byte(nil), grant...)
	c.inspection = selected.inspect()
	return c, nil
}

func (c *Client) SettlementReceipt(ctx context.Context) (Receipt, error) {
	var out Receipt
	if len(c.settlement) == 0 || c.inspection {
		return out, ErrDenied
	}
	_, _, raw, e := c.request(ctx, http.MethodGet, "receipt", nil, nil, MaxReceiptDocument)
	if e != nil {
		return out, e
	}
	g, e := VerifySettlement(c.settlement, c.authority, c.intentRaw, c.owner, time.Now())
	if e != nil {
		return out, e
	}
	if decodeReply(raw, &out) != nil || !VerifyReceipt(out, c.intent, c.authority, c.intentRaw, c.owner) || out.Generation != g.Generation || out.VerifiedAt < c.intent.NotBefore || out.VerifiedAt > time.Now().Unix() {
		return Receipt{}, ErrProtocol
	}
	return out, nil
}

func settlementRequest(r *http.Request, leaf *x509.Certificate, i Intent, grant []byte, purpose string, now time.Time) bool {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	remote := r.TLS.PeerCertificates[0]
	if peer.Identity(remote) != i.Source || now.Before(remote.NotBefore) || !now.Before(remote.NotAfter) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	if len(r.Header.Values("Outpost-Authority")) != 1 || r.Header.Get("Outpost-Authority") != i.Authority || len(r.Header.Values("Outpost-Settlement")) != 1 || r.Header.Get("Outpost-Settlement") != storage.Hash(grant) {
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() {
		return false
	}
	if purpose == SettlementRetireUnsealed && r.Method == http.MethodPut {
		return r.URL.Path == route(i)+"/retire" && r.ContentLength == 0 && len(r.TransferEncoding) == 0
	}
	if purpose == SettlementInspect || purpose == SettlementRetire || purpose == SettlementRetireUnsealed {
		return r.Method == http.MethodGet && r.URL.Path == route(i)+"/reconcile" && r.ContentLength == 0 && len(r.TransferEncoding) == 0
	}
	if r.Method == http.MethodGet && r.URL.Path == route(i)+"/receipt" {
		return r.ContentLength == 0 && len(r.TransferEncoding) == 0
	}
	return r.Method == http.MethodPut && r.URL.Path == route(i)+"/ack"
}

// completedReceipt returns only a previously durable receipt. It cannot infer
// completion from a replica head, create a receipt or refresh its verification
// time. LastObserved remains the ordinary monotonic journal clock guard.
func (s *Session) completedReceipt(ctx context.Context) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.guardMode(ctx, true); e != nil {
		return Receipt{}, e
	}
	return *s.state.Receipt, nil
}

func newSettlementServer(s *Session, grant []byte, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits) (*http.Server, error) {
	s.mu.Lock()
	authority, intentRaw, owner := bytes.Clone(s.state.Authority), bytes.Clone(s.state.Intent), bytes.Clone(s.owner)
	s.mu.Unlock()
	if _, e := VerifySettlement(grant, authority, intentRaw, owner, time.Now()); e != nil {
		return nil, e
	}
	base, e := NewServer(s, cert, roots, limits)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, e
	}
	grant = append([]byte(nil), grant...)
	base.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		now := time.Now()
		g, e := VerifySettlement(grant, authority, intentRaw, owner, now)
		if e != nil || !settlementRequest(r, leaf, s.intent, grant, g.Purpose, now) {
			fail(w, ErrDenied)
			return
		}
		deadline := now.Add(limits.Timeout)
		for _, expiry := range []time.Time{time.Unix(g.ExpiresUnix, 0), leaf.NotAfter, r.TLS.PeerCertificates[0].NotAfter} {
			if expiry.Before(deadline) {
				deadline = expiry
			}
		}
		ctx, cancel, e := requestLifetime(w, r.Context(), deadline)
		if e != nil {
			fail(w, ErrUnavailable)
			return
		}
		defer cancel()
		receipt, e := s.completedReceipt(ctx)
		if e != nil {
			fail(w, e)
			return
		}
		if receipt.Generation != g.Generation {
			fail(w, ErrDenied)
			return
		}
		if r.Method == http.MethodGet {
			jsonReply(w, http.StatusOK, receipt)
			return
		}
		raw, e := readBody(w, r, MaxReceiptDocument)
		var selected Receipt
		if e != nil || decodeReply(raw, &selected) != nil || selected != receipt {
			fail(w, ErrDenied)
			return
		}
		if _, e = VerifySettlement(grant, authority, intentRaw, owner, time.Now()); e != nil {
			fail(w, e)
			return
		}
		result, e := s.Acknowledge(ctx, selected, 256)
		if e != nil {
			fail(w, e)
			return
		}
		jsonReply(w, http.StatusOK, result)
	})
	return base, nil
}

// Called with Registry's bounded admission slot and mutex held. Configuration
// admission already binds a fresh grant; every request checks its lifetime and
// exact digest again before opening the historical session.
func (g *Registry) serveSettlement(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	grant, e := VerifySettlement(g.options.Settlement, g.options.Authority, g.options.SettlementIntent, g.options.Owner, now)
	var intent Intent
	if e != nil || canonicalIntent(g.options.SettlementIntent, g.options.Authority, g.options.Owner, &intent) != nil ||
		!settlementRequest(r, g.leaf, intent, g.options.Settlement, grant.Purpose, now) {
		fail(w, ErrDenied)
		return
	}
	if g.poisoned || now.Unix() < g.state.ObservedUnix {
		fail(w, ErrConflict)
		return
	}
	deadline := now.Add(g.options.Limits.Timeout)
	for _, expiry := range []time.Time{time.Unix(grant.ExpiresUnix, 0), g.leaf.NotAfter, r.TLS.PeerCertificates[0].NotAfter} {
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}
	ctx, cancel, e := requestLifetime(w, r.Context(), deadline)
	if e != nil {
		fail(w, e)
		return
	}
	defer cancel()
	if grant.inspect() {
		var result Reconciliation
		if r.Method == http.MethodPut {
			result, e = g.retireUnsealed(ctx, intent, grant)
		} else {
			result, e = g.reconcile(ctx, intent, grant)
		}
		if e != nil {
			fail(w, e)
			return
		}
		jsonReply(w, http.StatusOK, result)
		return
	}
	if g.session == nil {
		o := g.sessionOptions(g.state.Intent)
		o.Initialize = false
		if grant.Purpose == SettlementPublish {
			g.session, e = g.stagingSession(ctx)
			if errors.Is(e, ErrDenied) {
				g.session, e = openSession(ctx, o, true)
			}
		} else {
			g.session, e = openSession(ctx, o, true)
		}
		if e != nil {
			fail(w, e)
			return
		}
	}
	if g.handler == nil {
		server, e := newSettlementServer(g.session, g.options.Settlement, g.options.Certificate, g.options.Roots, g.options.Limits)
		if e != nil {
			fail(w, e)
			return
		}
		g.handler = server.Handler
	}
	g.handler.ServeHTTP(w, r.WithContext(ctx))
}
