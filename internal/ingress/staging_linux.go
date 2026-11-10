package ingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
)

// StagingRoutes is derived from the current signed placement configuration.
// Imports dial only Origins. Readers may retrieve only durable staged objects.
type StagingRoutes struct {
	Origins map[string]string
	Readers map[string]bool
}

type stagingOrigin struct {
	Authority json.RawMessage `json:"authority"`
	Intent    json.RawMessage `json:"intent"`
}

type stagingImportRequest struct {
	stagingOrigin
	Fallback *stagingOrigin `json:"fallback,omitempty"`
}

func sameStagingOrigin(a, b *stagingOrigin) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Authority, b.Authority) && bytes.Equal(a.Intent, b.Intent)
}

// Matching intents name the same capture but are signed separately for each
// receiver and bind to that receiver's own owner capability.
func sameCapture(a, b Intent) bool {
	a.Authority, a.Ingress, a.Signature = b.Authority, b.Ingress, nil
	b.Signature = nil
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (c *Client) PullStaged(ctx context.Context, origin *Client, ref filekit.Object) error {
	return c.requestStagedImport(ctx, origin, nil, ref, "imports/", http.StatusOK)
}

// QueueStaged acknowledges a durable request, which the receiving worker may
// fulfill later. Check confirms whether the object is available for the capture.
func (c *Client) QueueStaged(ctx context.Context, origin *Client, ref filekit.Object) error {
	return c.requestStagedImport(ctx, origin, nil, ref, "queued-imports/", http.StatusAccepted)
}

// QueueStagedWithFallback queues one object with a second, independently
// authorized origin for the receiving worker to use if the first is unavailable.
func (c *Client) QueueStagedWithFallback(ctx context.Context, origin, fallback *Client, ref filekit.Object) error {
	if fallback == nil {
		return ErrDenied
	}
	return c.requestStagedImport(ctx, origin, fallback, ref, "queued-imports/", http.StatusAccepted)
}

func (c *Client) requestStagedImport(ctx context.Context, origin, fallback *Client, ref filekit.Object, resource string, expected int) error {
	if origin == nil || origin.intent.Ingress == c.intent.Ingress || !sameCapture(c.intent, origin.intent) || !validObject(ref) {
		return ErrDenied
	}
	request := stagingImportRequest{stagingOrigin: stagingOrigin{Authority: origin.authority, Intent: origin.intentRaw}}
	if fallback != nil {
		if fallback.intent.Ingress == origin.intent.Ingress || fallback.intent.Ingress == c.intent.Ingress || !sameCapture(c.intent, fallback.intent) {
			return ErrDenied
		}
		request.Fallback = &stagingOrigin{Authority: fallback.authority, Intent: fallback.intentRaw}
	}
	raw, e := json.Marshal(request)
	if e != nil {
		return e
	}
	status, _, _, e := c.request(ctx, http.MethodPut, resource+ref.ID, &ref, raw, 0)
	if e == nil && status != expected {
		return ErrProtocol
	}
	return e
}

// stagingSession is called with the registry lock held. This path never
// admits an intent or opens an uninitialized slot on a peer's behalf.
func (g *Registry) stagingSession(ctx context.Context) (*Session, error) {
	if g.session != nil {
		return g.session, nil
	}
	options := g.sessionOptions(g.state.Intent)
	options.Initialize = false
	mode := sessionActive
	if g.settlementPurpose == SettlementPublish {
		mode = sessionPublish
		options.publishGrant = g.options.Settlement
	}
	session, e := openSessionFor(ctx, options, mode)
	if e != nil {
		return nil, e
	}
	session.Fault = g.point
	g.session = session
	return session, nil
}

func (s *Session) readStaged(ctx context.Context, ref filekit.Object) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.guard(ctx); e != nil {
		return nil, e
	}
	if s.state.Acknowledged || s.refs[ref.ID] != (generation.Object{ID: ref.ID, Bytes: ref.Bytes}) {
		return nil, os.ErrNotExist
	}
	return s.read(ctx, ref)
}

func (g *Registry) serveStaging(w http.ResponseWriter, r *http.Request) bool {
	prefix := "/v1/tenants/" + g.authority.Tenant + "/domains/" + g.authority.Trust.Domain + "/captures/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) != 3 || parts[1] != "imports" && parts[1] != "queued-imports" && parts[1] != "staged" {
		return false
	}
	read := parts[1] == "staged"
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() ||
		r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		fail(w, ErrDenied)
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	remote := r.TLS.PeerCertificates[0]
	identity := peer.Identity(remote)
	if read && (r.Method != http.MethodGet || r.ContentLength != 0 || !g.options.Staging.Readers[identity]) ||
		!read && (r.Method != http.MethodPut || identity != g.authority.Source || len(g.options.Settlement) != 0) {
		fail(w, ErrDenied)
		return true
	}
	length := r.Header.Get("Outpost-Bytes")
	size, e := strconv.Atoi(length)
	ref := filekit.Object{ID: parts[2], Bytes: size}
	if e != nil || strconv.Itoa(size) != length || !validObject(ref) {
		fail(w, ErrDenied)
		return true
	}
	slots := g.stageImports
	if read {
		slots = g.stageReads
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
	g.mu.Lock()
	raw := bytes.Clone(g.state.Intent)
	i, expiry, e := g.stagingIntent(now)
	if g.poisoned || now.Unix() < g.state.ObservedUnix || e != nil ||
		parts[0] != i.Operation || r.Header.Get("Outpost-Authority") != i.Authority {
		g.mu.Unlock()
		fail(w, ErrDenied)
		return true
	}
	deadline := now.Add(g.options.Limits.Timeout)
	var peerGrant []byte
	if g.settlementPurpose == SettlementPublish {
		encoded := r.Header.Values("Outpost-Publication-Grant")
		if len(encoded) != 1 || len(encoded[0]) > base64.RawStdEncoding.EncodedLen(MaxSettlementDocument) {
			g.mu.Unlock()
			fail(w, ErrDenied)
			return true
		}
		var err error
		peerGrant, err = base64.RawStdEncoding.DecodeString(encoded[0])
		var preview Settlement
		if err != nil || canonical(peerGrant, &preview) != nil || !active(now, preview.NotBefore, preview.ExpiresUnix) {
			g.mu.Unlock()
			fail(w, ErrDenied)
			return true
		}
		if candidate := time.Unix(preview.ExpiresUnix, 0); candidate.Before(deadline) {
			deadline = candidate
		}
		// Verify the signed peer grant against the frozen slot below. The
		// untrusted preview above can only shorten this request's lifetime.
	}
	for _, limit := range []time.Time{remote.NotAfter, g.leaf.NotAfter, expiry} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	ctx, stop, e := requestLifetime(w, r.Context(), deadline)
	if e != nil {
		g.mu.Unlock()
		fail(w, e)
		return true
	}
	defer stop()
	if read {
		s, e := g.stagingSession(ctx)
		var b []byte
		if e == nil {
			if g.settlementPurpose == SettlementPublish {
				e = s.permitsFinalizationRead(ctx, identity, ref, peerGrant)
			}
			if e == nil {
				b, e = s.readStaged(ctx, ref)
			}
		}
		g.mu.Unlock()
		if e != nil {
			fail(w, e)
			return true
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		_, _ = w.Write(b)
		return true
	}
	g.mu.Unlock()

	queued := parts[1] == "queued-imports"
	maxBody := 2*MaxDocument + 4096
	if queued {
		maxBody += 2 * MaxDocument
	}
	body, e := readBody(w, r, maxBody)
	var request stagingImportRequest
	if e != nil || decodeReply(body, &request) != nil || !queued && request.Fallback != nil {
		fail(w, ErrDenied)
		return true
	}
	if queued {
		importRequest := queuedStagingImport{Origin: request.stagingOrigin, Object: ref, Fallback: request.Fallback}
		if e = g.queueStagedImport(ctx, i, raw, importRequest); e != nil {
			fail(w, e)
			return true
		}
		w.WriteHeader(http.StatusAccepted)
		return true
	}
	if e = g.importStaged(ctx, i, raw, request.stagingOrigin, nil, ref, false); e != nil {
		fail(w, e)
		return true
	}
	w.WriteHeader(http.StatusOK)
	return true
}

func (g *Registry) stagingPeer(target Intent, origin stagingOrigin) (Intent, string, error) {
	if g.options.Staging == nil {
		return Intent{}, "", ErrDenied
	}
	i, authority, e := VerifyIntent(origin.Intent, origin.Authority, g.options.Owner, time.Now())
	if g.settlementPurpose == SettlementPublish {
		e = canonicalIntent(origin.Intent, origin.Authority, g.options.Owner, &i)
		if e == nil {
			authority, e = VerifyAuthorityDocument(origin.Authority, g.options.Owner)
		}
	}
	endpoint := g.options.Staging.Origins[i.Ingress]
	authority.Ingress = target.Ingress
	if e != nil || endpoint == "" || i.Ingress == target.Ingress || !sameCapture(i, target) ||
		!SameAuthorityScope(authority, g.authority) {
		return Intent{}, "", ErrDenied
	}
	return i, endpoint, nil
}

func (g *Registry) importStaged(ctx context.Context, target Intent, targetRaw []byte, origin stagingOrigin, fallback *stagingOrigin, ref filekit.Object, assembling bool) error {
	i, endpoint, e := g.stagingPeer(target, origin)
	if e != nil {
		return e
	}
	g.mu.Lock()
	e = g.withStagingSession(ctx, targetRaw, func(s *Session) error {
		_, e := s.Read(ctx, ref)
		return e
	})
	g.mu.Unlock()
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	// Keep part of the attempt available for the alternate. Both reads run
	// without a registry or session lock and use the same verified object ID.
	primaryCtx := ctx
	if fallback != nil {
		deadline, _ := ctx.Deadline() // queued imports always have an attempt deadline
		var cancel context.CancelFunc
		primaryCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/2)
		defer cancel()
	}
	b, e := g.fetchStaged(primaryCtx, target, i, endpoint, origin, ref)
	if fallback != nil && ctx.Err() == nil && stagedOriginUnavailable(e) {
		alternate, alternateEndpoint, err := g.stagingPeer(target, *fallback)
		if err != nil {
			return err
		}
		b, e = g.fetchStaged(ctx, target, alternate, alternateEndpoint, *fallback, ref)
	}
	if e != nil {
		return e
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.withStagingSession(ctx, targetRaw, func(s *Session) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if assembling {
			peer := s.state.CoveragePeer
			// Only AdvanceCoverage selects an object from this frozen catalog.
			if peer == nil || !bytes.Equal(peer.Intent, origin.Intent) || !bytes.Equal(peer.Authority, origin.Authority) {
				return ErrConflict
			}
		}
		_, e := s.write(ctx, ref, b, assembling)
		return e
	})
}

func stagedOriginUnavailable(err error) bool {
	var dns *net.DNSError
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrUnavailable) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.As(err, &dns)
}

func (g *Registry) fetchStaged(ctx context.Context, target, peerIntent Intent, endpoint string, origin stagingOrigin, ref filekit.Object) ([]byte, error) {
	client, err := clientWithIdentity(endpoint, target.Ingress, peerIntent, origin.Authority, origin.Intent,
		g.options.Owner, g.options.Certificate, g.options.Roots, g.options.Limits, false)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	client.stagingReader = true
	if g.settlementPurpose == SettlementPublish {
		grant, err := VerifySettlement(g.options.Settlement, g.options.Authority, g.options.SettlementIntent, g.options.Owner, time.Now())
		if err != nil {
			return nil, err
		}
		client.peerPublicationDeadline = time.Unix(grant.ExpiresUnix, 0)
		client.peerPublicationGrant = g.options.Settlement
	}
	return client.readObjectResource(ctx, ref, "staged/")
}

func (g *Registry) withStagingSession(ctx context.Context, raw []byte, fn func(*Session) error) error {
	if g.poisoned || !bytes.Equal(g.state.Intent, raw) {
		return ErrConflict
	}
	s, e := g.stagingSession(ctx)
	if e != nil {
		return e
	}
	return fn(s)
}
