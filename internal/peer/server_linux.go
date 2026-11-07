package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

type handler struct {
	replica  *generation.Replica
	journal  *Journal
	policy   Policy
	limits   Limits
	slots    chan struct{}
	selfCert *x509.Certificate
}

// NewServer does not listen or change host networking. The caller explicitly
// provides an admitted replica/journal and TLS credentials before serving.
func NewServer(replica *generation.Replica, journal *Journal, policy Policy, cert tls.Certificate, roots *x509.CertPool, limits Limits) (*http.Server, error) {
	if replica == nil || journal == nil || !limits.valid() {
		return nil, ErrDenied
	}
	if e := policy.validate(replica.Trust()); e != nil {
		return nil, e
	}
	if journal.identity.Self != policy.Self || journal.identity.Domain != policy.Domain || journal.identity.Repository != policy.Repository || journal.identity.Epoch != policy.Epoch {
		return nil, ErrDenied
	}
	config, e := serverTLS(cert, roots, policy.Self)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, ErrDenied
	}
	h := &handler{replica, journal, clonePolicy(policy), limits, make(chan struct{}, limits.Concurrency), leaf}
	return &http.Server{Handler: h, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: limits.Timeout, WriteTimeout: limits.Timeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}, nil
}

func (h *handler) bind(op, peer, id, kind string) Binding {
	return Binding{Operation: op, Kind: kind, Domain: h.policy.Domain, Repository: h.policy.Repository, Epoch: h.policy.Epoch, Generation: id, Peer: peer, Executor: h.policy.Self, Expected: id}
}
func leasePin(b Binding) string {
	return generation.Hash([]byte(Format + "/lease/" + b.Executor + "/" + b.Peer + "/" + b.Operation + "/" + b.Generation))
}
func body(w http.ResponseWriter, r *http.Request, max int) ([]byte, error) {
	if r.ContentLength > int64(max) || r.Header.Get("Content-Encoding") != "" {
		return nil, ErrProtocol
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(max))
	b, e := io.ReadAll(r.Body)
	if e != nil {
		return nil, ErrProtocol
	}
	return b, nil
}
func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, e error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(e, ErrDenied):
		status = http.StatusForbidden
	case errors.Is(e, ErrCapacity):
		status = http.StatusInsufficientStorage
	case errors.Is(e, ErrConflict), errors.Is(e, generation.ErrConflict), errors.Is(e, generation.ErrRollback), errors.Is(e, generation.ErrProtected):
		status = http.StatusConflict
	case errors.Is(e, generation.ErrIncomplete):
		status = http.StatusPreconditionFailed
	case errors.Is(e, ErrUnavailable), errors.Is(e, context.DeadlineExceeded), errors.Is(e, context.Canceled):
		status = http.StatusServiceUnavailable
	}
	http.Error(w, http.StatusText(status), status)
}
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || r.TLS.Version < tls.VersionTLS13 {
		fail(w, ErrDenied)
		return
	}
	if !certCurrent(h.selfCert, time.Now()) || !certCurrent(r.TLS.PeerCertificates[0], time.Now()) {
		fail(w, ErrDenied)
		return
	}
	peer := Identity(r.TLS.PeerCertificates[0])
	mode := r.Header.Get("Outpost-Mode")
	op := r.Header.Get("Outpost-Operation")
	if !validID(op) || (mode != "push" && mode != "pull") {
		fail(w, ErrDenied)
		return
	}
	push := mode == "push"
	if e := h.policy.grant(peer, push, time.Now()); e != nil {
		fail(w, e)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() {
		fail(w, ErrProtocol)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if (len(parts) != 6 && len(parts) != 7) || parts[1] != "v1" || parts[2] != h.policy.Domain || parts[3] != "generations" || !validID(parts[4]) {
		fail(w, ErrDenied)
		return
	}
	id, resource := parts[4], parts[5]
	history := r.Header.Get("Outpost-History")
	if history != "" && (history != "1" || !push || r.Method != http.MethodPut || resource != "catalog" || !h.policy.Peers[peer].History) {
		fail(w, ErrDenied)
		return
	}
	if (resource == "objects" && len(parts) != 7) || (resource != "objects" && len(parts) != 6) {
		fail(w, ErrProtocol)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "busy", http.StatusTooManyRequests)
		return
	}
	deadline := time.Now().Add(h.limits.Timeout)
	for _, expiry := range []time.Time{time.Unix(h.policy.Peers[peer].ExpiresUnix, 0), h.selfCert.NotAfter, r.TLS.PeerCertificates[0].NotAfter} {
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	kind := "serve"
	if push {
		kind = "receive"
	}
	binding := h.bind(op, peer, id, kind)
	if push && r.Method == http.MethodPut && resource == "catalog" {
		raw, e := body(w, r, generation.MaxCatalog)
		if e != nil {
			fail(w, e)
			return
		}
		if generation.Hash(raw) != id {
			fail(w, ErrProtocol)
			return
		}
		if _, e = generation.VerifyCatalog(raw, h.replica.Trust()); e != nil {
			fail(w, e)
			return
		}
		if e = h.policy.grant(peer, true, time.Now()); e != nil {
			fail(w, e)
			return
		}
		if _, e = h.journal.Begin(ctx, binding); e != nil {
			fail(w, e)
			return
		}
		_, e = h.replica.Begin(ctx, raw)
		if errors.Is(e, generation.ErrRollback) && history == "1" {
			_, e = h.replica.BeginHistorical(ctx, raw)
		}
		if e != nil {
			fail(w, e)
			return
		}
		if e = h.journal.Update(ctx, binding, "TRANSFERRING", nil, Counters{}); e != nil {
			fail(w, e)
			return
		}
		respond(w, map[string]string{"generation": id, "state": "RECEIVING"})
		return
	}
	if !push && r.Method == http.MethodPost && resource == "lease" {
		if _, e := body(w, r, 0); e != nil {
			fail(w, e)
			return
		}
		if _, e := h.journal.Begin(ctx, binding); e != nil {
			fail(w, e)
			return
		}
		if e := h.replica.Pin(ctx, leasePin(binding), id, "generation"); e != nil {
			fail(w, e)
			return
		}
		if e := h.journal.Update(ctx, binding, "TRANSFERRING", nil, Counters{}); e != nil {
			fail(w, e)
			return
		}
		respond(w, map[string]string{"generation": id, "state": "PINNED"})
		return
	}
	job, e := h.journal.Read(ctx, binding)
	if e != nil {
		fail(w, e)
		return
	}
	if !push && job.Phase == "RELEASED" && r.Method == http.MethodDelete && resource == "lease" {
		respond(w, map[string]string{"generation": id, "state": "RELEASED"})
		return
	}
	if !push && job.Phase != "TRANSFERRING" {
		fail(w, ErrDenied)
		return
	}
	if !push && r.Method == http.MethodDelete && resource == "lease" {
		if _, e = body(w, r, 0); e != nil {
			fail(w, e)
			return
		}
		if e = h.replica.ReleasePin(ctx, leasePin(binding)); e != nil {
			fail(w, e)
			return
		}
		if e = h.journal.Update(ctx, binding, "RELEASED", nil, Counters{}); e != nil {
			fail(w, e)
			return
		}
		respond(w, map[string]string{"generation": id, "state": "RELEASED"})
		return
	}
	if r.Method == http.MethodGet {
		// Push receipts are audited by GET, which needs explicit read authority.
		if e = h.policy.grant(peer, false, time.Now()); e != nil {
			fail(w, e)
			return
		}
		raw, e := h.replica.Catalog(ctx, id)
		if e != nil {
			fail(w, e)
			return
		}
		if resource == "catalog" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
			_, _ = w.Write(raw)
			return
		}
		if resource == "objects" && validID(parts[6]) {
			refs, e := generation.Dependencies(raw, h.replica.Trust())
			if e != nil {
				fail(w, e)
				return
			}
			for _, ref := range refs {
				if ref.ID == parts[6] {
					b, e := h.replica.ReadObject(ctx, id, ref)
					if e != nil {
						fail(w, e)
						return
					}
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Header().Set("Content-Length", strconv.Itoa(len(b)))
					w.Header().Set("ETag", `"`+ref.ID+`"`)
					_, _ = w.Write(b)
					return
				}
			}
		}
		fail(w, ErrDenied)
		return
	}
	if !push {
		fail(w, ErrDenied)
		return
	}
	if resource == "objects" && r.Method == http.MethodPut && validID(parts[6]) {
		b, e := body(w, r, generation.MaxObject)
		if e != nil {
			fail(w, e)
			return
		}
		if e = h.policy.grant(peer, true, time.Now()); e != nil {
			fail(w, e)
			return
		}
		if e = h.replica.Put(ctx, id, parts[6], b); e != nil {
			fail(w, e)
			return
		}
		respond(w, map[string]string{"object": parts[6], "state": "HASH_VERIFIED_DURABLE"})
		return
	}
	if r.Method != http.MethodPost {
		fail(w, ErrProtocol)
		return
	}
	if _, e = body(w, r, 0); e != nil {
		fail(w, e)
		return
	}
	switch resource {
	case "missing":
		refs, e := h.replica.Missing(ctx, id)
		if e != nil {
			fail(w, e)
			return
		}
		respond(w, refs)
	case "complete":
		if e = h.policy.grant(peer, true, time.Now()); e != nil {
			fail(w, e)
			return
		}
		if e = h.replica.Complete(ctx, id); e != nil {
			fail(w, e)
			return
		}
		receipt := Receipt{Format, h.policy.Self, id, id, op, "target-full-read", time.Now().Unix()}
		if e = h.journal.Update(ctx, binding, "COMPLETE", &receipt, Counters{}); e != nil {
			fail(w, e)
			return
		}
		respond(w, receipt)
	default:
		fail(w, ErrProtocol)
	}
}
