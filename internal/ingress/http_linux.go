package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

var ErrUnavailable = errors.New("source ingress unavailable or retry required")
var ErrProtocol = errors.New("invalid source ingress response")

type finishReply struct {
	Progress generation.BatchResult `json:"progress"`
	Receipt  *Receipt               `json:"receipt,omitempty"`
}

func route(i Intent) string {
	return "/v1/tenants/" + i.Tenant + "/domains/" + i.Domain + "/captures/" + i.Operation
}
func limitsOK(l peer.Limits) bool {
	return l.Concurrency >= 1 && l.Concurrency <= 4 && l.Timeout >= 100*time.Millisecond && l.Timeout <= 5*time.Minute && l.Attempts >= 1 && l.Attempts <= 3
}
func statusError(e error) int {
	switch {
	case errors.Is(e, ErrDenied):
		return http.StatusForbidden
	case errors.Is(e, os.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(e, ErrConflict), errors.Is(e, generation.ErrConflict), errors.Is(e, generation.ErrRollback):
		return http.StatusConflict
	case errors.Is(e, statefile.ErrCapacity):
		return http.StatusInsufficientStorage
	case errors.Is(e, ErrIncomplete), errors.Is(e, generation.ErrIncomplete):
		return http.StatusPreconditionFailed
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}
func fail(w http.ResponseWriter, e error) {
	status := statusError(e)
	http.Error(w, http.StatusText(status), status)
}
func readBody(w http.ResponseWriter, r *http.Request, max int) ([]byte, error) {
	if r.ContentLength > int64(max) || r.Header.Get("Content-Encoding") != "" {
		return nil, ErrProtocol
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(max)))
	if e != nil {
		return nil, ErrProtocol
	}
	return b, nil
}
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// NewServer serves one admitted session. It never listens itself or grants a
// new session; a worker registry must admit and route dynamic capture intents.
func NewServer(s *Session, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits) (*http.Server, error) {
	return newServer(s, cert, roots, limits, 256, 256<<20)
}

func newServer(s *Session, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits, batchObjects int, batchBytes int64) (*http.Server, error) {
	if s == nil || !limitsOK(limits) {
		return nil, ErrDenied
	}
	config, e := peer.AuthenticatedServerTLS(cert, roots, s.intent.Ingress)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, e
	}
	slots := make(chan struct{}, limits.Concurrency)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		now := time.Now()
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || peer.Identity(r.TLS.PeerCertificates[0]) != s.intent.Source || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			fail(w, ErrDenied)
			return
		}
		remote := r.TLS.PeerCertificates[0]
		if now.Before(remote.NotBefore) || !now.Before(remote.NotAfter) || r.Header.Get("Outpost-Authority") != s.intent.Authority {
			fail(w, ErrDenied)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() {
			fail(w, ErrDenied)
			return
		}
		prefix := route(s.intent) + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			fail(w, ErrDenied)
			return
		}
		resource := strings.TrimPrefix(r.URL.Path, prefix)
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		deadline := now.Add(limits.Timeout)
		expiries := []time.Time{leaf.NotAfter, remote.NotAfter}
		if resource != "ack" || r.Method != http.MethodPut {
			expiries = append(expiries, time.Unix(s.intent.ExpiresUnix, 0))
		}
		for _, expiry := range expiries {
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
		if resource == "ack" && r.Method == http.MethodPut {
			raw, e := readBody(w, r, 4096)
			var receipt Receipt
			if e != nil || decodeReply(raw, &receipt) != nil {
				fail(w, ErrProtocol)
				return
			}
			result, e := s.Acknowledge(ctx, receipt, batchObjects)
			if e != nil {
				fail(w, e)
				return
			}
			jsonReply(w, http.StatusOK, result)
			return
		}
		if resource == "catalog" && r.Method == http.MethodPut {
			raw, e := readBody(w, r, generation.MaxCatalog)
			if e != nil {
				fail(w, e)
				return
			}
			progress, receipt, e := s.FinishBatch(ctx, raw, batchObjects, batchBytes)
			if e != nil {
				fail(w, e)
				return
			}
			reply := finishReply{Progress: progress}
			status := http.StatusAccepted
			if progress.Complete {
				reply.Receipt = &receipt
				status = http.StatusOK
			}
			jsonReply(w, status, reply)
			return
		}
		if resource == "catalog" && r.Method == http.MethodGet {
			s.mu.Lock()
			defer s.mu.Unlock()
			if e := s.guard(ctx); e != nil {
				fail(w, e)
				return
			}
			if !s.state.Complete || s.state.Acknowledged {
				fail(w, ErrIncomplete)
				return
			}
			raw, e := s.replica.Catalog(ctx, storage.Hash(s.state.Catalog))
			if e != nil {
				fail(w, e)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
			return
		}
		if !strings.HasPrefix(resource, "objects/") {
			fail(w, ErrDenied)
			return
		}
		id := strings.TrimPrefix(resource, "objects/")
		length := r.Header.Get("Outpost-Bytes")
		size, e := strconv.Atoi(length)
		ref := filekit.Object{ID: id, Bytes: size}
		if e != nil || strconv.Itoa(size) != length || !validObject(ref) {
			fail(w, ErrDenied)
			return
		}
		switch r.Method {
		case http.MethodPut:
			b, e := readBody(w, r, generation.MaxObject)
			if e != nil {
				fail(w, e)
				return
			}
			created, e := s.Write(ctx, ref, b)
			if e != nil {
				fail(w, e)
				return
			}
			jsonReply(w, http.StatusOK, struct {
				Created bool `json:"created"`
			}{created})
		case http.MethodGet:
			b, e := s.Read(ctx, ref)
			if e != nil {
				fail(w, e)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			_, _ = w.Write(b)
		case http.MethodHead:
			if e := s.Check(ctx, ref); e != nil {
				fail(w, e)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(ref.Bytes))
			w.WriteHeader(http.StatusOK)
		default:
			fail(w, ErrDenied)
		}
	})
	return &http.Server{Handler: handler, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: limits.Timeout, WriteTimeout: limits.Timeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}, nil
}

type Client struct {
	http                         *http.Client
	endpoint                     *url.URL
	intent                       Intent
	cert                         *x509.Certificate
	authority, intentRaw         []byte
	owner                        ed25519.PublicKey
	cleanup                      bool
	stagingReader                bool
	settlement                   []byte
	UploadedBytes, ReadbackBytes atomic.Int64
}
type countedBody struct {
	r     *bytes.Reader
	count *atomic.Int64
}

func (r countedBody) Read(b []byte) (int, error) {
	n, e := r.r.Read(b)
	r.count.Add(int64(n))
	return n, e
}
func (c *Client) peerCurrent(s *tls.ConnectionState) bool {
	if s == nil || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
		return false
	}
	leaf := s.PeerCertificates[0]
	now := time.Now()
	return peer.Identity(leaf) == c.intent.Ingress && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}
func NewClient(endpoint string, authority, intent []byte, owner ed25519.PublicKey, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits) (*Client, error) {
	return newClient(endpoint, authority, intent, owner, cert, roots, limits, false)
}

// NewCleanupClient admits only acknowledgement of an already verified receipt.
// It cannot begin, read, upload or publish an operation, including before expiry.
func NewCleanupClient(endpoint string, authority, intent []byte, owner ed25519.PublicKey, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits) (*Client, error) {
	return newClient(endpoint, authority, intent, owner, cert, roots, limits, true)
}
func newClient(endpoint string, authority, intent []byte, owner ed25519.PublicKey, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits, cleanup bool) (*Client, error) {
	if !limitsOK(limits) {
		return nil, ErrDenied
	}
	i, _, e := VerifyIntent(intent, authority, owner, time.Now())
	if cleanup {
		e = canonicalIntent(intent, authority, owner, &i)
	}
	if e != nil {
		return nil, e
	}
	return clientWithIdentity(endpoint, i.Source, i, authority, intent, owner, cert, roots, limits, cleanup)
}

func clientWithIdentity(endpoint, self string, i Intent, authority, intent []byte, owner ed25519.PublicKey, cert tls.Certificate, roots *x509.CertPool, limits peer.Limits, cleanup bool) (*Client, error) {
	h, u, e := peer.AuthenticatedHTTP(endpoint, cert, roots, self, i.Ingress, limits)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		h.CloseIdleConnections()
		return nil, e
	}
	return &Client{http: h, endpoint: u, intent: i, cert: leaf, authority: bytes.Clone(authority), intentRaw: bytes.Clone(intent), owner: bytes.Clone(owner), cleanup: cleanup}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) request(ctx context.Context, method, resource string, ref *filekit.Object, payload []byte, max int) (int, http.Header, []byte, error) {
	now := time.Now()
	ack := resource == "ack" && method == http.MethodPut
	settling := len(c.settlement) != 0
	if c.stagingReader && (method != http.MethodGet || !strings.HasPrefix(resource, "staged/")) {
		return 0, nil, nil, ErrDenied
	}
	if (c.cleanup || settling) && !ack && !(settling && resource == "receipt" && method == http.MethodGet) {
		return 0, nil, nil, ErrDenied
	}
	var grant Settlement
	if settling {
		var e error
		grant, e = VerifySettlement(c.settlement, c.authority, c.intentRaw, c.owner, now)
		if e != nil {
			return 0, nil, nil, e
		}
	}
	if !ack && !settling {
		if _, _, e := VerifyIntent(c.intentRaw, c.authority, c.owner, now); e != nil {
			return 0, nil, nil, e
		}
	}
	if now.Before(c.cert.NotBefore) || !now.Before(c.cert.NotAfter) {
		return 0, nil, nil, ErrDenied
	}
	deadline := time.Unix(c.intent.ExpiresUnix, 0)
	if ack || settling {
		deadline = c.cert.NotAfter
	}
	if settling && time.Unix(grant.ExpiresUnix, 0).Before(deadline) {
		deadline = time.Unix(grant.ExpiresUnix, 0)
	}
	if c.cert.NotAfter.Before(deadline) {
		deadline = c.cert.NotAfter
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	u := *c.endpoint
	u.Path = route(c.intent) + "/" + resource
	r, e := http.NewRequestWithContext(bounded, method, u.String(), countedBody{bytes.NewReader(payload), &c.UploadedBytes})
	if e != nil {
		return 0, nil, nil, e
	}
	r.ContentLength = int64(len(payload))
	if len(payload) == 0 {
		r.Body = http.NoBody
	}
	r.Header.Set("Outpost-Authority", c.intent.Authority)
	if settling {
		r.Header.Set("Outpost-Settlement", storage.Hash(c.settlement))
	}
	if ref != nil {
		r.Header.Set("Outpost-Bytes", strconv.Itoa(ref.Bytes))
	}
	response, e := c.http.Do(r)
	if e != nil {
		return 0, nil, nil, e
	}
	defer response.Body.Close()
	if !c.peerCurrent(response.TLS) {
		return 0, nil, nil, ErrDenied
	}
	if response.Header.Get("Content-Encoding") != "" {
		return 0, nil, nil, ErrProtocol
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		n, _ := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		c.ReadbackBytes.Add(n)
		switch response.StatusCode {
		case http.StatusForbidden, http.StatusUnauthorized:
			return 0, nil, nil, ErrDenied
		case http.StatusNotFound:
			return 0, nil, nil, os.ErrNotExist
		case http.StatusConflict:
			return 0, nil, nil, ErrConflict
		case http.StatusInsufficientStorage:
			return 0, nil, nil, statefile.ErrCapacity
		case http.StatusPreconditionFailed:
			return 0, nil, nil, ErrIncomplete
		default:
			return 0, nil, nil, ErrUnavailable
		}
	}
	if method == http.MethodHead {
		return response.StatusCode, response.Header, nil, nil
	}
	if response.ContentLength > int64(max) {
		return 0, nil, nil, ErrProtocol
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, int64(max)+1))
	c.ReadbackBytes.Add(int64(len(body)))
	if e != nil {
		return 0, nil, nil, e
	}
	if len(body) > max {
		return 0, nil, nil, ErrProtocol
	}
	if !c.peerCurrent(response.TLS) {
		return 0, nil, nil, ErrDenied
	}
	if settling {
		if _, e = VerifySettlement(c.settlement, c.authority, c.intentRaw, c.owner, time.Now()); e != nil {
			return 0, nil, nil, e
		}
	}
	return response.StatusCode, response.Header, body, nil
}
func decodeReply(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrProtocol
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	return nil
}
func (c *Client) Read(ctx context.Context, ref filekit.Object) ([]byte, error) {
	return c.readObjectResource(ctx, ref, "objects/")
}

func (c *Client) readObjectResource(ctx context.Context, ref filekit.Object, prefix string) ([]byte, error) {
	if !validObject(ref) {
		return nil, ErrDenied
	}
	status, _, b, e := c.request(ctx, http.MethodGet, prefix+ref.ID, &ref, nil, ref.Bytes)
	if e != nil {
		return nil, e
	}
	if status != http.StatusOK || len(b) != ref.Bytes || storage.Hash(b) != ref.ID {
		return nil, ErrProtocol
	}
	return b, nil
}
func (c *Client) Check(ctx context.Context, ref filekit.Object) error {
	if !validObject(ref) {
		return ErrDenied
	}
	status, headers, _, e := c.request(ctx, http.MethodHead, "objects/"+ref.ID, &ref, nil, 0)
	if e != nil {
		return e
	}
	if status != http.StatusOK || headers.Get("Content-Length") != strconv.Itoa(ref.Bytes) {
		return ErrProtocol
	}
	return nil
}
func (c *Client) Write(ctx context.Context, ref filekit.Object, b []byte) (bool, error) {
	if !validObject(ref) || len(b) != ref.Bytes || storage.Hash(b) != ref.ID {
		return false, ErrDenied
	}
	status, _, raw, e := c.request(ctx, http.MethodPut, "objects/"+ref.ID, &ref, b, 4096)
	if e != nil {
		return false, e
	}
	var result struct {
		Created bool `json:"created"`
	}
	if status != http.StatusOK || decodeReply(raw, &result) != nil {
		return false, ErrProtocol
	}
	readback, e := c.Read(ctx, ref)
	if e != nil {
		return false, e
	}
	if !bytes.Equal(readback, b) {
		return false, ErrProtocol
	}
	return result.Created, nil
}

// FinishStep performs one bounded verification batch. The source journal must
// retain the operation and retry incomplete progress; it must release nothing
// until the returned receipt matches a published complete catalog.
func (c *Client) FinishStep(ctx context.Context, raw []byte) (generation.BatchResult, *Receipt, error) {
	var result generation.BatchResult
	a, e := VerifyAuthority(c.authority, c.owner, time.Now())
	if e != nil {
		return result, nil, e
	}
	catalog, e := generation.VerifyCatalog(raw, a.Trust)
	if e != nil || !c.intent.matches(catalog) {
		return result, nil, ErrDenied
	}
	refs, e := generation.Dependencies(raw, a.Trust)
	if e != nil {
		return result, nil, e
	}
	status, _, body, e := c.request(ctx, http.MethodPut, "catalog", nil, raw, 8192)
	if e != nil {
		return result, nil, e
	}
	var reply finishReply
	if decodeReply(body, &reply) != nil || reply.Progress.Generation != storage.Hash(raw) || reply.Progress.TotalObjects != len(refs) || reply.Progress.VerifiedObjects < 0 || reply.Progress.VerifiedObjects > reply.Progress.TotalObjects || reply.Progress.ReadBytes < 0 || reply.Progress.ReadBytes > 256<<20 || reply.Progress.WrittenBytes < 0 || reply.Progress.WrittenBytes > 256<<20 {
		return result, nil, ErrProtocol
	}
	if status == http.StatusAccepted {
		if reply.Progress.Complete || reply.Receipt != nil {
			return result, nil, ErrProtocol
		}
		return reply.Progress, nil, nil
	}
	r := reply.Receipt
	i := c.intent
	if !reply.Progress.Complete || reply.Progress.VerifiedObjects != reply.Progress.TotalObjects || r == nil || r.Operation != i.Operation || r.Ingress != i.Ingress || r.Tenant != i.Tenant || r.Domain != i.Domain || r.Generation != storage.Hash(raw) || r.NewBytes < 0 || r.NewBytes > i.MaxBytes || r.NewObjects < 0 || r.NewObjects > i.MaxObjects || r.VerifiedAt < i.NotBefore || r.VerifiedAt > time.Now().Unix() {
		return result, nil, ErrProtocol
	}
	_, _, published, e := c.request(ctx, http.MethodGet, "catalog", nil, nil, generation.MaxCatalog)
	if e != nil {
		return result, nil, e
	}
	if !bytes.Equal(published, raw) {
		return result, nil, ErrProtocol
	}
	return reply.Progress, r, nil
}

// AcknowledgeStep is called only after the source durably saves the verified
// receipt. A lost reply is retried with that identical receipt, never FinishStep.
func (c *Client) AcknowledgeStep(ctx context.Context, receipt Receipt) (Acknowledgement, error) {
	var result Acknowledgement
	if !receipt.matches(c.intent) || receipt.VerifiedAt > time.Now().Unix() {
		return result, ErrDenied
	}
	raw, e := json.Marshal(receipt)
	if e != nil {
		return result, e
	}
	status, _, body, e := c.request(ctx, http.MethodPut, "ack", nil, raw, 4096)
	if e != nil {
		return result, e
	}
	if status != http.StatusOK || decodeReply(body, &result) != nil || result.Receipt != receipt || result.RemainingObjects < 0 || result.RemainingObjects > receipt.NewObjects || result.RemainingBytes < 0 || result.RemainingBytes > receipt.NewBytes || result.Clean != (result.RemainingObjects == 0) || (result.RemainingObjects == 0 && result.RemainingBytes != 0) {
		return Acknowledgement{}, ErrProtocol
	}
	return result, nil
}
