package observation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

type Client struct {
	http        *http.Client
	base, self  string
	grant       []byte
	parsed      Grant
	owner       ed25519.PublicKey
	certificate *x509.Certificate
}

func NewClient(endpoint string, grant []byte, owner ed25519.PublicKey, cert tls.Certificate, roots *x509.CertPool, timeout time.Duration) (*Client, error) {
	g, e := VerifyGrant(grant, owner)
	if e != nil || len(cert.Certificate) == 0 {
		return nil, ErrDenied
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, e
	}
	self := peer.Identity(leaf)
	if self != g.Reader && !g.Target(self) {
		return nil, ErrDenied
	}
	h, u, e := peer.AuthenticatedHTTP(endpoint, cert, roots, self, g.Collector, peer.Limits{Concurrency: 1, Timeout: timeout, Attempts: 1})
	if e != nil {
		return nil, e
	}
	return &Client{h, strings.TrimRight(u.String(), "/"), self, bytes.Clone(grant), g, bytes.Clone(owner), leaf}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) active() bool {
	now := time.Now()
	return c.parsed.Active(now) && !now.Before(c.certificate.NotBefore) && now.Before(c.certificate.NotAfter)
}
func (c *Client) request(ctx context.Context, method, id, target string, body []byte) ([]byte, error) {
	if !storage.ID(id) || !c.active() {
		return nil, ErrDenied
	}
	u := c.base + "/v1/" + c.parsed.Trust.Domain + "/observations/" + storage.Hash(c.grant) + "/" + id
	if target != "" {
		u += "/" + target
	}
	r, e := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(r)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.VerifiedChains) == 0 || len(res.TLS.PeerCertificates) == 0 || peer.Identity(res.TLS.PeerCertificates[0]) != c.parsed.Collector {
		return nil, ErrDenied
	}
	leaf := res.TLS.PeerCertificates[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, ErrDenied
	}
	if res.StatusCode == 403 || res.StatusCode == 401 {
		return nil, ErrDenied
	}
	if res.StatusCode != 200 {
		return nil, ErrPending
	}
	if res.ContentLength > MaxReply || res.Header.Get("Content-Encoding") != "" {
		return nil, ErrDenied
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, MaxReply+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > MaxReply || !c.active() || !time.Now().Before(leaf.NotAfter) {
		return nil, ErrDenied
	}
	return raw, nil
}
func (c *Client) Publish(ctx context.Context, raw []byte) error {
	var p Proof
	if storage.Decode(raw, &p, MaxDocument) != nil {
		return ErrDenied
	}
	verified, e := VerifyProof(raw, c.grant, c.owner, p.Generation, time.Now())
	if e != nil || verified.Target != c.self {
		return ErrDenied
	}
	got, e := c.request(ctx, http.MethodPut, p.Generation, c.self, raw)
	if e != nil {
		return e
	}
	if !bytes.Equal(got, raw) {
		return ErrDenied
	}
	return nil
}
func (c *Client) Read(ctx context.Context, id string) ([]json.RawMessage, error) {
	if c.self != c.parsed.Reader {
		return nil, ErrDenied
	}
	raw, e := c.request(ctx, http.MethodGet, id, "", nil)
	if e != nil {
		return nil, e
	}
	var b Bundle
	if storage.Decode(raw, &b, MaxReply) != nil || b.Format != ProofFormat || b.Grant != storage.Hash(c.grant) || b.Generation != id || len(b.Proofs) > len(c.parsed.Targets) {
		return nil, ErrDenied
	}
	seen := map[string]bool{}
	for _, raw := range b.Proofs {
		p, e := VerifyProof(raw, c.grant, c.owner, id, time.Now())
		if e != nil || seen[p.Target] {
			return nil, ErrDenied
		}
		seen[p.Target] = true
	}
	return b.Proofs, nil
}
