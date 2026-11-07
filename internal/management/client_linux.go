package management

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

// ReportClient only contacts the locally configured HTTPS origin and SPKI.
// Enrollment, placement and plaintext recovery keys are never fetched here.
type ReportClient struct {
	client                 *http.Client
	endpoint, target, node string
}

func NewReportClient(endpoint, target, node string, cert tls.Certificate, roots *x509.CertPool, timeout time.Duration) (*ReportClient, error) {
	u, e := url.Parse(endpoint)
	if e != nil || roots == nil || !storage.ID(target) || !storage.ID(node) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || timeout < 100*time.Millisecond || timeout > time.Minute || len(cert.Certificate) == 0 {
		return nil, ErrInvalid
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if e != nil || !ok || peer.Identity(leaf) != node {
		return nil, ErrDenied
	}
	public, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return nil, ErrDenied
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots.Clone(), VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || peer.Identity(s.PeerCertificates[0]) != target {
			return ErrDenied
		}
		return nil
	}}
	tr := &http.Transport{TLSClientConfig: cfg, Proxy: nil, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, IdleConnTimeout: 30 * time.Second}
	return &ReportClient{client: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: strings.TrimSuffix(u.String(), "/"), target: target, node: node}, nil
}
func (c *ReportClient) Close() { c.client.CloseIdleConnections() }

func (c *ReportClient) Publish(ctx context.Context, enrollment Enrollment, raw []byte) (Receipt, error) {
	var out Receipt
	if c == nil || enrollment.Node != c.node || !enrollment.Active(time.Now()) {
		return out, ErrDenied
	}
	report, e := VerifyReport(raw, enrollment, time.Now())
	if e != nil {
		return out, e
	}
	body, _ := json.Marshal(struct {
		Document []byte `json:"document"`
	}{raw})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/v1/tenants/"+enrollment.Tenant+"/nodes/"+c.node+"/reports", bytes.NewReader(body))
	if e != nil {
		return out, ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("X-Outpost-Request", "1")
	res, e := c.client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, ErrUnavailable
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.VerifiedChains) == 0 || len(res.TLS.PeerCertificates) == 0 || peer.Identity(res.TLS.PeerCertificates[0]) != c.target || !time.Now().Before(res.TLS.PeerCertificates[0].NotAfter) {
		return out, ErrDenied
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return out, ErrDenied
	case http.StatusConflict:
		return out, ErrConflict
	case http.StatusTooManyRequests:
		return out, ErrCapacity
	default:
		return out, ErrUnavailable
	}
	media, _, e := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || res.ContentLength > 4096 || res.Header.Get("Content-Encoding") != "" {
		return out, ErrInvalid
	}
	response, e := io.ReadAll(io.LimitReader(res.Body, 4097))
	if e != nil || decodeHTTP(response, &out, 4096) != nil || out != reportReceipt(raw, report.ObservedUnix) {
		return Receipt{}, ErrInvalid
	}
	return out, nil
}
