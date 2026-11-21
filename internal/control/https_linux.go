package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

type Fetcher struct {
	client                 *http.Client
	endpoint, node, target string
}

func certificate(c tls.Certificate) (*x509.Certificate, error) {
	if len(c.Certificate) == 0 || c.PrivateKey == nil {
		return nil, ErrDenied
	}
	return x509.ParseCertificate(c.Certificate[0])
}
func NewFetcher(endpoint, target, node string, cert tls.Certificate, roots *x509.CertPool, timeout time.Duration) (*Fetcher, error) {
	u, e := url.Parse(endpoint)
	leaf, ce := certificate(cert)
	if e != nil || ce != nil || peer.Identity(leaf) != node || roots == nil || !storage.ID(target) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || timeout <= 0 || timeout > time.Minute {
		return nil, ErrDenied
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots.Clone(), VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || peer.Identity(s.PeerCertificates[0]) != target {
			return ErrDenied
		}
		return nil
	}}
	tr := &http.Transport{TLSClientConfig: cfg, Proxy: nil, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, IdleConnTimeout: 30 * time.Second}
	return &Fetcher{&http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, strings.TrimSuffix(u.String(), "/"), node, target}, nil
}
func (f *Fetcher) Close()                                    { f.client.CloseIdleConnections() }
func (f *Fetcher) Fetch(ctx context.Context) ([]byte, error) { return f.FetchFor(ctx, f.node) }

// FetchFor is used by a relay whose separate server ACL authorizes the target.
func (f *Fetcher) FetchFor(ctx context.Context, node string) ([]byte, error) {
	if !storage.ID(node) {
		return nil, ErrDenied
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, f.endpoint+"/v1/config/"+node, nil)
	if e != nil {
		return nil, ErrDenied
	}
	req.Header.Set("Accept-Encoding", "identity")
	res, e := f.client.Do(req)
	if e != nil {
		return nil, ErrDenied
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.TLS == nil || len(res.TLS.VerifiedChains) == 0 || len(res.TLS.PeerCertificates) == 0 || peer.Identity(res.TLS.PeerCertificates[0]) != f.target || !time.Now().Before(res.TLS.PeerCertificates[0].NotAfter) || res.ContentLength > MaxConfig || res.Header.Get("Content-Encoding") != "" {
		return nil, ErrDenied
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, MaxConfig+1))
	if e != nil || len(b) == 0 || len(b) > MaxConfig {
		return nil, ErrDenied
	}
	return b, nil
}

// Handler serves verified caches only. ACL maps authenticated SPKI IDs to
// recipient node IDs. A relay needs an explicit per-recipient entry as well.
func Handler(caches map[string]*Cache, acl map[string][]string) (http.Handler, error) {
	if len(caches) == 0 || len(caches) > 128 || len(acl) == 0 || len(acl) > 128 {
		return nil, ErrDenied
	}
	copies := map[string]*Cache{}
	for id, c := range caches {
		if !storage.ID(id) || c == nil || c.node != id {
			return nil, ErrDenied
		}
		copies[id] = c
	}
	grants := map[string]map[string]bool{}
	for id, recipients := range acl {
		if !storage.ID(id) || len(recipients) == 0 || len(recipients) > 128 {
			return nil, ErrDenied
		}
		grants[id] = map[string]bool{}
		for _, node := range recipients {
			if copies[node] == nil || grants[id][node] {
				return nil, ErrDenied
			}
			grants[id][node] = true
		}
	}
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, "/v1/config/") || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		node := strings.TrimPrefix(r.URL.Path, "/v1/config/")
		now := time.Now()
		if !storage.ID(node) || !grants[peer.Identity(cert)][node] || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		raw, e := copies[node].Raw(r.Context())
		if e != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}), nil
}
func ServerTLS(cert tls.Certificate, roots *x509.CertPool, self string) (*tls.Config, error) {
	leaf, e := certificate(cert)
	if e != nil || peer.Identity(leaf) != self || roots == nil {
		return nil, ErrDenied
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots.Clone()}, nil
}
