// Package peer implements the bounded G3 HTTPS peer transport candidate.
package peer

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
)

const Format = "outpost-peer-1"

var (
	ErrDenied      = errors.New("peer operation denied")
	ErrProtocol    = errors.New("invalid peer protocol response")
	ErrUnavailable = errors.New("peer unavailable or retry required")
	ErrConflict    = errors.New("operation binding conflict")
	ErrCapacity    = statefile.ErrCapacity
)

type Grant struct {
	Class       string `json:"class"`
	Push        bool   `json:"push"`
	Pull        bool   `json:"pull"`
	History     bool   `json:"history,omitempty"`
	ExpiresUnix int64  `json:"expiresUnix"`
}

// Policy is an explicit domain-specific edge list, supplied out of band. A
// trusted worker is still keyless; category membership never grants an edge.
type Policy struct {
	ReadbackMaxAgeSeconds int64            `json:"readbackMaxAgeSeconds,omitempty"`
	RequiredRevision      uint64           `json:"requiredRevision,omitempty"`
	Self                  string           `json:"self"`
	Class                 string           `json:"class"`
	Domain                string           `json:"domain"`
	Repository            string           `json:"repository"`
	Epoch                 uint64           `json:"epoch"`
	AllowedClasses        []string         `json:"allowedClasses"`
	Peers                 map[string]Grant `json:"peers"`
}

type Limits struct {
	Concurrency int
	Timeout     time.Duration
	Attempts    int
}

func (l Limits) valid() bool {
	return l.Concurrency >= 1 && l.Concurrency <= 4 && l.Timeout > 0 && l.Timeout <= 5*time.Minute && l.Attempts >= 1 && l.Attempts <= 3
}
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func category(s string) bool { return s == "trusted" || s == "untrusted" }
func (p Policy) allowed(c string) bool {
	for _, v := range p.AllowedClasses {
		if v == c {
			return true
		}
	}
	return false
}
func (p Policy) validate(t generation.Trust) error {
	if p.ReadbackMaxAgeSeconds < 0 || p.ReadbackMaxAgeSeconds > readback.MaxAgeSeconds {
		return ErrDenied
	}
	if !validID(p.Self) || p.Domain != t.Domain || p.Repository != t.Repository || p.Epoch != t.Epoch || !category(p.Class) || !p.allowed(p.Class) || len(p.AllowedClasses) == 0 || len(p.AllowedClasses) > 2 || len(p.Peers) == 0 || len(p.Peers) > 128 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, c := range p.AllowedClasses {
		if !category(c) || seen[c] {
			return ErrDenied
		}
		seen[c] = true
	}
	for id, g := range p.Peers {
		if !validID(id) || id == p.Self || !category(g.Class) || !p.allowed(g.Class) || (!g.Push && !g.Pull) || g.ExpiresUnix <= 0 {
			return ErrDenied
		}
	}
	return nil
}
func (p Policy) grant(id string, push bool, now time.Time) error {
	g, ok := p.Peers[id]
	if !ok || !p.allowed(g.Class) || now.Unix() >= g.ExpiresUnix || (push && !g.Push) || (!push && !g.Pull) {
		return ErrDenied
	}
	return nil
}
func clonePolicy(p Policy) Policy {
	p.AllowedClasses = append([]string(nil), p.AllowedClasses...)
	peers := map[string]Grant{}
	for id, g := range p.Peers {
		peers[id] = g
	}
	p.Peers = peers
	return p
}

// Identity pins the certificate's public key, independently of display names.
func Identity(c *x509.Certificate) string { return generation.Hash(c.RawSubjectPublicKeyInfo) }
func certCurrent(c *x509.Certificate, now time.Time) bool {
	return !now.Before(c.NotBefore) && now.Before(c.NotAfter)
}
func certificateID(c tls.Certificate) (string, error) {
	if len(c.Certificate) == 0 || c.PrivateKey == nil {
		return "", ErrDenied
	}
	leaf, e := x509.ParseCertificate(c.Certificate[0])
	if e != nil {
		return "", ErrDenied
	}
	return Identity(leaf), nil
}

func serverTLS(c tls.Certificate, roots *x509.CertPool, self string) (*tls.Config, error) {
	id, e := certificateID(c)
	if e != nil || id != self || roots == nil {
		return nil, ErrDenied
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots.Clone()}, nil
}

func clientHTTP(endpoint string, c tls.Certificate, roots *x509.CertPool, self, target string, l Limits) (*http.Client, *url.URL, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || !validID(target) || roots == nil || !l.valid() {
		return nil, nil, ErrDenied
	}
	id, e := certificateID(c)
	if e != nil || id != self {
		return nil, nil, ErrDenied
	}
	u.Path = ""
	u.RawPath = ""
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots.Clone(), Certificates: []tls.Certificate{c}, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || Identity(s.PeerCertificates[0]) != target {
			return ErrDenied
		}
		return nil
	}}
	transport := &http.Transport{TLSClientConfig: config, Proxy: nil, DisableCompression: true, MaxConnsPerHost: l.Concurrency, MaxIdleConnsPerHost: l.Concurrency, MaxIdleConns: l.Concurrency, TLSHandshakeTimeout: l.Timeout, ResponseHeaderTimeout: l.Timeout, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, Timeout: l.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, u, nil
}
