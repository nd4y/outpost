package peer

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
)

// AuthenticatedHTTP shares transport-only TLS restrictions with other scoped
// protocols. Callers still enforce their own operation and placement authority.
func AuthenticatedHTTP(endpoint string, cert tls.Certificate, roots *x509.CertPool, self, target string, limits Limits) (*http.Client, *url.URL, error) {
	return clientHTTP(endpoint, cert, roots, self, target, limits)
}

// AuthenticatedServerTLS requires mutual TLS; the protocol handler must also
// authorize the authenticated public-key identity for every requested action.
func AuthenticatedServerTLS(cert tls.Certificate, roots *x509.CertPool, self string) (*tls.Config, error) {
	return serverTLS(cert, roots, self)
}
