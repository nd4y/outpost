package telemetry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func tlsFixture(t *testing.T, handler http.Handler) (*httptest.Server, *Client, tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic telemetry CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(raw)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(serial int64) tls.Certificate {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		b, e := x509.CreateCertificate(rand.Reader, template, ca, p, key)
		if e != nil {
			t.Fatal(e)
		}
		parsed, _ := x509.ParseCertificate(b)
		return tls.Certificate{Certificate: [][]byte{b, ca.Raw}, PrivateKey: k, Leaf: parsed}
	}
	serverCert, clientCert := leaf(2), leaf(3)
	config, e := peer.AuthenticatedServerTLS(serverCert, roots, peer.Identity(serverCert.Leaf))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = config
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	client, e := NewClient(server.URL, clientCert, roots, peer.Identity(clientCert.Leaf), peer.Identity(serverCert.Leaf))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return server, client, clientCert, roots
}
func TestTelemetryHTTPOutcomesAndBoundedResponses(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body, content string
		state, code   string
	}{
		{"accepted", 200, `{}`, "application/json", "ACCEPTED", ""},
		{"unknown-fields", 200, `{"newField":true}`, "application/json", "ACCEPTED", ""},
		{"warning", 200, `{"partialSuccess":{"rejectedLogRecords":"0","errorMessage":"private remote diagnostic"}}`, "application/json", "ACCEPTED", ""},
		{"partial", 200, `{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"private remote diagnostic"}}`, "application/json", "BLOCKED", "PARTIAL_REJECTION"},
		{"numeric-partial", 200, `{"partialSuccess":{"rejectedLogRecords":1}}`, "application/json", "BLOCKED", "PARTIAL_REJECTION"},
		{"duplicate", 200, `{"partialSuccess":{"rejectedLogRecords":"1","rejectedLogRecords":"0"}}`, "application/json", "BLOCKED", "INVALID_RESPONSE"},
		{"negative", 200, `{"partialSuccess":{"rejectedLogRecords":"-1"}}`, "application/json", "BLOCKED", "INVALID_RESPONSE"},
		{"wrong-signal", 200, `{"partialSuccess":{"rejectedDataPoints":"3"}}`, "application/json", "BLOCKED", "INVALID_RESPONSE"},
		{"bad-json", 200, `{`, "application/json", "BLOCKED", "INVALID_RESPONSE"},
		{"null", 200, `null`, "application/json", "BLOCKED", "INVALID_RESPONSE"},
		{"empty", 200, ``, "application/json", "BLOCKED", "INVALID_RESPONSE"},
		{"wrong-type", 200, `{}`, "text/plain", "BLOCKED", "INVALID_RESPONSE"},
		{"oversized", 200, strings.Repeat(" ", MaxFrame+1), "application/json", "BLOCKED", "INVALID_RESPONSE"},
		{"permanent", 500, `{}`, "application/json", "BLOCKED", "PERMANENT_REJECTION"},
		{"unauthorized", 403, `{}`, "application/json", "BLOCKED", "PERMANENT_REJECTION"},
		{"retry", 503, `{}`, "application/json", "RETRY_WAIT", ""},
		{"throttle", 429, `{}`, "application/json", "RETRY_WAIT", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var received []byte
			_, client, _, _ := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/logs" || r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || len(r.TLS.PeerCertificates) == 0 {
					t.Error("request contract")
				}
				received, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", tc.content)
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			messages, _ := Encode(storage.Hash([]byte("node")), storage.Hash([]byte("domain")), fixtureRecord())
			out := client.Send(context.Background(), messages[0])
			if out.State != tc.state || out.Code != tc.code || !bytes.Equal(received, messages[0].Body) {
				t.Fatal(out)
			}
			if tc.state == "RETRY_WAIT" && out.RetryAfter != 120*time.Second {
				t.Fatal(out)
			}
		})
	}
}
func TestTelemetryTLSIdentityRedirectAndRetryAfter(t *testing.T) {
	var hits atomic.Int32
	forbidden := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer forbidden.Close()
	server, client, cert, roots := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, forbidden.URL, 307) }))
	messages, _ := Encode(storage.Hash([]byte("node")), storage.Hash([]byte("domain")), fixtureRecord())
	out := client.Send(context.Background(), messages[0])
	if out.State != "BLOCKED" || hits.Load() != 0 {
		t.Fatal(out, hits.Load())
	}
	wrong, e := NewClient(server.URL, cert, roots, peer.Identity(cert.Leaf), storage.Hash([]byte("wrong")))
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	out = wrong.Send(context.Background(), messages[0])
	if out.State != "BLOCKED" {
		t.Fatal(out)
	}
	for _, endpoint := range []string{"http://127.0.0.1", server.URL + "/other", server.URL + "?credential=invalid"} {
		if c, e := NewClient(endpoint, cert, roots, peer.Identity(cert.Leaf), storage.Hash([]byte("target"))); e == nil {
			c.Close()
			t.Fatal("unsafe endpoint")
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if retryAfter(now.Add(time.Minute).Format(http.TimeFormat), now) != time.Minute || retryAfter("18446744073709551615", now) != 24*time.Hour || retryAfter("-3", now) != 0 {
		t.Fatal("retry bounds")
	}
}
