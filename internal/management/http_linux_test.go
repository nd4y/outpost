package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
)

type httpFixture struct {
	f                            *fixture
	server                       *httptest.Server
	owner, node, viewer, unknown *http.Client
	handler                      http.Handler
}

func newHTTPFixture(t *testing.T) *httpFixture {
	return newHTTPFixtureWithRelay(t, false)
}
func newHTTPFixtureWithRelay(t *testing.T, allowRelay bool) *httpFixture {
	t.Helper()
	f := newFixture(t)
	now := time.Now()
	caPub, caKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	must(t, e)
	ca, e = x509.ParseCertificate(der)
	must(t, e)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cert := func(key ed25519.PrivateKey, serial int64, server bool) tls.Certificate {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, e := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
		must(t, e)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	_, ownerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	_, viewerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	_, unknownKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.p.Actor = identity(ownerKey.Public().(ed25519.PublicKey))
	viewer := Principal{Actor: identity(viewerKey.Public().(ed25519.PublicKey)), Roles: []string{"viewer"}, Scopes: append([]Scope(nil), f.p.Scopes...)}
	options := HTTPOptions{Principals: []Principal{f.p, viewer}, Origin: "https://management.invalid", Concurrency: 2, Timeout: 500 * time.Millisecond, ReportMaxAge: 5 * time.Second}
	if allowRelay {
		options.Relays = map[string][]string{viewer.Actor: {f.e.Node}}
	}
	h, e := Handler(f.r, options)
	must(t, e)
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert(f.options.Signer, 2, true)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	t.Cleanup(s.Close)
	client := func(key ed25519.PrivateKey, serial int64) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert(key, serial, false)}}, Proxy: nil}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &httpFixture{f: f, server: s, owner: client(ownerKey, 3), node: client(f.node, 4), viewer: client(viewerKey, 5), unknown: client(unknownKey, 6), handler: h}
}
func (h *httpFixture) base() string {
	return "/api/v1/tenants/" + h.f.e.Tenant + "/nodes/" + h.f.e.Node
}
func (h *httpFixture) request(t *testing.T, client *http.Client, method, path string, body any) (int, []byte) {
	t.Helper()
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		must(t, e)
	}
	req, e := http.NewRequest(method, h.server.URL+path, bytes.NewReader(raw))
	must(t, e)
	if method != "GET" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Outpost-Request", "1")
		req.Header.Set("Origin", "https://management.invalid")
	}
	res, e := client.Do(req)
	must(t, e)
	defer res.Body.Close()
	raw, e = io.ReadAll(io.LimitReader(res.Body, 16<<20))
	must(t, e)
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("private response cache/CORS")
	}
	return res.StatusCode, raw
}
func TestManagementHTTPSConsumerEnrollmentPreviewReportsAndRoles(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	status, _ := h.request(t, h.owner, "GET", "/api/v1/session", nil)
	if status != 200 {
		t.Fatal("owner session", status)
	}
	status, _ = h.request(t, h.unknown, "GET", "/api/v1/session", nil)
	if status != 403 {
		t.Fatal("unknown certificate principal admitted", status)
	}
	enrollment, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	mutation := SignedMutation{Operation: id("http-enroll"), Reason: "INITIAL_ENROLLMENT", Document: enrollment}
	status, _ = h.request(t, h.viewer, "PUT", h.base()+"/enrollment", mutation)
	if status != 403 {
		t.Fatal("viewer enrolled", status)
	}
	status, raw := h.request(t, h.owner, "PUT", h.base()+"/enrollment", mutation)
	if status != 200 {
		t.Fatalf("enrollment %d %s", status, raw)
	}
	status, _ = h.request(t, h.node, "GET", "/api/v1/session", nil)
	if status != 200 {
		t.Fatal("enrolled node unavailable", status)
	}
	c := configFixture(t, f)
	input := configurationMutation(t, f, c, "http-config", 0)
	status, raw = h.request(t, h.owner, "POST", h.base()+"/configuration/preview", input)
	if status != 200 {
		t.Fatalf("preview %d %s", status, raw)
	}
	var preview Preview
	must(t, json.Unmarshal(raw, &preview))
	input.PreviewDigest = preview.CandidateDigest
	status, _ = h.request(t, h.viewer, "PUT", h.base()+"/configuration", input)
	if status != 403 {
		t.Fatal("viewer applied policy", status)
	}
	status, raw = h.request(t, h.owner, "PUT", h.base()+"/configuration", input)
	if status != 200 {
		t.Fatalf("apply %d %s", status, raw)
	}
	status, raw = h.request(t, h.node, "GET", h.base()+"/configuration", nil)
	if status != 200 {
		t.Fatal("node configuration", status)
	}
	var got Configuration
	must(t, json.Unmarshal(raw, &got))
	if !bytes.Equal(got.Document, input.Document) {
		t.Fatal("HTTPS changed owner signed bytes")
	}
	tlsConfig := h.node.Transport.(*http.Transport).TLSClientConfig
	fetcher, e := control.NewFetcher(h.server.URL, identity(f.options.Signer.Public().(ed25519.PublicKey)), f.e.Node, tlsConfig.Certificates[0], tlsConfig.RootCAs, time.Second)
	must(t, e)
	defer fetcher.Close()
	fetched, e := fetcher.Fetch(context.Background())
	must(t, e)
	if !bytes.Equal(fetched, input.Document) {
		t.Fatal("existing worker fetch protocol changed signed bytes")
	}
	status, _ = h.request(t, h.viewer, "GET", "/v1/config/"+f.e.Node, nil)
	if status != 403 {
		t.Fatal("viewer bypassed explicit relay grant", status)
	}
	signed := f.report(t, 1, time.Now().Unix()-60)
	status, raw = h.request(t, h.node, "POST", h.base()+"/reports", map[string]any{"document": signed})
	if status != 200 {
		t.Fatalf("report %d %s", status, raw)
	}
	status, raw = h.request(t, h.viewer, "GET", h.base()+"/domains/"+id("domain")+"/report", nil)
	if status != 200 {
		t.Fatal("viewer report", status)
	}
	var view ReportView
	must(t, json.Unmarshal(raw, &view))
	if view.State != "STALE" || view.ObservedUnix >= time.Now().Unix()-30 {
		t.Fatal("stale report refreshed", view)
	}
	status, _ = h.request(t, h.viewer, "GET", h.base()+"/domains/"+id("ungranted-domain")+"/report", nil)
	if status != 403 {
		t.Fatal("foreign domain visible", status)
	}
	status, _ = h.request(t, h.viewer, "GET", "/api/v1/tenants/"+id("foreign-tenant")+"/nodes", nil)
	if status != 403 {
		t.Fatal("foreign tenant visible", status)
	}
	status, raw = h.request(t, h.owner, "GET", "/api/v1/tenants/"+f.e.Tenant+"/audit", nil)
	if status != 200 {
		t.Fatal("audit unavailable", status)
	}
	var audit AuditPage
	must(t, json.Unmarshal(raw, &audit))
	if len(audit.Items) != 2 {
		t.Fatal("audit missing accepted effects")
	}
	status, _ = h.request(t, h.viewer, "GET", "/api/v1/tenants/"+f.e.Tenant+"/audit", nil)
	if status != 403 {
		t.Fatal("viewer audit permission expanded", status)
	}
}
func TestManagementHTTPSRejectsCSRFEncodedAliasesDuplicateFieldsAndOversize(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	f.enroll(t)
	enrollment, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	body, _ := json.Marshal(SignedMutation{Operation: id("request"), Reason: "POLICY_CHANGE", Document: enrollment, Expected: 1})
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") }, func(r *http.Request) { r.Header.Del("X-Outpost-Request") }, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }} {
		req, e := http.NewRequest("PUT", h.server.URL+h.base()+"/enrollment", bytes.NewReader(body))
		must(t, e)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Outpost-Request", "1")
		change(req)
		res, e := h.owner.Do(req)
		must(t, e)
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatal("CSRF accepted", res.StatusCode)
		}
	}
	for _, body := range []string{`{"operationId":"` + id("one") + `","operationId":"` + id("two") + `"}`, strings.Repeat("[", 34) + strings.Repeat("]", 34)} {
		req, e := http.NewRequest("PUT", h.server.URL+h.base()+"/enrollment", strings.NewReader(body))
		must(t, e)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Outpost-Request", "1")
		res, e := h.owner.Do(req)
		must(t, e)
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Fatal("ambiguous/deep body accepted", res.StatusCode)
		}
	}
	status, _ := h.request(t, h.owner, "GET", "/api/v1/tenants/"+f.e.Tenant+"/nodes?limit=1&limit=2", nil)
	if status != 400 {
		t.Fatal("duplicate query accepted", status)
	}
	status, _ = h.request(t, h.owner, "GET", strings.Replace(h.base(), "/nodes/", "/%6eodes/", 1)+"/configuration", nil)
	if status != 400 {
		t.Fatal("encoded path alias accepted", status)
	}
	req, e := http.NewRequest("PUT", h.server.URL+h.base()+"/enrollment", strings.NewReader(strings.Repeat("x", 2*MaxEnrollment+1)))
	must(t, e)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Outpost-Request", "1")
	res, e := h.owner.Do(req)
	must(t, e)
	res.Body.Close()
	if res.StatusCode != 413 {
		t.Fatal("oversized body accepted", res.StatusCode)
	}
	plain := httptest.NewRecorder()
	h.handler.ServeHTTP(plain, httptest.NewRequest("GET", "/api/v1/session", nil))
	if plain.Code != 403 {
		t.Fatal("plaintext request accepted")
	}
}
func TestManagementCursorBindingAndRevisionPreventMixedSnapshots(t *testing.T) {
	f := newFixture(t)
	f.enroll(t)
	ctx := context.Background()
	otherPub, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	other := f.e
	other.Node = identity(otherPub)
	other.PublicKey = otherPub
	raw, e := SignEnrollment(other, f.owner)
	must(t, e)
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("other-enroll"), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	path := "/api/v1/tenants/" + f.e.Tenant + "/nodes"
	first, e := f.r.Nodes(ctx, f.p, f.e.Tenant, 1, "", path, time.Minute)
	must(t, e)
	if len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatal("page absent")
	}
	second, e := f.r.Nodes(ctx, f.p, f.e.Tenant, 1, first.NextCursor, path, time.Minute)
	must(t, e)
	if len(second.Items) != 1 || second.Items[0].Node == first.Items[0].Node {
		t.Fatal("pagination repeated node")
	}
	if _, e = f.r.Nodes(ctx, f.p, f.e.Tenant, 1, first.NextCursor, path+"-other", time.Minute); !errors.Is(e, ErrConflict) {
		t.Fatal("cursor rebound", e)
	}
	_, e = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, f.report(t, 1, time.Now().Unix()))
	must(t, e)
	if _, e = f.r.Nodes(ctx, f.p, f.e.Tenant, 1, first.NextCursor, path, time.Minute); !errors.Is(e, ErrConflict) {
		t.Fatal("stale cursor combined revisions", e)
	}
}
