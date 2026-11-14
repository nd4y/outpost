package storage

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSigV4SDKSignsImplicitLengthAndWirePath(t *testing.T) {
	const body = "payload"
	const path = "/bucket/a%20b/%24/%D1%8F"
	req, err := http.NewRequest(http.MethodPut, "https://objects.invalid"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("If-None-Match", "*")
	now, _ := time.Parse("20060102T150405Z", "20130524T000000Z")
	if err := signV4(req, []byte(body), "synthetic-vector", "synthetic-vector-secret", "synthetic-token", "test-region", now); err != nil {
		t.Fatal(err)
	}
	if req.URL.EscapedPath() != path || req.Header.Get("X-Amz-Content-Sha256") != Hash([]byte(body)) {
		t.Fatal("SDK changed the wire path or exact payload digest")
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=content-length;host;if-none-match;x-amz-content-sha256;x-amz-date;x-amz-security-token") {
		t.Fatal("implicit length and conditional/token fields were not signed")
	}
	// Independent Python HMAC-SHA256 vector, including implicit Content-Length.
	const expectedSignature = "d19cdb2cbb025da1687392f1009194d9b3d04e9d736a191cfc901ea25fa53cae"
	if !strings.HasSuffix(auth, "Signature="+expectedSignature) {
		t.Fatal("independent SDK framing signature vector differs")
	}
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatal(err)
	}
	parsed, err := http.ReadRequest(bufio.NewReader(&wire))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Body.Close()
	actual, err := io.ReadAll(parsed.Body)
	if err != nil || string(actual) != body || parsed.RequestURI != path || parsed.ContentLength != int64(len(body)) || parsed.Header.Get("Authorization") != auth {
		t.Fatal("signed request differs from serialized HTTP framing", err)
	}
}

func TestSigV4SDKRefusesAmbiguousPathsAndCancelledRequests(t *testing.T) {
	for _, path := range []string{"/bucket/a%2Fb", "/bucket/%61"} {
		req, err := http.NewRequest(http.MethodGet, "https://objects.invalid"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		before := req.URL.String()
		if signV4(req, nil, "test-access", "test-secret", "", "test-region", time.Now()) == nil || req.URL.String() != before || req.Header.Get("Authorization") != "" {
			t.Fatal("noncanonical path was signed or rewritten")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://objects.invalid/bucket/part", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signV4(req, nil, "test-access", "test-secret", "", "test-region", time.Now()); !errors.Is(err, context.Canceled) || req.Header.Get("Authorization") != "" {
		t.Fatal("cancelled request reached signing", err)
	}
}

func TestSigV4IndependentVectors(t *testing.T) {
	// Frozen synthetic vectors calculated independently with Python HMAC-SHA256.
	now, _ := time.Parse("20060102T150405Z", "20130524T000000Z")
	for _, vector := range []struct{ method, query, body, signature string }{
		{"GET", "", "", "d2b94fd907fc2e24f9faa178aa59c214a8fe07de6e87c484d566ee3513f24ccc"},
		{"POST", "?restore=", "<RestoreRequest/>", "6922ac023f1806e214d221d348af6620ceb1ecea38e3eca5d5138242904c4598"},
	} {
		req, _ := http.NewRequest(vector.method, "https://objects.invalid/test.txt"+vector.query, nil)
		if vector.method == "GET" {
			req.Header.Set("Range", "bytes=0-9")
		}
		if err := signV4(req, []byte(vector.body), "synthetic-vector", "synthetic-vector-secret", "", "test-region", now); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(req.Header.Get("Authorization"), "Signature="+vector.signature) {
			t.Fatal("independent signature vector differs", vector.method)
		}
	}
}
func TestSigV4ConditionalTokenAndInput(t *testing.T) {
	req, _ := http.NewRequest("PUT", "https://objects.invalid/bucket/a%20b", nil)
	req.Header.Set("If-None-Match", "*")
	if e := signV4(req, []byte("payload"), "test-access", "test-secret", "test-token", "test-region", time.Unix(1700000000, 0)); e != nil {
		t.Fatal(e)
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=host;if-none-match;x-amz-content-sha256;x-amz-date;x-amz-security-token") || req.Header.Get("X-Amz-Security-Token") != "test-token" {
		t.Fatal("conditional/token header not signed")
	}
	if uriPath("/a b/$/я") != "/a%20b/%24/%D1%8F" {
		t.Fatal("URI escaping differs")
	}
	for _, url := range []string{"http://objects.invalid/", "https://objects.invalid/?x=1", "https://name:password@objects.invalid/", "https://objects.invalid/#fragment"} {
		r, _ := http.NewRequest("GET", url, nil)
		if signV4(r, nil, "test", "test", "", "test-region", time.Now()) == nil {
			t.Fatal("unsafe signing URL accepted")
		}
	}
	for _, query := range []string{"", "?restore=1", "?restore=&other=", "?delete="} {
		req, _ := http.NewRequest(http.MethodPost, "https://objects.invalid/test.txt"+query, nil)
		if signV4(req, []byte("payload"), "test", "test", "", "test-region", time.Unix(1700000000, 0)) == nil {
			t.Fatal("POST outside the archive protocol was signed")
		}
	}
}
