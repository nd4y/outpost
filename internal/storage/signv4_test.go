package storage

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSigV4PublishedVector(t *testing.T) {
	// Public protocol test credentials, never valid service credentials.
	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	now, _ := time.Parse("20060102T150405Z", "20130524T000000Z")
	if e := signV4(req, nil, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "us-east-1", now); e != nil {
		t.Fatal(e)
	}
	if !strings.HasSuffix(req.Header.Get("Authorization"), "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Fatal("published signature vector differs")
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
}
