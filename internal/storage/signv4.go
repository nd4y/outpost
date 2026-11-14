package storage

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/encoding/httpbinding"
)

func uriPath(s string) string {
	if s == "" {
		return "/"
	}
	return httpbinding.EscapePath(s, false)
}

// signV4 signs bounded non-streaming S3 requests. Credentials are never logged.
func signV4(r *http.Request, payload []byte, access, secret, token, region string, now time.Time) error {
	bad := errors.New("invalid request signing input")
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.Host == "" || r.URL.User != nil || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.Opaque != "" || access == "" || secret == "" || !safeName(region, 64) || strings.ContainsAny(access+secret+token, "\r\n") || strings.ContainsAny(access, " /,\t") {
		return bad
	}
	if e := r.Context().Err(); e != nil {
		return e
	}
	switch r.Method {
	case http.MethodGet, http.MethodPut, http.MethodHead:
		if r.URL.RawQuery != "" {
			return bad
		}
	case http.MethodPost:
		if r.URL.RawQuery != restoreQuery || len(payload) == 0 {
			return bad
		}
	default:
		return bad
	}
	path := uriPath(r.URL.Path)
	// S3 signs the path sent on the wire without an additional escaping pass.
	// Refuse an alternative RawPath instead of changing an encoded separator.
	if r.URL.RawPath != "" && r.URL.RawPath != path || strings.ContainsAny(r.Host+r.URL.Host, "\r\n") {
		return bad
	}
	for _, values := range r.Header {
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return bad
			}
		}
	}
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	digest := Hash(payload)
	r.Header.Set("X-Amz-Content-Sha256", digest)
	r.Header.Del("X-Amz-Security-Token")
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	r.URL.RawPath = path
	// SignHTTP performs no I/O. Credential discovery, endpoint selection and
	// retries stay outside the SDK and retain the admitted Outpost bounds.
	credentials := aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: token}
	signer := v4.NewSigner(func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = true
		o.LogSigning = false
	})
	if e := signer.SignHTTP(r.Context(), credentials, r, digest, "s3", region, now.UTC()); e != nil {
		return bad
	}
	return nil
}
