package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

func mac(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}
func uriPath(s string) string {
	if s == "" {
		return "/"
	}
	const digits = "0123456789ABCDEF"
	var out strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~/", rune(c)) {
			out.WriteByte(c)
		} else {
			out.WriteByte('%')
			out.WriteByte(digits[c>>4])
			out.WriteByte(digits[c&15])
		}
	}
	return out.String()
}

// signV4 signs bounded non-streaming S3 requests. Credentials are never logged.
func signV4(r *http.Request, payload []byte, access, secret, token, region string, now time.Time) error {
	bad := errors.New("invalid request signing input")
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.Host == "" || r.URL.User != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.Opaque != "" || access == "" || secret == "" || !safeName(region, 64) || strings.ContainsAny(access+secret+token, "\r\n") || strings.ContainsAny(access, " /,\t") {
		return bad
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodHead {
		return bad
	}
	now = now.UTC()
	date := now.Format("20060102")
	stamp := now.Format("20060102T150405Z")
	digest := Hash(payload)
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("X-Amz-Date", stamp)
	r.Header.Set("X-Amz-Content-Sha256", digest)
	r.Header.Del("X-Amz-Security-Token")
	if token != "" {
		r.Header.Set("X-Amz-Security-Token", token)
	}
	host := r.URL.Host
	if r.Host != "" {
		host = r.Host
	}
	values := map[string]string{"host": host}
	for name, all := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") || lower == "range" || lower == "if-none-match" {
			v := strings.Join(all, ",")
			if strings.ContainsAny(v, "\r\n") {
				return bad
			}
			values[lower] = strings.Join(strings.Fields(v), " ")
		}
	}
	if strings.ContainsAny(host, "\r\n") {
		return bad
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var headers strings.Builder
	for _, name := range names {
		headers.WriteString(name + ":" + values[name] + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := r.Method + "\n" + uriPath(r.URL.Path) + "\n\n" + headers.String() + "\n" + signed + "\n" + digest
	scope := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + Hash([]byte(canonical))
	key := mac([]byte("AWS4"+secret), date)
	key = mac(key, region)
	key = mac(key, "s3")
	key = mac(key, "aws4_request")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+access+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(mac(key, stringToSign)))
	return nil
}
