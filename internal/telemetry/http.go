package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

type Client struct {
	http *http.Client
	base *url.URL
}

func NewClient(endpoint string, cert tls.Certificate, roots *x509.CertPool, node, target string) (*Client, error) {
	h, u, e := peer.AuthenticatedHTTP(endpoint, cert, roots, node, target, peer.Limits{Concurrency: 1, Timeout: 15 * time.Second, Attempts: 1})
	if e != nil {
		return nil, e
	}
	return &Client{h, u}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) Send(ctx context.Context, m Message) Outcome {
	blocked := func(code string) Outcome { return Outcome{State: "BLOCKED", Code: code} }
	if !member(m.Signal, "logs", "metrics") || len(m.Body) < 1 || len(m.Body) > MaxFrame || storage.Hash(m.Body) != m.Digest {
		return blocked("INVALID_RESPONSE")
	}
	u := *c.base
	u.Path = "/v1/" + m.Signal
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(m.Body))
	if e != nil {
		return blocked("INVALID_RESPONSE")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, e := c.http.Do(request)
	if e != nil {
		var verify *tls.CertificateVerificationError
		if errors.Is(e, peer.ErrDenied) || errors.As(e, &verify) {
			return blocked("PERMANENT_REJECTION")
		}
		return Outcome{State: "RETRY_WAIT"}
	}
	defer response.Body.Close()
	// A known permanent HTTP response stays permanent even if its diagnostic
	// body is truncated. Do not turn a 4xx/500 into an automatic retry.
	retryable := response.StatusCode == 429 || response.StatusCode == 502 || response.StatusCode == 503 || response.StatusCode == 504
	if response.StatusCode != http.StatusOK && !retryable {
		return blocked("PERMANENT_REJECTION")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, MaxFrame+1))
	if len(raw) > MaxFrame {
		return blocked("INVALID_RESPONSE")
	}
	if e != nil {
		return Outcome{State: "RETRY_WAIT"}
	}
	if retryable {
		return Outcome{State: "RETRY_WAIT", RetryAfter: retryAfter(response.Header.Get("Retry-After"), time.Now())}
	}
	if response.StatusCode != http.StatusOK {
		return blocked("PERMANENT_REJECTION")
	}
	content, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || content != "application/json" || response.Header.Get("Content-Encoding") != "" || !uniqueJSON(raw) {
		return blocked("INVALID_RESPONSE")
	}
	var result struct {
		Partial json.RawMessage `json:"partialSuccess"`
	}
	if json.Unmarshal(raw, &result) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return blocked("INVALID_RESPONSE")
	}
	if len(result.Partial) == 0 || bytes.Equal(result.Partial, []byte("null")) {
		return Outcome{State: "ACCEPTED"}
	}
	var partial struct {
		Logs    json.RawMessage `json:"rejectedLogRecords"`
		Points  json.RawMessage `json:"rejectedDataPoints"`
		Message string          `json:"errorMessage"`
	}
	if json.Unmarshal(result.Partial, &partial) != nil {
		return blocked("INVALID_RESPONSE")
	}
	value, other := partial.Logs, partial.Points
	if m.Signal == "metrics" {
		value, other = other, value
	}
	if len(other) != 0 {
		return blocked("INVALID_RESPONSE")
	}
	rejected, ok := count(value)
	if !ok {
		return blocked("INVALID_RESPONSE")
	}
	// Even partial rejection is terminal for this request under OTLP. Arbitrary
	// collector diagnostic text is deliberately neither persisted nor returned.
	if rejected > 0 {
		return Outcome{State: "BLOCKED", Code: "PARTIAL_REJECTION", Rejected: rejected}
	}
	return Outcome{State: "ACCEPTED", Warning: partial.Message != ""}
}
func count(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, true
	}
	text := string(raw)
	if len(text) > 0 && text[0] == '"' {
		if json.Unmarshal(raw, &text) != nil {
			return 0, false
		}
	}
	n, e := strconv.ParseInt(text, 10, 64)
	return n, e == nil && n >= 0
}
func retryAfter(value string, now time.Time) time.Duration {
	var delay time.Duration
	if seconds, e := strconv.ParseUint(value, 10, 64); e == nil {
		if seconds > 86400 {
			return 24 * time.Hour
		}
		delay = time.Duration(seconds) * time.Second
	} else if errors.Is(e, strconv.ErrRange) && len(value) > 0 && value[0] >= '0' && value[0] <= '9' {
		return 24 * time.Hour
	} else if date, e := http.ParseTime(value); e == nil {
		delay = date.Sub(now)
	}
	if delay < 0 {
		return 0
	}
	if delay > 24*time.Hour {
		return 24 * time.Hour
	}
	return delay
}

// Unknown OTLP JSON fields are permitted, but duplicate names and ambiguous
// documents are not. Depth and bytes remain bounded for untrusted collectors.
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var parse func(int) bool
	parse = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, e := d.Token()
		if e != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				name, ok := key.(string)
				if e != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !parse(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !parse(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		return false
	}
	if !parse(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
