// Package storage implements bounded, namespace-scoped external object IO.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrDenied      = errors.New("external storage access denied")
	ErrNotFound    = errors.New("external object absent")
	ErrConflict    = errors.New("external immutable object conflict")
	ErrUnavailable = errors.New("external storage retry required")
	ErrIntegrity   = errors.New("external object integrity failure")
	ErrCapacity    = errors.New("external storage capacity or object limit")
	ErrUnsupported = errors.New("external storage capability not supported")
)

const MaxPhysical = 8 << 20

func Hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func ID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func safeName(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Profile contains no credentials. Endpoint is an explicitly provisioned bucket
// prefix or existing collection; keys are flat within this namespace.
type Profile struct {
	Kind               string `json:"kind"`
	Endpoint           string `json:"endpoint"`
	Namespace          string `json:"namespace"`
	Region             string `json:"region,omitempty"`
	MaxObjectBytes     int    `json:"maxObjectBytes"`
	Concurrency        int    `json:"concurrency"`
	RequestsPerSecond  int    `json:"requestsPerSecond"`
	Attempts           int    `json:"attempts"`
	TimeoutMillis      int    `json:"timeoutMillis"`
	CredentialScope    string `json:"credentialScope"`
	NoDelete           bool   `json:"noDelete"`
	WriteMode          string `json:"writeMode,omitempty"`
	MaxStagingAttempts int    `json:"maxStagingAttempts,omitempty"`
}

func (p Profile) ID() string { b, _ := json.Marshal(p); return Hash(b) }
func (p Profile) Validate() error {
	if p.WriteMode != "" && (p.WriteMode != WebDAVMoveMode || p.Kind != "webdav" || p.MaxStagingAttempts < 1 || p.MaxStagingAttempts > 8) || p.WriteMode == "" && p.MaxStagingAttempts != 0 {
		return ErrDenied
	}
	if p.Kind != "s3" && p.Kind != "webdav" || !ID(p.Namespace) || p.MaxObjectBytes < 64<<10 || p.MaxObjectBytes > MaxPhysical || p.Concurrency < 1 || p.Concurrency > 4 || p.RequestsPerSecond < 1 || p.RequestsPerSecond > 1000 || p.Attempts < 1 || p.Attempts > 3 || p.TimeoutMillis < 1 || p.TimeoutMillis > 300000 || (p.CredentialScope != "namespace" && p.CredentialScope != "account") || !p.NoDelete {
		return ErrDenied
	}
	if p.Kind == "s3" && !safeName(p.Region, 64) || p.Kind == "webdav" && p.Region != "" {
		return ErrDenied
	}
	_, e := origin(p.Endpoint)
	return e
}
func origin(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(u.Path, "\x00\\\r\n") {
		return nil, ErrDenied
	}
	for _, s := range strings.Split(u.Path, "/") {
		if s == "." || s == ".." {
			return nil, ErrDenied
		}
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	u.RawPath = ""
	return u, nil
}

type Credentials struct {
	Access       string `json:"-"`
	Secret       string `json:"-"`
	SessionToken string `json:"-"`
	ExpiresUnix  int64  `json:"-"`
}
type Backend struct {
	profile     Profile
	credentials Credentials
	base        *url.URL
	client      *http.Client
	gate        *RequestGate
	account     *RequestGate
	bodyBudget  *HTTPBodyBudget
}

// RequestGate shares request admission without sharing credentials or
// transports. The optional exact profile binding distinguishes target gates.
type RequestGate struct {
	profile  Profile
	slots    chan struct{}
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func NewRequestGate(p Profile) (*RequestGate, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &RequestGate{profile: p, slots: make(chan struct{}, p.Concurrency), interval: time.Second / time.Duration(p.RequestsPerSecond)}, nil
}

func NewAccountRequestGate(concurrency, requestsPerSecond int) (*RequestGate, error) {
	if concurrency < 1 || concurrency > 4 || requestsPerSecond < 1 || requestsPerSecond > 1000 {
		return nil, ErrDenied
	}
	return &RequestGate{slots: make(chan struct{}, concurrency), interval: time.Second / time.Duration(requestsPerSecond)}, nil
}

func New(p Profile, c Credentials, roots *x509.CertPool) (*Backend, error) {
	gate, e := NewRequestGate(p)
	if e != nil {
		return nil, e
	}
	if c.Access == "" || c.Secret == "" || strings.ContainsAny(c.Access+c.Secret+c.SessionToken, "\r\n") || c.ExpiresUnix <= time.Now().Unix() {
		return nil, ErrDenied
	}
	if p.Kind == "webdav" && (strings.Contains(c.Access, ":") || c.SessionToken != "") {
		return nil, ErrDenied
	}
	u, _ := origin(p.Endpoint)
	var ca *x509.CertPool
	if roots != nil {
		ca = roots.Clone()
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca}, DisableCompression: true, MaxConnsPerHost: p.Concurrency, MaxIdleConnsPerHost: p.Concurrency, MaxIdleConns: p.Concurrency, MaxResponseHeaderBytes: 16 << 10, TLSHandshakeTimeout: time.Duration(p.TimeoutMillis) * time.Millisecond, ResponseHeaderTimeout: time.Duration(p.TimeoutMillis) * time.Millisecond, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: tr, Timeout: time.Duration(p.TimeoutMillis) * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Backend{profile: p, credentials: c, base: u, client: client, gate: gate}, nil
}
func (b *Backend) Profile() Profile { return b.profile }
func (b *Backend) Close()           { b.client.CloseIdleConnections() }

// WithRequestGate binds a freshly resolved backend to shared admission.
// The returned backend takes over the caller's transport.
func (b *Backend) WithRequestGate(g *RequestGate) (*Backend, error) {
	if b == nil || g == nil || g.profile != b.profile {
		return nil, ErrDenied
	}
	bound := *b
	bound.gate = g
	return &bound, nil
}

// WithAccountRequestGate adds a private process-local account budget.
// The caller supplies an explicit group; endpoints and credentials are opaque.
func (b *Backend) WithAccountRequestGate(g *RequestGate) (*Backend, error) {
	if b == nil || g == nil || g.profile.Kind != "" || g.slots == nil || b.account != nil {
		return nil, ErrDenied
	}
	bound := *b
	bound.account = g
	return &bound, nil
}

// NextRequest preserves an observed throttle deadline when a scheduler persists a retry.
// It includes the target gate and the optional account gate.
func (b *Backend) NextRequest() time.Time {
	return b.gate.deadline(b.account)
}

func (g *RequestGate) enter(ctx context.Context) error {
	select {
	case g.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *RequestGate) leave() { <-g.slots }

// Always lock the target first. An account gate can be shared with several
// targets, and reserving both deadlines at once keeps both rates independent.
func (g *RequestGate) deadline(account *RequestGate) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	if account != nil {
		account.mu.Lock()
		defer account.mu.Unlock()
		if account.next.After(g.next) {
			return account.next
		}
	}
	return g.next
}

func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (g *RequestGate) reserve(account *RequestGate) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if account != nil {
		account.mu.Lock()
		defer account.mu.Unlock()
	}
	now := time.Now()
	next := g.next
	if account != nil && account.next.After(next) {
		next = account.next
	}
	if delay := next.Sub(now); delay > 0 {
		return delay
	}
	g.next = now.Add(g.interval)
	if account != nil {
		account.next = now.Add(account.interval)
	}
	return 0
}

func (g *RequestGate) admit(ctx context.Context, account *RequestGate) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		delay := g.reserve(account)
		if delay <= 0 {
			return nil
		}
		if e := pause(ctx, delay); e != nil {
			return e
		}
	}
}
func (g *RequestGate) cooldown(account *RequestGate, delay time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	at := time.Now().Add(delay)
	if at.After(g.next) {
		g.next = at
	}
	if account != nil {
		account.mu.Lock()
		defer account.mu.Unlock()
		if at.After(account.next) {
			account.next = at
		}
	}
}

type requestOptions struct {
	stage       bool
	objectStage bool
	destination string
}

func (b *Backend) resourceURL(key string) string {
	address := *b.base
	address.Path += b.profile.Namespace + "-" + key
	return address.String()
}

func (b *Backend) request(ctx context.Context, method, key string, payload []byte) ([]byte, int, error) {
	return b.requestWith(ctx, method, key, payload, requestOptions{})
}

func (b *Backend) requestWith(ctx context.Context, method, key string, payload []byte, options requestOptions) ([]byte, int, error) {
	if !safeName(key, 170) || len(payload) > b.profile.MaxObjectBytes {
		return nil, 0, ErrCapacity
	}
	if method == http.MethodPut && b.profile.WriteMode == WebDAVMoveMode && !options.stage {
		return nil, 0, ErrDenied
	}
	attempts := b.profile.Attempts
	if options.stage {
		if b.profile.WriteMode != WebDAVMoveMode || method != http.MethodPut || !moveTemporary(key) || options.destination != "" {
			return nil, 0, ErrDenied
		}
		// A lost staging PUT reply is reconciled from the attempt book.
		attempts = 1
	}
	if method == "MOVE" || options.destination != "" {
		if b.profile.WriteMode != WebDAVMoveMode || method != "MOVE" || !moveTemporary(key) || !safeName(options.destination, 170) || moveTemporary(options.destination) || len(payload) != 0 {
			return nil, 0, ErrDenied
		}
	}
	var book WriteAttempts
	if options.stage || method == "MOVE" {
		var ok bool
		book, ok = ctx.Value(writeAttemptsKey{}).(WriteAttempts)
		if !ok {
			return nil, 0, ErrDenied
		}
	}
	if time.Now().Unix() >= b.credentials.ExpiresUnix {
		return nil, 0, ErrDenied
	}
	ctx, timeout := context.WithTimeout(ctx, time.Duration(b.profile.TimeoutMillis)*time.Millisecond)
	defer timeout()
	ctx, cancel := context.WithDeadline(ctx, time.Unix(b.credentials.ExpiresUnix, 0))
	defer cancel()
	if e := b.gate.enter(ctx); e != nil {
		return nil, 0, e
	}
	defer b.gate.leave()
	if b.account != nil {
		if e := b.account.enter(ctx); e != nil {
			return nil, 0, e
		}
		defer b.account.leave()
	}
	var last int
	traffic := b.requestTraffic(ctx, method, key, options)
	for attempt := 0; attempt < attempts; attempt++ {
		if time.Now().Unix() >= b.credentials.ExpiresUnix {
			return nil, 0, ErrDenied
		}
		if e := b.gate.admit(ctx, b.account); e != nil {
			return nil, 0, e
		}
		if book != nil {
			if e := book.Check(ctx); e != nil {
				return nil, 0, e
			}
		}
		req, e := http.NewRequestWithContext(ctx, method, b.resourceURL(key), bytes.NewReader(payload))
		if e != nil {
			return nil, 0, ErrDenied
		}
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Content-Type", "application/octet-stream")
		if options.stage {
			req.GetBody = nil
		} else if method == http.MethodPut {
			req.Header.Set("If-None-Match", "*")
		}
		if method == "MOVE" {
			req.Header.Set("Destination", b.resourceURL(options.destination))
			req.Header.Set("Overwrite", "F")
		}
		if b.profile.Kind == "s3" {
			if e = signV4(req, payload, b.credentials.Access, b.credentials.Secret, b.credentials.SessionToken, b.profile.Region, time.Now()); e != nil {
				return nil, 0, ErrDenied
			}
		} else {
			req.SetBasicAuth(b.credentials.Access, b.credentials.Secret)
		}
		b.bodyBudget.request(req)
		traffic.begin(req)
		res, e := b.client.Do(req)
		delay := time.Duration(attempt+1) * 50 * time.Millisecond
		if e == nil {
			last = res.StatusCode
			if res.StatusCode == 200 || res.StatusCode == 201 || res.StatusCode == 204 {
				if res.Header.Get("Content-Encoding") != "" || res.ContentLength > int64(b.profile.MaxObjectBytes) {
					res.Body.Close()
					return nil, last, ErrIntegrity
				}
				reader := b.bodyBudget.response(ctx, res.Body)
				data, readErr := io.ReadAll(io.LimitReader(traffic.response(reader), int64(b.profile.MaxObjectBytes)+1))
				res.Body.Close()
				if len(data) > b.profile.MaxObjectBytes {
					return nil, last, ErrCapacity
				}
				if readErr == nil {
					return data, last, nil
				}
			} else {
				res.Body.Close()
				switch last {
				case 404:
					return nil, last, ErrNotFound
				case 412:
					return nil, last, ErrConflict
				case 401, 403:
					return nil, last, ErrDenied
				case 413, 507:
					return nil, last, ErrCapacity
				case 409, 429, 500, 502, 503, 504:
					if raw := res.Header.Get("Retry-After"); raw != "" {
						remaining := max(time.Duration(0), time.Until(time.Unix(b.credentials.ExpiresUnix, 0)))
						if seconds, e := strconv.ParseUint(raw, 10, 64); e == nil || errors.Is(e, strconv.ErrRange) {
							delay = remaining
							if e == nil && seconds < uint64(remaining/time.Second) {
								delay = time.Duration(seconds) * time.Second
							}
						} else if date, e := http.ParseTime(raw); e == nil {
							delay = time.Until(date)
						}
						delay = min(remaining, max(time.Duration(0), delay))
						// Preserve server backoff across calls and already waiting requests.
						b.gate.cooldown(b.account, delay)
						if delay > 30*time.Second {
							return nil, last, ErrUnavailable
						}
					}
				default:
					return nil, last, ErrUnsupported
				}
			}
		}
		if e = ctx.Err(); e != nil {
			return nil, last, e
		}
		if attempt+1 < attempts {
			if e = pause(ctx, delay); e != nil {
				return nil, last, e
			}
		}
	}
	return nil, last, ErrUnavailable
}
func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	data, _, e := b.request(ctx, http.MethodGet, key, nil)
	return data, e
}

// Put is create-only. A duplicate succeeds only after byte-for-byte readback.
func (b *Backend) Put(ctx context.Context, key string, data []byte) error {
	if b.profile.WriteMode == WebDAVMoveMode {
		return b.putMove(ctx, key, data)
	}
	_, _, e := b.request(ctx, http.MethodPut, key, data)
	if e != nil && !errors.Is(e, ErrConflict) {
		return e
	}
	for attempt := 0; attempt < b.profile.Attempts; attempt++ {
		got, readErr := b.Get(ctx, key)
		if readErr == nil {
			if !bytes.Equal(got, data) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(readErr, ErrNotFound) && !errors.Is(readErr, ErrUnavailable) {
			return readErr
		}
		if attempt+1 < b.profile.Attempts {
			if e = pause(ctx, 50*time.Millisecond); e != nil {
				return e
			}
		}
	}
	return ErrUnavailable
}

// Probe checks create-only behavior and readback with one immutable diagnostic
// object per namespace. Retries and independent workers use identical public,
// nonsensitive bytes, so a no-delete profile cannot accumulate a new probe on
// every attempt. An existing probe does not prove fresh-create permission,
// physical durability or the account's actual ACL scope.
func (b *Backend) Probe(ctx context.Context) error {
	if b.profile.WriteMode == WebDAVMoveMode {
		return b.probeMove(ctx)
	}
	value := sha256.Sum256([]byte("outpost-storage-probe-1\x00" + b.profile.Namespace))
	data := value[:]
	key := "probe-" + Hash(data)
	if e := b.Put(ctx, key, data); e != nil {
		return e
	}
	other := append([]byte(nil), data...)
	other[0] ^= 1
	_, status, e := b.request(ctx, http.MethodPut, key, other)
	if !errors.Is(e, ErrConflict) || status != 412 {
		return ErrUnsupported
	}
	got, e := b.Get(ctx, key)
	if e != nil {
		return e
	}
	if !bytes.Equal(got, data) {
		return ErrIntegrity
	}
	return b.checkLayout(ctx)
}

func (b *Backend) checkLayout(ctx context.Context) error {
	// A changed fragmentation profile cannot silently reinterpret old manifests.
	layout, _ := json.Marshal(struct {
		Format       string `json:"format"`
		MaxPartBytes int    `json:"maxPartBytes"`
	}{BlobFormat, b.profile.MaxObjectBytes})
	return b.Put(ctx, "layout", layout)
}
