package storage

import (
	"context"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
)

// HTTPBodyCounts observes reads of HTTP bodies in one local execution scope.
// Counts cover retries and failures, and omit HTTP headers, TLS and TCP overhead.
type HTTPBodyCounts struct {
	Requests             int64 `json:"requests"`
	GetRequests          int64 `json:"getRequests"`
	PutRequests          int64 `json:"putRequests"`
	MoveRequests         int64 `json:"moveRequests"`
	RequestBytes         int64 `json:"requestBytes"`
	ObjectRequestBytes   int64 `json:"objectRequestBytes"`
	RepeatedRequestBytes int64 `json:"repeatedRequestBytes"`
	ResponseBytes        int64 `json:"responseBytes"`
	ObjectResponseBytes  int64 `json:"objectResponseBytes"`
	StagingResponseBytes int64 `json:"stagingResponseBytes"`
	Incomplete           bool  `json:"incomplete"`
}

// Valid checks the relationships that must hold for a persisted observation.
func (c HTTPBodyCounts) Valid() bool {
	return c.Requests >= 0 && c.GetRequests >= 0 && c.PutRequests >= 0 && c.MoveRequests >= 0 &&
		c.GetRequests <= c.Requests && c.PutRequests <= c.Requests-c.GetRequests &&
		c.MoveRequests <= c.Requests-c.GetRequests-c.PutRequests &&
		c.RequestBytes >= 0 && c.ObjectRequestBytes >= 0 && c.ObjectRequestBytes <= c.RequestBytes &&
		c.RepeatedRequestBytes >= 0 && c.RepeatedRequestBytes <= c.RequestBytes &&
		c.ResponseBytes >= 0 && c.ObjectResponseBytes >= 0 && c.ObjectResponseBytes <= c.ResponseBytes &&
		c.StagingResponseBytes >= 0 && c.StagingResponseBytes <= c.ResponseBytes-c.ObjectResponseBytes
}

type HTTPMeter struct {
	target          string
	mu              sync.Mutex
	counts          HTTPBodyCounts
	openBodies      int
	activeBodyReads int
}

type httpMeterKey struct{}

// WithHTTPMeter isolates observations from other operations sharing a backend.
func WithHTTPMeter(ctx context.Context, profile Profile) (context.Context, *HTTPMeter) {
	meter := &HTTPMeter{target: profile.ID()}
	return context.WithValue(ctx, httpMeterKey{}, meter), meter
}

func (m *HTTPMeter) Snapshot() HTTPBodyCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := m.counts
	// net/http may close the request body asynchronously after Do returns.
	counts.Incomplete = counts.Incomplete || m.openBodies != 0 || m.activeBodyReads != 0
	return counts
}

func (m *HTTPMeter) add(total *int64, amount int64) {
	if amount > math.MaxInt64-*total {
		*total = math.MaxInt64
		m.counts.Incomplete = true
		return
	}
	*total += amount
}

type requestTraffic struct {
	meter       *HTTPMeter
	objectWrite bool
	objectRead  bool
	stageRead   bool
	// All readers are copies of the same request body starting at offset 0.
	// The meter lock serializes overlap accounting across request replays.
	highestOffset int64
}

func (b *Backend) requestTraffic(ctx context.Context, method, key string, options requestOptions) *requestTraffic {
	meter, ok := ctx.Value(httpMeterKey{}).(*HTTPMeter)
	if !ok || meter.target != b.profile.ID() {
		return nil
	}
	part := strings.HasPrefix(key, "part-")
	return &requestTraffic{meter: meter, objectWrite: method == http.MethodPut && (part || options.objectStage), objectRead: method == http.MethodGet && part, stageRead: method == http.MethodGet && moveTemporary(key)}
}

func (r *requestTraffic) begin(req *http.Request) {
	if r == nil {
		return
	}
	m := r.meter
	m.mu.Lock()
	m.add(&m.counts.Requests, 1)
	switch req.Method {
	case http.MethodGet:
		m.add(&m.counts.GetRequests, 1)
	case http.MethodPut:
		m.add(&m.counts.PutRequests, 1)
	case "MOVE":
		m.add(&m.counts.MoveRequests, 1)
	}
	m.mu.Unlock()
	if req.ContentLength <= 0 {
		return
	}
	req.Body = r.body(req.Body)
	if original := req.GetBody; original != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			body, err := original()
			if err != nil {
				return nil, err
			}
			return r.body(body), nil
		}
	}
}

func (r *requestTraffic) body(body io.ReadCloser) io.ReadCloser {
	m := r.meter
	m.mu.Lock()
	m.openBodies++
	m.mu.Unlock()
	return &meteredRequestBody{ReadCloser: body, traffic: r}
}

type meteredRequestBody struct {
	io.ReadCloser
	traffic *requestTraffic
	offset  int64
	once    sync.Once
}

func (b *meteredRequestBody) Read(p []byte) (int, error) {
	r := b.traffic
	m := r.meter
	m.mu.Lock()
	m.activeBodyReads++
	m.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeBodyReads--
	if n == 0 {
		return n, err
	}
	end := b.offset + int64(n)
	overlap := max(int64(0), min(end, r.highestOffset)-b.offset)
	r.highestOffset = max(end, r.highestOffset)
	b.offset = end
	m.add(&m.counts.RequestBytes, int64(n))
	m.add(&m.counts.RepeatedRequestBytes, overlap)
	if r.objectWrite {
		m.add(&m.counts.ObjectRequestBytes, int64(n))
	}
	return n, err
}

func (b *meteredRequestBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		m := b.traffic.meter
		m.mu.Lock()
		m.openBodies--
		m.mu.Unlock()
	})
	return err
}

type meteredResponseBody struct {
	io.Reader
	traffic *requestTraffic
}

func (r *requestTraffic) response(body io.Reader) io.Reader {
	if r == nil {
		return body
	}
	return meteredResponseBody{Reader: body, traffic: r}
}

func (b meteredResponseBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	m := b.traffic.meter
	m.mu.Lock()
	defer m.mu.Unlock()
	m.add(&m.counts.ResponseBytes, int64(n))
	if b.traffic.objectRead {
		m.add(&m.counts.ObjectResponseBytes, int64(n))
	}
	if b.traffic.stageRead {
		m.add(&m.counts.StagingResponseBytes, int64(n))
	}
	return n, err
}
