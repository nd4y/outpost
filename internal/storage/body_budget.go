package storage

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

const bodyBudgetQuantum = 32 << 10

// HTTPBodyBudget paces body reads for one process's configured link allowance.
// It has no authority over the transport or kernel's buffering and framing.
type HTTPBodyBudget struct {
	bytesPerSecond int64
	mu             sync.Mutex
	next           time.Time
}

func NewHTTPBodyBudget(bytesPerSecond int64) (*HTTPBodyBudget, error) {
	if bytesPerSecond < 64<<10 || bytesPerSecond > 1<<30 {
		return nil, ErrDenied
	}
	return &HTTPBodyBudget{bytesPerSecond: bytesPerSecond}, nil
}

// WithHTTPBodyBudget binds a freshly resolved backend to a private shared link.
func (b *Backend) WithHTTPBodyBudget(budget *HTTPBodyBudget) (*Backend, error) {
	if b == nil || budget == nil || budget.bytesPerSecond == 0 || b.bodyBudget != nil {
		return nil, ErrDenied
	}
	bound := *b
	bound.bodyBudget = budget
	return &bound, nil
}

func (b *HTTPBodyBudget) wait(ctx context.Context, size int) error {
	// Reserve the maximum this read can use, with no accumulated idle burst.
	// A short read may reserve more than it uses. The meter counts actual bytes.
	duration := time.Duration((int64(size)*int64(time.Second) + b.bytesPerSecond - 1) / b.bytesPerSecond)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.mu.Lock()
		now := time.Now()
		delay := b.next.Sub(now)
		if delay <= 0 {
			b.next = now.Add(duration)
			b.mu.Unlock()
			return ctx.Err()
		}
		b.mu.Unlock()
		if err := pause(ctx, delay); err != nil {
			return err
		}
	}
}

type pacedReader struct {
	ctx       context.Context
	source    io.Reader
	budget    *HTTPBodyBudget
	remaining int64 // -1 for responses whose reads remain governed by net/http
}

func (r *pacedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	size := min(len(p), bodyBudgetQuantum)
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if r.remaining > 0 {
		size = int(min(int64(size), r.remaining))
	}
	if err := r.budget.wait(r.ctx, size); err != nil {
		return 0, err
	}
	n, err := r.source.Read(p[:size])
	if r.remaining > 0 {
		r.remaining -= int64(n)
	}
	return n, err
}

type pacedRequestBody struct {
	pacedReader
	body   io.ReadCloser
	cancel context.CancelFunc
}

func (b *pacedRequestBody) Close() error {
	b.cancel()
	return b.body.Close()
}

func (b *HTTPBodyBudget) request(req *http.Request) {
	if b == nil || req.ContentLength <= 0 {
		return
	}
	wrap := func(body io.ReadCloser) io.ReadCloser {
		// Outpost constructs the request from an immutable byte slice.
		ctx, cancel := context.WithCancel(req.Context())
		return &pacedRequestBody{pacedReader{ctx, body, b, req.ContentLength}, body, cancel}
	}
	req.Body = wrap(req.Body)
	if original := req.GetBody; original != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			body, err := original()
			if err != nil {
				return nil, err
			}
			return wrap(body), nil
		}
	}
}

func (b *HTTPBodyBudget) response(ctx context.Context, body io.Reader) io.Reader {
	if b == nil || body == http.NoBody {
		return body
	}
	return &pacedReader{ctx, body, b, -1}
}
