package storage

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

const bodyBudgetQuantum = 32 << 10

// HTTPBodyBudget paces body reads for one process's configured link allowance.
// A reader may carry one bounded allowance through short reads. An unused
// tail stays reserved when the body closes.
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
	// Reserve one bounded allowance without accumulating unused time globally.
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
	prepaid   int   // unused bytes in this reader's most recent allowance
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
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.prepaid == 0 {
		if err := r.budget.wait(r.ctx, size); err != nil {
			return 0, err
		}
		r.prepaid = size
	}
	// A short TLS read can spend the rest of this allowance on its next reads.
	// Never refund an unused tail into the shared schedule of other readers.
	n, err := r.source.Read(p[:min(size, r.prepaid)])
	r.prepaid -= n
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

// PaceRequest wraps a known-length body and any transport replay. Closing the
// body cancels waits for an allowance without changing HTTP framing.
func (b *HTTPBodyBudget) PaceRequest(req *http.Request) {
	if b == nil || req.ContentLength <= 0 {
		return
	}
	wrap := func(body io.ReadCloser) io.ReadCloser {
		// Outpost constructs the request from an immutable byte slice.
		ctx, cancel := context.WithCancel(req.Context())
		return &pacedRequestBody{pacedReader{ctx: ctx, source: body, budget: b, remaining: req.ContentLength}, body, cancel}
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

// PaceResponse throttles reads from a body before consumption. The caller
// retains responsibility for limiting its length and closing it.
func (b *HTTPBodyBudget) PaceResponse(ctx context.Context, body io.Reader) io.Reader {
	if b == nil || body == http.NoBody {
		return body
	}
	return &pacedReader{ctx: ctx, source: body, budget: b, remaining: -1}
}

// WriteBody paces one already verified outbound body without changing framing.
// The caller retains responsibility for write deadlines and closing on error.
func (b *HTTPBodyBudget) WriteBody(ctx context.Context, out io.Writer, body []byte) error {
	if b == nil {
		_, err := out.Write(body)
		return err
	}
	reader := &pacedReader{ctx: ctx, source: bytes.NewReader(body), budget: b, remaining: int64(len(body))}
	_, err := io.Copy(out, reader)
	return err
}
