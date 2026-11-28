package worker

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"time"
)

type requestBody struct {
	io.ReadCloser
	read int64
	eof  bool
}

func (b *requestBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	b.read += int64(n)
	if e == io.EOF {
		b.eof = true
	}
	return n, e
}

// A canceled context does not interrupt a server body read or response write.
// Bound the connection deadlines and join cancellation before normal reset.
func (w *Worker) requestContext(out http.ResponseWriter, r *http.Request, v *view) (context.Context, func(), error) {
	deadline := time.Now().Add(time.Duration(v.cfg.Limits.AttemptMillis) * time.Millisecond)
	leaf, e := x509.ParseCertificate(w.cert.Certificate[0])
	if e != nil {
		return nil, nil, e
	}
	for _, expires := range []time.Time{leaf.NotAfter, r.TLS.PeerCertificates[0].NotAfter, time.Unix(v.cfg.ExpiresUnix, 0)} {
		if expires.Before(deadline) {
			deadline = expires
		}
	}
	base, cancelBase := context.WithCancel(r.Context())
	stopView := context.AfterFunc(v.ctx, cancelBase)
	rc := http.NewResponseController(out)
	if e = rc.SetReadDeadline(deadline); e != nil {
		stopView()
		cancelBase()
		return nil, nil, e
	}
	if e = rc.SetWriteDeadline(deadline); e != nil {
		_ = rc.SetReadDeadline(time.Time{})
		stopView()
		cancelBase()
		return nil, nil, e
	}
	ctx, cancel := context.WithDeadline(base, deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = rc.SetReadDeadline(time.Now()); _ = rc.SetWriteDeadline(time.Now()) })
	body := &requestBody{ReadCloser: r.Body}
	r.Body = body
	cleanup := func() {
		if v.ctx.Err() != nil || r.Context().Err() != nil {
			cancelBase()
		}
		if !stop() {
			<-done
		}
		active := ctx.Err() == nil && base.Err() == nil && time.Now().Before(deadline)
		cancel()
		stopView()
		cancelBase()
		if active {
			_ = rc.SetWriteDeadline(time.Time{})
			if r.ContentLength == 0 || body.eof || r.ContentLength > 0 && body.read >= r.ContentLength {
				_ = rc.SetReadDeadline(time.Time{})
			} else {
				// Do not let net/http drain a refused, unfinished body indefinitely.
				r.Close = true
				_ = rc.SetReadDeadline(time.Now())
			}
		}
	}
	return ctx, cleanup, nil
}
