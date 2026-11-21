package ingress

import (
	"context"
	"net/http"
	"time"
)

// Cancelling a request context alone does not interrupt a blocked server body
// read. Bind the network deadline too, and join the callback before resetting
// deadlines so it cannot poison a later request on this connection.
func requestLifetime(w http.ResponseWriter, parent context.Context, deadline time.Time) (context.Context, func(), error) {
	rc := http.NewResponseController(w)
	if e := rc.SetReadDeadline(deadline); e != nil {
		return nil, nil, e
	}
	if e := rc.SetWriteDeadline(deadline); e != nil {
		_ = rc.SetReadDeadline(time.Time{})
		return nil, nil, e
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = rc.SetReadDeadline(time.Now()); _ = rc.SetWriteDeadline(time.Now()) })
	cleanup := func() {
		if !stop() {
			<-done
		}
		active := ctx.Err() == nil && parent.Err() == nil && time.Now().Before(deadline)
		cancel()
		// Keep an expired deadline after cancellation so net/http cannot block
		// draining an unfinished body when the handler returns.
		if active {
			_ = rc.SetReadDeadline(time.Time{})
			_ = rc.SetWriteDeadline(time.Time{})
		}
	}
	return ctx, cleanup, nil
}
