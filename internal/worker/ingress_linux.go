package worker

import (
	"context"
	"net/http"
	"time"
)

// The view owns admission, lifetime and cancellation. Registry capabilities
// never outlive the current accepted placement, even on reused TLS connections.
func (w *Worker) serveIngress(out http.ResponseWriter, r *http.Request, domain string) {
	w.mu.Lock()
	v := w.active
	if v == nil || v.ctx.Err() != nil || v.cfg.Active(time.Now()) != nil {
		w.mu.Unlock()
		http.Error(out, "inactive", 503)
		return
	}
	d := v.domains[domain]
	if d == nil || d.ingress == nil {
		w.mu.Unlock()
		http.Error(out, "denied", 403)
		return
	}
	v.requests.Add(1)
	w.mu.Unlock()
	defer v.requests.Done()
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(v.ctx, cancel)
	defer stop()
	defer cancel()
	d.ingress.ServeHTTP(out, r.WithContext(ctx))
}
