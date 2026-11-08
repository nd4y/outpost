package worker

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
)

func captureStagingRoutes(c control.Config, domain string) *ingress.StagingRoutes {
	d, ok := c.DomainByID(domain)
	if !ok || !d.CaptureStaging {
		return nil
	}
	routes := &ingress.StagingRoutes{Origins: map[string]string{}, Readers: map[string]bool{}}
	for _, edge := range d.Placement.Edges {
		if edge.Mode != "pull" || !slices.Contains(d.Placement.Holders, edge.From) || !slices.Contains(d.Placement.Holders, edge.To) {
			continue
		}
		if edge.To == c.Node {
			node, _ := c.NodeByID(edge.From)
			routes.Origins[edge.From] = node.Endpoint
		}
		if edge.From == c.Node {
			routes.Readers[edge.To] = true
		}
	}
	return routes
}

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
	if d == nil || d.ingress == nil || v.paused(domain, "") {
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
