package worker

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
)

func captureStagingRoutes(c control.Config, domain, source string) *ingress.StagingRoutes {
	d, ok := c.DomainByID(domain)
	if !ok || len(d.CaptureStagingPeers) == 0 {
		return nil
	}
	routes := &ingress.StagingRoutes{Origins: map[string]string{}, Readers: map[string]bool{}, AutomaticPeers: map[string]bool{}, RelayOrigins: map[string]bool{}, RelayReaders: map[string]bool{}}
	for _, id := range d.CaptureAutomaticPeers {
		routes.AutomaticPeers[id] = true
	}
	for _, edge := range d.Placement.Edges {
		if edge.Mode != "pull" {
			continue
		}
		if edge.To == c.Node && slices.Contains(d.CaptureStagingPeers, edge.From) {
			node, _ := c.NodeByID(edge.From)
			routes.Origins[edge.From] = node.Endpoint
			if slices.Contains(d.CaptureRelayPeers, edge.From) && d.Placement.HasEdge(source, edge.From, "push") {
				routes.RelayOrigins[edge.From] = true
			}
		}
		if edge.From == c.Node && slices.Contains(d.CaptureStagingPeers, edge.To) {
			routes.Readers[edge.To] = true
			if slices.Contains(d.CaptureRelayPeers, edge.To) {
				routes.RelayReaders[edge.To] = true
			}
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
