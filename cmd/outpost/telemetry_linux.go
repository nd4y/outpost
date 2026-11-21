package main

import (
	"context"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/telemetry"
	"github.com/nd4y/outpost/internal/worker"
)

func runTelemetry(ctx context.Context, command, bootstrap, input, digest string) (any, error) {
	b, e := worker.LoadBootstrap(bootstrap)
	if e != nil {
		return nil, e
	}
	p, e := worker.LoadTelemetryProfile(input)
	if e != nil {
		return nil, e
	}
	var enrollment []byte
	if command == "worker-telemetry-init" || command == "worker-telemetry-renew" {
		enrollment, e = worker.ReadPrivate(p.EnrollmentFile, management.MaxEnrollment)
		if e != nil {
			return nil, e
		}
	}
	w, close, e := b.Open(false)
	if e != nil {
		return nil, e
	}
	defer close()
	initial := enrollment
	if command != "worker-telemetry-init" {
		initial = nil
	}
	q, e := w.OpenTelemetry(ctx, p, initial, command == "worker-telemetry-init")
	if e != nil {
		return nil, e
	}
	defer q.Close()
	switch command {
	case "worker-telemetry-init", "worker-telemetry-status":
		return q.Status(ctx)
	case "worker-telemetry-renew":
		if e = q.Renew(ctx, enrollment); e != nil {
			return nil, e
		}
		return q.Status(ctx)
	case "worker-telemetry-discard":
		if e = q.DiscardBlocked(ctx, digest); e != nil {
			return nil, e
		}
		return q.Status(ctx)
	case "worker-telemetry-once", "worker-telemetry-loop":
		cert, roots, e := b.TLS()
		if e != nil {
			return nil, e
		}
		client, e := telemetry.NewClient(p.Endpoint, cert, roots, b.Node, p.Identity)
		if e != nil {
			return nil, e
		}
		defer client.Close()
		if command == "worker-telemetry-once" {
			return w.TelemetryOnce(ctx, p, q, client)
		}
		e = w.RunTelemetry(ctx, p, q, client)
		return map[string]any{"node": b.Node, "domain": p.Domain, "stopped": true}, e
	}
	return nil, errUsage
}
