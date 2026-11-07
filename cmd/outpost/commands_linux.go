package main

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/worker"
)

func runCommands(ctx context.Context, action, bootstrap, input string) (any, error) {
	b, e := worker.LoadBootstrap(bootstrap)
	if e != nil {
		return nil, e
	}
	p, e := worker.LoadCommandProfile(input)
	if e != nil {
		return nil, e
	}
	enrollment, e := worker.ReadPrivate(p.EnrollmentFile, management.MaxEnrollment)
	if e != nil {
		return nil, e
	}
	w, close, e := b.Open(false)
	if e != nil {
		return nil, e
	}
	defer close()
	cert, roots, e := b.TLS()
	if e != nil {
		return nil, e
	}
	client, e := management.NewReportClient(p.Endpoint, p.Identity, b.Node, cert, roots, 5*time.Second)
	if e != nil {
		return nil, e
	}
	defer client.Close()
	if action == "worker-command-once" {
		bounded, cancel := context.WithTimeout(ctx, time.Duration(p.AttemptSeconds)*time.Second)
		defer cancel()
		return w.CommandOnce(bounded, client, enrollment)
	}
	e = w.RunCommands(ctx, p, enrollment, client)
	return map[string]any{"node": b.Node, "stopped": true}, e
}
