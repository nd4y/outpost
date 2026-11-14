package main

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/worker"
)

func runReporting(ctx context.Context, command, bootstrap, input string) (any, error) {
	b, e := worker.LoadBootstrap(bootstrap)
	if e != nil {
		return nil, e
	}
	profile, e := worker.LoadReportProfile(input)
	if e != nil {
		return nil, e
	}
	enrollment, e := worker.ReadPrivate(profile.EnrollmentFile, management.MaxEnrollment)
	if e != nil {
		return nil, e
	}
	w, close, e := b.Open(false)
	if e != nil {
		return nil, e
	}
	defer close()
	reporter, e := w.OpenReporter(ctx, profile.Identity, profile.Domain, enrollment, command == "worker-report-init")
	if e != nil {
		return nil, e
	}
	defer reporter.Close()
	switch command {
	case "worker-report-init", "worker-report-set":
		e = reporter.SetDispatch(ctx, profile.Schedule)
		if e != nil {
			return nil, e
		}
		return reporter.DispatchStatus(ctx)
	case "worker-report-renew":
		if e = reporter.Renew(ctx, enrollment); e != nil {
			return nil, e
		}
		return reporter.Status(ctx)
	case "worker-report-status":
		queue, e := reporter.Status(ctx)
		if e != nil {
			return nil, e
		}
		schedule, e := reporter.DispatchStatus(ctx)
		if e != nil {
			return nil, e
		}
		return map[string]any{"queue": queue, "dispatch": schedule}, nil
	case "worker-report-loop":
		cert, roots, e := b.TLS()
		if e != nil {
			return nil, e
		}
		client, e := management.NewReportClient(profile.Endpoint, profile.Identity, b.Node, cert, roots, 5*time.Second)
		if e != nil {
			return nil, e
		}
		defer client.Close()
		e = reporter.RunDispatch(ctx, client, w.ManagementSnapshot)
		return map[string]any{"node": b.Node, "domain": profile.Domain, "stopped": true}, e
	}
	return nil, errUsage
}
