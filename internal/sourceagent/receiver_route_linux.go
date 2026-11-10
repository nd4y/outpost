package sourceagent

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

func (a *Agent) routed() bool { return a.b.ActiveFailover || a.b.Reserve != nil }

func (a *Agent) loadReserve() error {
	if a.b.Reserve == nil {
		return nil
	}
	selection := *a.b.Reserve
	if !policy.Endpoint(selection.Endpoint) || selection.Endpoint == a.b.Endpoint || selection.Endpoint == a.b.Companion.Endpoint {
		return ErrInvalid
	}
	raw, err := worker.ReadPrivate(selection.AuthorityFile, ingress.MaxDocument)
	if err != nil {
		return err
	}
	reserve, err := ingress.VerifyAuthorityDocument(raw, a.b.Local.Owner)
	if err != nil || !sameReceiverPair(a.anchor, reserve) || reserve.Ingress == a.companion.Ingress {
		return ErrInvalid
	}
	targets := a.b.Profile.CopyTargets
	if len(targets) != 3 || !slices.Contains(targets, reserve.Ingress) ||
		!slices.Contains(targets, a.anchor.Ingress) || !slices.Contains(targets, a.companion.Ingress) {
		return ErrInvalid
	}
	a.b.Reserve, a.reserve, a.reserveAuthority = &selection, reserve, raw
	return nil
}

func routeScope(operation string, route []string) string {
	return storage.Hash([]byte(operation + "/" + strings.Join(route, "/")))
}

func (a *Agent) validateRoute(s state, i ingress.Intent) error {
	if !a.routed() {
		if len(s.Route)+len(s.Superseded) != 0 || s.RoutePreparing || s.RoutePlan != "" || s.RouteCatalog != "" {
			return ErrInvalid
		}
		return nil
	}
	valid := func(route []string) bool {
		if len(route) != a.b.Profile.MinimumCopies {
			return false
		}
		for k, id := range route {
			if !slices.Contains(a.b.Profile.CopyTargets, id) || slices.Contains(route[:k], id) {
				return false
			}
		}
		return true
	}
	if !valid(s.Route) || s.RoutePlan != "" && !storage.ID(s.RoutePlan) || len(s.Superseded) != 0 && s.RoutePlan == "" || s.RoutePreparing && (s.Phase != "ACTIVE" || len(s.Superseded) == 0) {
		return ErrInvalid
	}
	if s.RouteCatalog != "" && (!storage.ID(s.RouteCatalog) || len(s.Superseded) != 2 ||
		s.Phase == "COMPLETE" && s.Generation != s.RouteCatalog) {
		return ErrInvalid
	}
	if len(s.Superseded) != 0 {
		if !a.b.ActiveFailover || s.Phase == "PREPARING" || !valid(s.Superseded) {
			return ErrInvalid
		}
		changes := 0
		for k, id := range s.Superseded {
			if s.Route[k] != id {
				if slices.Contains(s.Superseded, s.Route[k]) {
					return ErrInvalid
				}
				changes++
			}
		}
		if changes != 1 {
			return ErrInvalid
		}
	}
	if !slices.Contains(a.b.Profile.CopyTargets, i.Ingress) {
		return ErrInvalid
	}
	return nil
}

type captureReceiver struct {
	intent    ingress.Intent
	raw       []byte
	authority []byte
	endpoint  string
}

func (a *Agent) routeReceiver(s state, i ingress.Intent, id string) (captureReceiver, error) {
	var r captureReceiver
	switch {
	case id == a.anchor.Ingress:
		r.endpoint, r.authority = a.b.Endpoint, a.authority
		if s.Format == renewedFormat {
			r.authority = s.IntentAuthority
		}
	case a.b.Companion != nil && id == a.companion.Ingress:
		r.endpoint, r.authority = a.b.Companion.Endpoint, a.companionAuthority
		if s.Format == renewedFormat {
			r.authority = s.IntentCompanionAuthority
		}
	case a.b.Reserve != nil && id == a.reserve.Ingress:
		r.endpoint, r.authority = a.b.Reserve.Endpoint, a.reserveAuthority
		if s.Format == renewedFormat {
			r.authority = s.IntentReserveAuthority
		}
	default:
		return r, ErrInvalid
	}
	var err error
	r.intent, r.raw, err = a.receiverIntent(i, id, r.authority)
	return r, err
}

// An unchanged route has no third holder that already participated in the
// capture. After one replacement, only the removed holder is a candidate.
func (a *Agent) openPreviousHolder(s state, i ingress.Intent, limits peer.Limits) *ingress.Client {
	for _, id := range s.Superseded {
		if slices.Contains(s.Route, id) {
			continue
		}
		r, err := a.routeReceiver(s, i, id)
		if err != nil {
			return nil
		}
		client, _ := ingress.NewClient(r.endpoint, r.authority, r.raw, a.b.Local.Owner, a.cert, a.roots, limits)
		return client
	}
	return nil
}

func receiverUnavailable(err error) bool {
	if err == nil {
		return false
	}
	// Context cancellation of the entire source attempt is handled by the
	// caller. An individual holder's bounded attempt can time out.
	var network *net.OpError
	return errors.Is(err, ingress.ErrUnavailable) || errors.Is(err, ingress.ErrConflict) ||
		errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network)
}

func (a *Agent) readyReceiver(ctx context.Context, r captureReceiver) error {
	limits := peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1}
	client, err := ingress.NewClient(r.endpoint, r.authority, r.raw, a.b.Local.Owner, a.cert, a.roots, limits)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.Ready(ctx)
}

func (a *Agent) replacementRoute(ctx context.Context, s state) ([]string, error) {
	i, err := a.stateIntent(s)
	if err != nil {
		return nil, err
	}
	probe := func(id string) error {
		r, err := a.routeReceiver(s, i, id)
		if err != nil {
			return err
		}
		return a.readyReceiver(ctx, r)
	}
	failed := -1
	var outage error
	for k, id := range s.Route {
		err = probe(id)
		if err == nil {
			continue
		}
		if failed >= 0 || ctx.Err() != nil || !receiverUnavailable(err) {
			return nil, errors.Join(outage, err)
		}
		failed, outage = k, err
	}
	if failed < 0 {
		return nil, nil
	}
	for _, id := range a.b.Profile.CopyTargets {
		if slices.Contains(s.Route, id) {
			continue
		}
		if err = probe(id); err != nil {
			return nil, errors.Join(outage, err)
		}
		route := slices.Clone(s.Route)
		route[failed] = id
		return route, nil
	}
	return nil, outage
}

func (a *Agent) switchRoute(ctx context.Context, s *state, job *capture.Job) (bool, error) {
	allowed, err := job.CanChangeReceivers(ctx)
	if err != nil {
		return false, err
	}
	var sealed *capture.SealedTransfer
	if !allowed {
		if a.b.Reserve == nil || s.Phase != "ACTIVE" {
			return false, nil
		}
		sealed, err = job.SealedTransfer(ctx)
		if err != nil || sealed == nil {
			return false, err
		}
	}
	route, err := a.replacementRoute(ctx, *s)
	if err != nil || len(route) == 0 {
		return false, err
	}
	if sealed != nil {
		if err = a.checkSealedDonor(ctx, *s, route, sealed.Catalog); err != nil {
			return false, err
		}
		s.RouteCatalog = storage.Hash(sealed.Catalog)
	}
	if err = a.guard(ctx); err != nil {
		return false, err
	}
	if s.Phase == "ACTIVE" {
		s.Superseded, s.RoutePreparing = s.Route, true
	}
	s.Route = route
	s.RoutePlan = job.RoutePlanDigest()
	if err = a.save(*s); err != nil {
		return false, err
	}
	return true, a.point("source-agent-receiver-route-durable")
}

// checkSealedDonor refuses a route change when the survivor cannot confirm
// the entire closure. In particular a split capture can lose unique objects.
func (a *Agent) checkSealedDonor(ctx context.Context, s state, route []string, catalog []byte) error {
	i, err := a.stateIntent(s)
	if err != nil {
		return err
	}
	refs, err := generation.Dependencies(catalog, a.anchor.Trust)
	if err != nil {
		return err
	}
	for _, id := range s.Route {
		if !slices.Contains(route, id) {
			continue
		}
		r, err := a.routeReceiver(s, i, id)
		if err != nil {
			return err
		}
		client, err := ingress.NewClient(r.endpoint, r.authority, r.raw, a.b.Local.Owner, a.cert, a.roots,
			peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1})
		if err != nil {
			return err
		}
		defer client.Close()
		for _, ref := range refs {
			if err = client.Check(ctx, filekit.Object{ID: ref.ID, Bytes: ref.Bytes}); err != nil {
				return errors.Join(ingress.ErrIncomplete, err)
			}
		}
		return nil
	}
	return ErrInvalid
}

// The source execution lease covers the old job, the signed route decision
// and creation of the next job. At most one ACTIVE replacement may happen.
func (a *Agent) executeCapture(ctx context.Context, s *state, grant []byte, companion [][]byte) ([]byte, map[string]string, error) {
	preflight := true
	for {
		job, closeJob, err := a.openJobMode(ctx, *s, false, grant, companion...)
		if err != nil {
			return nil, nil, err
		}
		canSwitch := len(grant) == 0 && a.routed() && !s.RoutePreparing && s.RoutePlan == "" &&
			(s.Phase == "PREPARING" || a.b.ActiveFailover)
		if canSwitch && preflight {
			changed, err := a.switchRoute(ctx, s, job)
			if changed || err != nil {
				closeJob()
				if err != nil {
					return nil, nil, err
				}
				preflight = false
				continue
			}
		}
		if err = a.fenceCapture(ctx, s); err != nil {
			closeJob()
			return nil, nil, err
		}
		err = job.Run(ctx)
		if err == nil {
			checkpoint, heads, err := job.Export(ctx)
			closeJob()
			return checkpoint, heads, err
		}
		if canSwitch && a.b.ActiveFailover && ctx.Err() == nil && receiverUnavailable(err) {
			changed, switchErr := a.switchRoute(ctx, s, job)
			closeJob()
			if changed && switchErr == nil {
				continue
			}
			return nil, nil, errors.Join(err, switchErr)
		}
		closeJob()
		return nil, nil, err
	}
}
