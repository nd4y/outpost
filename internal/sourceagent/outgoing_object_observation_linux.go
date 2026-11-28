package sourceagent

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

const sourceObjectBodyRetention = "CURRENT_PROCESS_RUN"

type SourceObjectBodyObservation struct {
	Route string `json:"route"`
	ingress.ObjectWriteObservation
}

type SourceObjectBodySnapshot struct {
	Retention string                        `json:"retention"`
	Samples   []SourceObjectBodyObservation `json:"samples"`
}

type sourceObjectSample struct {
	operation, authority string
	SourceObjectBodyObservation
}

type sourceObjectSamples struct {
	slots [3]atomic.Pointer[sourceObjectSample]
}

type sourceObjectScopeKey struct{}

// RunWithObjectBodyObservations returns a volatile projection for this run.
// The callback has no writer, filesystem access, or lifecycle to join.
func (a *Agent) RunWithObjectBodyObservations(ctx context.Context, relay []byte) (Status, error) {
	samples := new(sourceObjectSamples)
	observed := context.WithValue(ctx, sourceObjectScopeKey{}, samples)
	var err error
	if relay == nil {
		err = a.Run(observed)
	} else {
		err = a.RunWithRelay(observed, relay)
	}
	if err != nil {
		return Status{}, err
	}
	return a.status(ctx, StatusOptions{}, samples)
}

func sourceObjectRoute(a ingress.Authority) string {
	return storage.Hash([]byte(fmt.Sprintf("outpost-source-object-body-1/%s/%s/%s/%s/%d/%s/%s",
		a.Tenant, a.Profile, a.Trust.Domain, a.Trust.Repository, a.Trust.Epoch, a.Source, a.Ingress)))
}

func (a *Agent) sourceObjectSlot(receiver string) (int, bool) {
	switch {
	case a.anchor.Ingress == receiver:
		return 0, true
	case a.b.Companion != nil && a.companion.Ingress == receiver:
		return 1, true
	case a.b.Reserve != nil && a.reserve.Ingress == receiver:
		return 2, true
	default:
		return 0, false
	}
}

func (a *Agent) outgoingObjectObserver(ctx context.Context, raw []byte, operation string) func(ingress.ObjectWriteObservation) {
	samples, ok := ctx.Value(sourceObjectScopeKey{}).(*sourceObjectSamples)
	if !ok {
		return nil
	}
	authority, err := ingress.VerifyAuthority(raw, a.b.Local.Owner, time.Now())
	if err != nil {
		return nil
	}
	slot, ok := a.sourceObjectSlot(authority.Ingress)
	if !ok {
		return nil
	}
	route, digest := sourceObjectRoute(authority), storage.Hash(raw)
	destination := &samples.slots[slot]
	return func(observation ingress.ObjectWriteObservation) {
		if !withinObjectAuthority(observation, authority) || ctx.Err() != nil {
			return
		}
		prior := destination.Load()
		if prior != nil && prior.VerifiedUnixMillis > observation.VerifiedUnixMillis {
			return
		}
		// Drop a contended update instead of retrying or waiting on the PUT path.
		destination.CompareAndSwap(prior, &sourceObjectSample{operation: operation, authority: digest,
			SourceObjectBodyObservation: SourceObjectBodyObservation{Route: route, ObjectWriteObservation: observation}})
	}
}

func withinObjectAuthority(value ingress.ObjectWriteObservation, authority ingress.Authority) bool {
	return value.PutStartedUnixMillis/1000 >= authority.NotBefore && value.VerifiedUnixMillis/1000 < authority.ExpiresUnix
}

// Status already owns the ordinary read lease and has loaded canonical signed
// source state under the existing held-volume guard. No additional I/O here.
func (a *Agent) outgoingObjectStatus(ctx context.Context, s state, intent ingress.Intent, samples *sourceObjectSamples) *SourceObjectBodySnapshot {
	targets := s.Route
	if !a.routed() {
		targets = []string{intent.Ingress}
		if a.b.Companion != nil && !a.b.Standby {
			targets = append(targets, a.companion.Ingress)
		}
	}
	now := time.Now()
	result := SourceObjectBodySnapshot{Retention: sourceObjectBodyRetention}
	var expiry int64
	for _, target := range targets {
		slot, ok := a.sourceObjectSlot(target)
		if !ok {
			continue
		}
		sample := samples.slots[slot].Load()
		if sample == nil || sample.operation != intent.Operation || sample.VerifiedUnixMillis > now.UnixMilli() {
			continue
		}
		receiver, err := a.routeReceiver(s, intent, target)
		if err != nil || sample.authority != storage.Hash(receiver.authority) {
			continue
		}
		authority, err := ingress.VerifyAuthority(receiver.authority, a.b.Local.Owner, now)
		if err != nil || sample.Route != sourceObjectRoute(authority) || !withinObjectAuthority(sample.ObjectWriteObservation, authority) {
			continue
		}
		result.Samples = append(result.Samples, sample.SourceObjectBodyObservation)
		if expiry == 0 || authority.ExpiresUnix < expiry {
			expiry = authority.ExpiresUnix
		}
	}
	finished := time.Now().UnixMilli()
	if len(result.Samples) == 0 || ctx.Err() != nil || finished < now.UnixMilli() || finished/1000 >= expiry {
		return nil
	}
	return &result
}
