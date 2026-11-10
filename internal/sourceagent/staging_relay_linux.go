package sourceagent

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
)

func (a *Agent) offerRelayIntent(ctx context.Context, s state, authority []byte) error {
	i, err := a.stateIntent(s)
	if err != nil {
		return err
	}
	bridge := i.Ingress
	if a.routed() {
		bridge = s.Route[0]
	}
	route, err := a.routeReceiver(s, i, bridge)
	if err != nil {
		return err
	}
	target, err := ingress.VerifyAuthority(authority, a.b.Local.Owner, time.Now())
	if err != nil || target.Ingress == bridge || a.routed() && len(s.Route) > 1 && target.Ingress == s.Route[1] ||
		a.b.Companion != nil && !a.b.Standby && target.Ingress == a.companion.Ingress {
		return ingress.ErrDenied
	}
	_, downstream, err := a.receiverIntent(i, target.Ingress, authority)
	if err != nil {
		return err
	}
	limits := peer.Limits{Concurrency: 1, Timeout: 30 * time.Second, Attempts: 1}
	client, err := ingress.NewClient(route.endpoint, route.authority, route.raw, a.b.Local.Owner, a.cert, a.roots, limits)
	if err != nil {
		return err
	}
	defer client.Close()
	if err = client.Begin(ctx); err != nil {
		return err
	}
	return client.OfferRelayIntent(ctx, authority, downstream)
}
