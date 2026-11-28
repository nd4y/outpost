package sourceagent

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func (a *Agent) standbySelected(id string) bool {
	return a.b.Standby && id == a.companion.Ingress
}

func (a *Agent) receiverEndpoint(id string) string {
	if a.standbySelected(id) {
		return a.b.Companion.Endpoint
	}
	return a.b.Endpoint
}

// selectReceiver runs before the source binds an operation to a sink and
// before any receiver is contacted for admission. The readiness protocol
// cannot create a slot. An uncertain admitted capture never uses this path.
func (a *Agent) selectReceiver(ctx context.Context, selected ingress.Intent, raw []byte) ([]byte, error) {
	ready := func(endpoint string, authority, intent []byte) error {
		limits := peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1}
		c, err := ingress.NewClient(endpoint, authority, intent, a.b.Local.Owner, a.cert, a.roots, limits)
		if err != nil {
			return err
		}
		defer c.Close()
		return c.Ready(ctx)
	}
	authority, otherAuthority, otherID := a.authority, a.companionAuthority, a.companion.Ingress
	if a.standbySelected(selected.Ingress) {
		authority, otherAuthority, otherID = a.companionAuthority, a.authority, a.grant.Ingress
	}
	err := ready(a.receiverEndpoint(selected.Ingress), authority, raw)
	if err == nil {
		return raw, nil
	}
	var network *net.OpError
	if ctx.Err() != nil || !(errors.Is(err, ingress.ErrUnavailable) || errors.Is(err, ingress.ErrConflict) ||
		errors.Is(err, statefile.ErrCapacity) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network)) {
		return nil, err
	}
	selected.Ingress, selected.Authority = otherID, storage.Hash(otherAuthority)
	alternate, alternateErr := ingress.SignIntent(selected, otherAuthority, a.b.Local.Owner, a.writer, time.Now())
	if alternateErr == nil {
		alternateErr = ready(a.receiverEndpoint(otherID), otherAuthority, alternate)
	}
	if alternateErr != nil {
		return nil, errors.Join(err, alternateErr)
	}
	return alternate, a.guard(ctx)
}
