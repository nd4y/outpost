package sourceagent

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/observation"
)

func (a *Agent) copies(ctx context.Context, id string) ([]capture.CopyReceipt, error) {
	if e := a.guard(ctx); e != nil {
		return nil, e
	}
	c, e := observation.NewClient(a.b.Endpoint, a.observation, a.b.Local.Owner, a.cert, a.roots, 30*time.Second)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	proofs, e := c.Read(ctx, id)
	if e != nil {
		return nil, e
	}
	out := make([]capture.CopyReceipt, 0, len(proofs))
	for _, raw := range proofs {
		p, e := observation.VerifyProof(raw, a.observation, a.b.Local.Owner, id, time.Now())
		if e != nil {
			return nil, e
		}
		out = append(out, capture.CopyReceipt{Target: p.Target, Generation: p.Generation, Verification: p.Verification, ObservedUnix: p.ObservedUnix, SignedObservation: string(raw)})
	}
	return out, a.guard(ctx)
}
