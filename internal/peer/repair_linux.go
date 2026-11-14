package peer

import (
	"context"
	"github.com/nd4y/outpost/internal/generation"
	"net/http"
	"sync/atomic"
)

// Verification may discover another corrupt dependency after the initial
// metadata page. Each retry must make bounded payload progress; the caller
// limits the number of passes by the authenticated closure size.
func (c *Client) sendRepairMissing(ctx context.Context, b Binding, source *generation.Replica, refs []generation.Object, submitted *atomic.Int64) (int, error) {
	response, e := c.request(ctx, b.Operation, b.Generation, "push", http.MethodPost, "missing", nil, generation.MaxCatalog, nil)
	if e != nil {
		return 0, e
	}
	var missing []generation.Object
	if decode(response.data, &missing, generation.MaxCatalog) != nil || len(missing) > len(refs) {
		return 0, ErrProtocol
	}
	expected := map[string]generation.Object{}
	for _, ref := range refs {
		expected[ref.ID] = ref
	}
	seen := map[string]bool{}
	for _, ref := range missing {
		want, exists := expected[ref.ID]
		if !exists || want != ref || seen[ref.ID] {
			return 0, ErrProtocol
		}
		seen[ref.ID] = true
	}
	e = parallel(ctx, missing, c.limits.Concurrency, func(ctx context.Context, ref generation.Object) error {
		data, e := source.ReadObject(ctx, b.Generation, ref)
		if e != nil {
			return e
		}
		reply, e := c.request(ctx, b.Operation, b.Generation, "push", http.MethodPut, "objects/"+ref.ID, data, 1024, submitted)
		if e != nil {
			return e
		}
		var ack struct {
			Object string `json:"object"`
			State  string `json:"state"`
		}
		if decode(reply.data, &ack, 1024) != nil || ack.Object != ref.ID || ack.State != "HASH_VERIFIED_DURABLE" {
			return ErrProtocol
		}
		return nil
	})
	return len(missing), e
}
