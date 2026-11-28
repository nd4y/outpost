package peer

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/readback"
	"github.com/nd4y/outpost/internal/statefile"
)

func (c *Client) readbackScope() string {
	raw, _ := json.Marshal(struct {
		Protocol, Endpoint, Target, Reader string
		Trust                              generation.Trust
	}{Format, c.endpoint.String(), c.peer, c.policy.Self, c.trust})
	return generation.Hash(raw)
}
func (c *Client) auditObjects(ctx context.Context, op, id string, refs []generation.Object, count *atomic.Int64) (int, int64, error) {
	if c.policy.ReadbackMaxAgeSeconds == 0 {
		e := parallel(ctx, refs, c.limits.Concurrency, func(ctx context.Context, ref generation.Object) error {
			b, e := c.getObject(ctx, op, id, "push", ref)
			if e == nil {
				count.Add(int64(len(b)))
			}
			return e
		})
		return 0, time.Now().Unix(), e
	}
	store, e := statefile.OpenAt(c.journal.root, ".", readback.MaxPage, false)
	if e != nil {
		return 0, 0, e
	}
	defer store.Close()
	store.Admit = c.journal.Admit
	cache := readback.Cache{Store: store, Scope: c.readbackScope()}
	observed, e := cache.Lookup(ctx, refs, time.Now(), c.policy.ReadbackMaxAgeSeconds)
	if e != nil {
		return 0, 0, e
	}
	reused := len(observed)
	pending := make([]generation.Object, 0, len(refs)-reused)
	for _, r := range refs {
		if _, ok := observed[r.ID]; !ok {
			pending = append(pending, r)
		}
	}
	// Durable batches bound repeated network work after an interrupted audit.
	// No journal/cache lock is held while waiting on a peer.
	for offset := 0; offset < len(pending); offset += 16 {
		fresh := map[string]readback.Record{}
		var mu sync.Mutex
		e = parallel(ctx, pending[offset:min(offset+16, len(pending))], c.limits.Concurrency, func(ctx context.Context, ref generation.Object) error {
			b, e := c.getObject(ctx, op, id, "push", ref)
			if e != nil {
				return e
			}
			count.Add(int64(len(b)))
			mu.Lock()
			fresh[ref.ID] = readback.Record{Bytes: ref.Bytes, ObservedUnix: time.Now().Unix()}
			mu.Unlock()
			return nil
		})
		if e != nil {
			return reused, 0, e
		}
		if e = cache.Remember(ctx, fresh, time.Now()); e != nil {
			return reused, 0, e
		}
		for id, r := range fresh {
			observed[id] = r
		}
	}
	oldest := time.Now().Unix()
	for _, r := range observed {
		oldest = min(oldest, r.ObservedUnix)
	}
	if len(observed) != len(refs) || time.Now().Unix()-oldest > c.policy.ReadbackMaxAgeSeconds {
		return reused, 0, ErrUnavailable
	}
	return reused, oldest, nil
}
