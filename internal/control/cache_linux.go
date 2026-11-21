package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

type cacheState struct {
	Format       string            `json:"format"`
	Node         string            `json:"node"`
	Owner        ed25519.PublicKey `json:"owner"`
	ObservedUnix int64             `json:"observedUnix"`
	Current      json.RawMessage   `json:"current,omitempty"`
	Authorities  map[string]Domain `json:"authorities"`
}
type Cache struct {
	store *statefile.Store
	owner ed25519.PublicKey
	node  string
}

func OpenCache(dir, node string, owner ed25519.PublicKey, initialize bool) (*Cache, error) {
	return OpenCacheAt(nil, dir, node, owner, initialize)
}
func OpenCacheAt(parent *os.Root, dir, node string, owner ed25519.PublicKey, initialize bool) (*Cache, error) {
	return OpenCacheAdmittedAt(parent, dir, node, owner, initialize, nil)
}

// OpenCacheAdmittedAt accounts the initial durable state as well as updates.
func OpenCacheAdmittedAt(parent *os.Root, dir, node string, owner ed25519.PublicKey, initialize bool, admit statefile.Admission) (*Cache, error) {
	if !storage.ID(node) || len(owner) != 32 {
		return nil, ErrDenied
	}
	s, e := statefile.OpenAt(parent, dir, MaxConfig+2<<20, initialize)
	if e != nil {
		return nil, e
	}
	c := &Cache{s, append([]byte(nil), owner...), node}
	s.Admit = admit
	e = s.WithLock(context.Background(), func() error {
		_, err := c.load()
		if errors.Is(err, os.ErrNotExist) && initialize {
			return c.save(cacheState{Format: Format, Node: node, Owner: owner, Authorities: map[string]Domain{}})
		}
		return err
	})
	if e != nil {
		s.Close()
		return nil, e
	}
	return c, nil
}
func (c *Cache) Close() error                      { return c.store.Close() }
func (c *Cache) Verify(raw []byte) (Config, error) { return Verify(raw, c.owner, c.node) }
func (c *Cache) SetAdmission(ctx context.Context, admit statefile.Admission) error {
	return c.store.SetAdmission(ctx, admit)
}
func (c *Cache) load() (cacheState, error) {
	b, e := c.store.Read("cache.json")
	if e != nil {
		return cacheState{}, e
	}
	return checkCacheBytes(b, c.node, c.owner)
}
func checkCacheBytes(b []byte, node string, owner ed25519.PublicKey) (cacheState, error) {
	var s cacheState
	c := &Cache{node: node, owner: owner}
	if storage.Decode(b, &s, MaxConfig+2<<20) != nil || s.Format != Format || s.Node != c.node || !bytes.Equal(s.Owner, c.owner) || s.Authorities == nil || len(s.Authorities) > 128 || s.ObservedUnix < 0 {
		return s, ErrDenied
	}
	if len(s.Current) > 0 {
		cfg, err := Verify(s.Current, c.owner, c.node)
		if err != nil {
			return s, err
		}
		for _, d := range cfg.Domains {
			old, ok := s.Authorities[d.Trust.Domain]
			if !ok || !sameAuthority(d, old) {
				return s, ErrRollback
			}
		}
	}
	for id, d := range s.Authorities {
		if !storage.ID(id) || id != d.Trust.Domain || d.Trust.Epoch == 0 || !storage.ID(d.Trust.Repository) || len(d.Trust.Writer) != 32 || len(d.Trust.Maintenance) != 32 || len(d.Planner) != 32 {
			return s, ErrDenied
		}
	}
	return s, nil
}

// InspectCacheSnapshot validates the retained authority fences without opening
// a store or requiring an active (unexpired) configuration.
func InspectCacheSnapshot(raw []byte, node string, owner ed25519.PublicKey) (Config, string, error) {
	s, e := checkCacheBytes(raw, node, owner)
	if e != nil {
		return Config{}, "", e
	}
	if len(s.Current) == 0 {
		return Config{}, "", nil
	}
	c, e := Verify(s.Current, owner, node)
	return c, storage.Hash(s.Current), e
}
func sameAuthority(a, b Domain) bool {
	return a.Trust.Domain == b.Trust.Domain && a.Trust.Repository == b.Trust.Repository && a.Trust.Epoch == b.Trust.Epoch && bytes.Equal(a.Trust.Writer, b.Trust.Writer) && bytes.Equal(a.Trust.Maintenance, b.Trust.Maintenance) && bytes.Equal(a.Planner, b.Planner)
}
func (c *Cache) save(s cacheState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return c.store.Write("cache.json", b)
}

// Accept is atomic with the monotonic revision and authority ledger. A future
// policy immediately supersedes the old one, but cannot run before NotBefore.
func (c *Cache) Accept(ctx context.Context, raw []byte, now time.Time) error {
	next, e := Verify(raw, c.owner, c.node)
	if e != nil {
		return e
	}
	if now.Unix() >= next.ExpiresUnix || now.Unix() < 1 {
		return ErrInactive
	}
	return c.store.WithLock(ctx, func() error {
		s, e := c.load()
		if e != nil {
			return e
		}
		if now.Unix() < s.ObservedUnix {
			return ErrRollback
		}
		if len(s.Current) > 0 {
			old, e := Verify(s.Current, c.owner, c.node)
			if e != nil {
				return e
			}
			if next.Revision < old.Revision || next.Revision == old.Revision && !bytes.Equal(raw, s.Current) {
				return ErrRollback
			}
		}
		for _, d := range next.Domains {
			if old, ok := s.Authorities[d.Trust.Domain]; ok && (d.Trust.Epoch < old.Trust.Epoch || d.Trust.Epoch == old.Trust.Epoch && !sameAuthority(d, old)) {
				return ErrRollback
			}
			s.Authorities[d.Trust.Domain] = Domain{Trust: d.Trust, Planner: d.Planner}
		}
		if len(s.Authorities) > 128 {
			return ErrDenied
		}
		s.Current = append([]byte(nil), raw...)
		s.ObservedUnix = now.Unix()
		return c.save(s)
	})
}

// Current never falls back to an older policy. Expiry or clock rollback denies
// new work without deleting replicas, journals, pins or recovery material.
func (c *Cache) Current(ctx context.Context, now time.Time) (Config, error) {
	var out Config
	e := c.WithCurrent(ctx, now, func(cfg Config, _ []byte) error { out = cfg; return nil })
	return out, e
}

// WithCurrent serializes a short local admission with policy replacement.
// The callback must not re-enter this cache or perform network/long-running I/O.
func (c *Cache) WithCurrent(ctx context.Context, now time.Time, fn func(Config, []byte) error) error {
	var cfg Config
	return c.store.WithLock(ctx, func() error {
		s, e := c.load()
		if e != nil {
			return e
		}
		if now.Unix() < s.ObservedUnix {
			return ErrRollback
		}
		if len(s.Current) == 0 {
			return ErrInactive
		}
		cfg, e = Verify(s.Current, c.owner, c.node)
		if e != nil {
			return e
		}
		inactive := cfg.Active(now)
		if now.Unix() > s.ObservedUnix {
			s.ObservedUnix = now.Unix()
			if e = c.save(s); e != nil {
				return e
			}
		}
		if inactive != nil {
			return inactive
		}
		return fn(cfg, append([]byte(nil), s.Current...))
	})
}

// Raw preserves the owner's bytes for an authorized relay; it never re-signs.
func (c *Cache) Raw(ctx context.Context) ([]byte, error) {
	var raw []byte
	e := c.store.WithLock(ctx, func() error {
		s, e := c.load()
		if e != nil {
			return e
		}
		if len(s.Current) == 0 {
			return ErrInactive
		}
		raw = append([]byte(nil), s.Current...)
		return nil
	})
	return raw, e
}
