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
	if !storage.ID(node) || len(owner) != 32 {
		return nil, ErrDenied
	}
	s, e := statefile.Open(dir, MaxConfig+2<<20, initialize)
	if e != nil {
		return nil, e
	}
	c := &Cache{s, append([]byte(nil), owner...), node}
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
	var s cacheState
	b, e := c.store.Read("cache.json")
	if e != nil {
		return s, e
	}
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
	var cfg Config
	var inactive error
	e := c.store.WithLock(ctx, func() error {
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
		inactive = cfg.Active(now)
		if now.Unix() > s.ObservedUnix {
			s.ObservedUnix = now.Unix()
			return c.save(s)
		}
		return nil
	})
	if e != nil {
		return Config{}, e
	}
	if inactive != nil {
		return Config{}, inactive
	}
	return cfg, nil
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
