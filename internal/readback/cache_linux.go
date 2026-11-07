// Package readback retains private evidence of past immutable-object reads.
// It is an optimization, never authority to transfer, publish or delete data.
package readback

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
)

const Format = "outpost-readback-page-1"
const MaxPage = 1 << 20
const maxEntries = 4096
const MaxAgeSeconds = int64(366 * 24 * 60 * 60)

var ErrInvalid = errors.New("invalid readback evidence")

type Record struct {
	Bytes        int   `json:"bytes"`
	ObservedUnix int64 `json:"observedUnix"`
}
type page struct {
	Format  string            `json:"format"`
	Scope   string            `json:"scope"`
	Prefix  string            `json:"prefix"`
	Records map[string]Record `json:"records"`
}
type Cache struct {
	Store *statefile.Store
	Scope string
}

func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func validObject(r generation.Object) bool {
	return validID(r.ID) && r.Bytes > 0 && r.Bytes <= generation.MaxObject
}
func (c Cache) name(prefix string) string { return "readback-" + c.Scope + "-" + prefix + ".json" }
func (c Cache) load(prefix string, now int64) (page, error) {
	p := page{Format: Format, Scope: c.Scope, Prefix: prefix, Records: map[string]Record{}}
	raw, e := c.Store.Read(c.name(prefix))
	if errors.Is(e, os.ErrNotExist) {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	if len(raw) > MaxPage || json.Unmarshal(raw, &p) != nil {
		return p, ErrInvalid
	}
	canonical, e := json.Marshal(p)
	if e != nil || !bytes.Equal(raw, canonical) || p.Format != Format || p.Scope != c.Scope || p.Prefix != prefix || p.Records == nil || len(p.Records) > maxEntries {
		return p, ErrInvalid
	}
	for id, r := range p.Records {
		if !validObject(generation.Object{ID: id, Bytes: r.Bytes}) || id[:2] != prefix || r.ObservedUnix < 1 || r.ObservedUnix > now {
			return p, ErrInvalid
		}
	}
	return p, nil
}
func (c Cache) valid() bool { return c.Store != nil && validID(c.Scope) }
func groups(refs []generation.Object) (map[string][]generation.Object, error) {
	if len(refs) > generation.MaxObjects {
		return nil, ErrInvalid
	}
	out := map[string][]generation.Object{}
	seen := map[string]bool{}
	for _, r := range refs {
		if !validObject(r) || seen[r.ID] {
			return nil, ErrInvalid
		}
		seen[r.ID] = true
		out[r.ID[:2]] = append(out[r.ID[:2]], r)
	}
	return out, nil
}

// Lookup performs no network IO. Zero maxAge requests a fresh content read.
// Missing/expired entries are omitted; malformed evidence is never ignored.
func (c Cache) Lookup(ctx context.Context, refs []generation.Object, now time.Time, maxAge int64) (map[string]Record, error) {
	out := map[string]Record{}
	if !c.valid() || now.Unix() < 1 || maxAge < 0 || maxAge > MaxAgeSeconds {
		return nil, ErrInvalid
	}
	parts, e := groups(refs)
	if e != nil {
		return nil, e
	}
	e = c.Store.WithLock(ctx, func() error {
		for prefix, objects := range parts {
			if e := ctx.Err(); e != nil {
				return e
			}
			p, e := c.load(prefix, now.Unix())
			if e != nil {
				return e
			}
			for _, ref := range objects {
				r, ok := p.Records[ref.ID]
				if ok && r.Bytes != ref.Bytes {
					return ErrInvalid
				}
				if ok && maxAge > 0 && now.Unix()-r.ObservedUnix <= maxAge {
					out[ref.ID] = r
				}
			}
		}
		return nil
	})
	return out, e
}

// Remember accepts only evidence supplied after a successful independent read.
// Records are scoped by the caller to exact target/protocol/reader/trust. Each
// page is committed atomically; an interrupted batch only causes extra reads.
func (c Cache) Remember(ctx context.Context, records map[string]Record, now time.Time) error {
	return c.RememberChecked(ctx, records, now, nil)
}

// RememberChecked joins a local validation with the evidence update under the
// same store lock. check must not reenter Store or perform network IO.
func (c Cache) RememberChecked(ctx context.Context, records map[string]Record, now time.Time, check func() error) error {
	if !c.valid() || len(records) > generation.MaxObjects || now.Unix() < 1 {
		return ErrInvalid
	}
	refs := make([]generation.Object, 0, len(records))
	for id, r := range records {
		if r.ObservedUnix < 1 || r.ObservedUnix > now.Unix() {
			return ErrInvalid
		}
		refs = append(refs, generation.Object{ID: id, Bytes: r.Bytes})
	}
	parts, e := groups(refs)
	if e != nil {
		return e
	}
	return c.Store.WithLock(ctx, func() error {
		if check != nil {
			if e := check(); e != nil {
				return e
			}
		}
		for prefix, objects := range parts {
			if e := ctx.Err(); e != nil {
				return e
			}
			p, e := c.load(prefix, now.Unix())
			if e != nil {
				return e
			}
			for _, ref := range objects {
				r := records[ref.ID]
				old, ok := p.Records[ref.ID]
				if ok && old.Bytes != r.Bytes {
					return ErrInvalid
				}
				if !ok || r.ObservedUnix > old.ObservedUnix {
					p.Records[ref.ID] = r
				}
			}
			if len(p.Records) > maxEntries {
				ids := make([]string, 0, len(p.Records))
				for id := range p.Records {
					ids = append(ids, id)
				}
				sort.Slice(ids, func(i, j int) bool {
					a, b := p.Records[ids[i]], p.Records[ids[j]]
					if a.ObservedUnix == b.ObservedUnix {
						return ids[i] < ids[j]
					}
					return a.ObservedUnix < b.ObservedUnix
				})
				for _, id := range ids[:len(ids)-maxEntries] {
					delete(p.Records, id)
				}
			}
			raw, e := json.Marshal(p)
			if e != nil || len(raw) > MaxPage {
				return ErrInvalid
			}
			if e = c.Store.Write(c.name(prefix), raw); e != nil {
				return e
			}
		}
		return nil
	})
}

// Invalidate removes only advisory evidence for bytes observed absent or
// corrupt. It never changes payload or protection pins. Malformed pages remain
// preserved and block reuse rather than being silently replaced.
func (c Cache) Invalidate(ctx context.Context, refs []generation.Object, now time.Time) error {
	return c.InvalidateChecked(ctx, refs, now, nil)
}

// InvalidateChecked also fences local in-flight verification under this lock.
// check has the same restrictions as RememberChecked; it runs before removal.
func (c Cache) InvalidateChecked(ctx context.Context, refs []generation.Object, now time.Time, check func() error) error {
	if !c.valid() || now.Unix() < 1 {
		return ErrInvalid
	}
	parts, e := groups(refs)
	if e != nil {
		return e
	}
	return c.Store.WithLock(ctx, func() error {
		if check != nil {
			if e := check(); e != nil {
				return e
			}
		}
		for prefix, objects := range parts {
			p, e := c.load(prefix, now.Unix())
			if e != nil {
				return e
			}
			changed := false
			for _, ref := range objects {
				if r, ok := p.Records[ref.ID]; ok {
					if r.Bytes != ref.Bytes {
						return ErrInvalid
					}
					delete(p.Records, ref.ID)
					changed = true
				}
			}
			if changed {
				raw, e := json.Marshal(p)
				if e != nil {
					return e
				}
				if e = c.Store.Write(c.name(prefix), raw); e != nil {
					return e
				}
			}
		}
		return nil
	})
}
