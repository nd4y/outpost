package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const planningPageFormat = "outpost-upload-planning-page-1"
const planningPageObjects = 64
const maxPlanningPage = 1 << 20

// PlanningCache uses the worker's private, quota-admitted store. It contains
// only immutable descriptions. Losing it costs source reads; corruption fails
// closed. Source pin ownership remains with the caller through queue handoff.
type PlanningCache struct {
	Store *statefile.Store
	Fault func(string) error
}
type plannedObject struct {
	Index int          `json:"index"`
	Blob  storage.Blob `json:"blob"`
}
type planningPage struct {
	Format  string          `json:"format"`
	Scope   string          `json:"scope"`
	Page    int             `json:"page"`
	Objects []plannedObject `json:"objects"`
}

func canonicalParts(blob storage.Blob, limit int) error {
	if blob.Validate(limit) != nil || limit < 64<<10 || limit > storage.MaxPhysical {
		return ErrDenied
	}
	remaining := blob.Object.Bytes
	if len(blob.Parts) != (remaining+limit-1)/limit {
		return ErrDenied
	}
	for _, part := range blob.Parts {
		size := min(remaining, limit)
		if part.Bytes != size {
			return ErrDenied
		}
		remaining -= size
	}
	if len(blob.Parts) == 1 && blob.Parts[0] != blob.Object {
		return ErrDenied
	}
	return nil
}

// Descriptor lengths depend only on signed lengths and the physical limit.
// Reject an oversized representation before reading any source payload. Unique
// task count still needs the actual part digests and is checked by Plan.Tasks.
func preflightPlan(p Plan, refs []generation.Object) error {
	p.Blobs = []storage.Blob{}
	p.Signature = nil
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	size := len(raw) + 128 // includes the legacy signature and its field overhead
	for _, ref := range refs {
		blob := storage.Blob{Format: storage.BlobFormat, Object: ref, Parts: []generation.Object{}}
		for remaining := ref.Bytes; remaining > 0; {
			n := min(remaining, p.Profile.MaxObjectBytes)
			blob.Parts = append(blob.Parts, generation.Object{ID: ref.ID, Bytes: n})
			remaining -= n
		}
		entry, e := json.Marshal(blob)
		if e != nil {
			return e
		}
		size += len(entry) + 1
		if size > MaxPlan {
			return ErrDenied
		}
	}
	return nil
}

func (c *PlanningCache) describe(ctx context.Context, scope string, refs []generation.Object, index, limit int, compute func() (storage.Blob, error)) (storage.Blob, error) {
	if c.Store == nil || !storage.ID(scope) || index < 0 || index >= len(refs) {
		return storage.Blob{}, ErrDenied
	}
	pageID := index / planningPageObjects
	name := fmt.Sprintf("upload-parts-%s-%03d.json", scope, pageID)
	load := func() (planningPage, error) {
		p := planningPage{Format: planningPageFormat, Scope: scope, Page: pageID, Objects: []plannedObject{}}
		raw, e := c.Store.Read(name)
		if errors.Is(e, os.ErrNotExist) {
			return p, nil
		}
		if e != nil {
			return p, e
		}
		if storage.Decode(raw, &p, maxPlanningPage) != nil || p.Format != planningPageFormat || p.Scope != scope || p.Page != pageID || len(p.Objects) == 0 || len(p.Objects) > planningPageObjects {
			return p, ErrConflict
		}
		last := -1
		for _, item := range p.Objects {
			if item.Index <= last || item.Index < pageID*planningPageObjects || item.Index >= min((pageID+1)*planningPageObjects, len(refs)) || item.Blob.Object != refs[item.Index] || canonicalParts(item.Blob, limit) != nil {
				return p, ErrConflict
			}
			last = item.Index
		}
		return p, nil
	}
	var found storage.Blob
	e := c.Store.WithLock(ctx, func() error {
		p, e := load()
		if e != nil {
			return e
		}
		for _, item := range p.Objects {
			if item.Index == index {
				found = item.Blob
				break
			}
		}
		return nil
	})
	if e != nil || found.Format != "" {
		return found, e
	}
	blob, e := compute() // no source IO while holding the private-state lock
	if e != nil {
		return blob, e
	}
	if blob.Object != refs[index] || canonicalParts(blob, limit) != nil {
		return storage.Blob{}, ErrDenied
	}
	e = c.Store.WithLock(ctx, func() error {
		p, e := load()
		if e != nil {
			return e
		}
		for _, item := range p.Objects {
			if item.Index == index {
				x, _ := json.Marshal(item.Blob)
				y, _ := json.Marshal(blob)
				if !bytes.Equal(x, y) {
					return ErrConflict
				}
				return nil
			}
		}
		p.Objects = append(p.Objects, plannedObject{index, blob})
		sort.Slice(p.Objects, func(i, j int) bool { return p.Objects[i].Index < p.Objects[j].Index })
		raw, e := json.Marshal(p)
		if e != nil {
			return e
		}
		if len(raw) > maxPlanningPage {
			return ErrDenied
		}
		return c.Store.Write(name, raw)
	})
	if e == nil && c.Fault != nil {
		e = c.Fault("upload-part-map-durable")
	}
	return blob, e
}
