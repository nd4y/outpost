package generation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
)

// The first explicit maintenance operation upgrades the local state to v3.
// Older writers must refuse this state rather than recalculate a frozen GC set.
// Wire catalogs, file kits and independent recovery payloads remain unchanged.
const MaintenanceStateFormat = "outpost-replica-state-3"

type gcRecord struct {
	Plan   string              `json:"plan"`
	Result *MaintenanceReceipt `json:"result,omitempty"`
}
type gcPlan struct {
	Format   string   `json:"format"`
	Permit   string   `json:"permit"`
	Objects  []Object `json:"objects"`
	Catalogs []string `json:"catalogs"`
}

// MaintenanceReceipt is a historical outcome, not fresh verification or proof
// of physical erasure. Absent counts include candidates removed before retry.
type MaintenanceReceipt struct {
	Operation         string `json:"operation"`
	Permit            string `json:"permit"`
	CandidateObjects  int    `json:"candidateObjects"`
	AbsentObjects     int    `json:"absentObjects"`
	ProtectedObjects  int    `json:"protectedObjects"`
	CandidateCatalogs int    `json:"candidateCatalogs"`
	AbsentCatalogs    int    `json:"absentCatalogs"`
	ProtectedCatalogs int    `json:"protectedCatalogs"`
	CompletedUnix     int64  `json:"completedUnix"`
}

func (r MaintenanceReceipt) valid(op, permit string) bool {
	return r.Operation == op && r.Permit == permit && r.CompletedUnix > 0 &&
		r.CandidateObjects >= 0 && r.CandidateObjects <= MaxObjects*4 && r.AbsentObjects >= 0 && r.ProtectedObjects >= 0 && r.AbsentObjects <= r.CandidateObjects && r.ProtectedObjects == r.CandidateObjects-r.AbsentObjects &&
		r.CandidateCatalogs >= 0 && r.CandidateCatalogs <= MaxGenerations*4 && r.AbsentCatalogs >= 0 && r.ProtectedCatalogs >= 0 && r.AbsentCatalogs <= r.CandidateCatalogs && r.ProtectedCatalogs == r.CandidateCatalogs-r.AbsentCatalogs
}

func (r MaintenanceReceipt) Validate() error {
	if !validID(r.Operation) || !validID(r.Permit) || !r.valid(r.Operation, r.Permit) {
		return ErrInvalid
	}
	return nil
}
func (r *Replica) MaintenanceResult(ctx context.Context, operation string) (MaintenanceReceipt, error) {
	var out MaintenanceReceipt
	if !validID(operation) {
		return out, ErrInvalid
	}
	e := r.locked(ctx, func(s *state) error {
		record, ok := s.GC[operation]
		if !ok {
			return ErrMigrationRequired
		}
		if record.Result == nil {
			return ErrIncomplete
		}
		out = *record.Result
		return nil
	})
	return out, e
}
func gcName(op string) string { return "gc-" + op + ".json" }
func (r *Replica) gcPlan(ctx context.Context, p Permit, digest, expected string, keep map[string]Object, retiring map[string]bool, s *state) (gcPlan, string, error) {
	var plan gcPlan
	b, e := read(r.root, gcName(p.Operation), MaxState)
	if e == nil {
		if expected != "" && Hash(b) != expected || canonical(b, &plan, MaxState) != nil || plan.Format != "outpost-gc-plan-1" || plan.Permit != digest || len(plan.Objects) > MaxObjects*4 || len(plan.Catalogs) > MaxGenerations*4 {
			return plan, "", ErrInvalid
		}
		last := ""
		for _, ref := range plan.Objects {
			if !validID(ref.ID) || ref.ID <= last || ref.Bytes < 1 || ref.Bytes > MaxObject {
				return plan, "", ErrInvalid
			}
			last = ref.ID
		}
		last = ""
		for _, id := range plan.Catalogs {
			if !validID(id) || id <= last {
				return plan, "", ErrInvalid
			}
			last = id
		}
		return plan, Hash(b), nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return plan, "", e
	}
	if expected != "" {
		return plan, "", ErrMigrationRequired
	}
	plan = gcPlan{Format: "outpost-gc-plan-1", Permit: digest, Objects: []Object{}, Catalogs: []string{}}
	for _, directory := range []string{"objects", "catalogs"} {
		limit := MaxObjects * 4
		if directory == "catalogs" {
			limit = MaxGenerations * 4
		}
		f, e := r.root.Open(directory)
		if e != nil {
			return plan, "", e
		}
		entries, re := f.ReadDir(limit + 1)
		ce := f.Close()
		if ce != nil {
			return plan, "", ce
		}
		if (re != nil && !errors.Is(re, io.EOF)) || len(entries) > limit {
			return plan, "", ErrInvalid
		}
		for _, item := range entries {
			if e = ctx.Err(); e != nil {
				return plan, "", e
			}
			if !item.Type().IsRegular() || !validID(item.Name()) {
				return plan, "", ErrInvalid
			}
			if directory == "catalogs" {
				if _, exists := s.Generations[item.Name()]; !exists || retiring[item.Name()] {
					plan.Catalogs = append(plan.Catalogs, item.Name())
				}
				continue
			}
			info, e := item.Info()
			if e != nil {
				return plan, "", e
			}
			if info.Size() < 1 || info.Size() > MaxObject {
				return plan, "", ErrInvalid
			}
			if ref, exists := keep[item.Name()]; exists {
				if int64(ref.Bytes) != info.Size() {
					return plan, "", ErrIncomplete
				}
			} else {
				plan.Objects = append(plan.Objects, Object{ID: item.Name(), Bytes: int(info.Size())})
			}
		}
	}
	sort.Slice(plan.Objects, func(i, j int) bool { return plan.Objects[i].ID < plan.Objects[j].ID })
	sort.Strings(plan.Catalogs)
	b, e = json.Marshal(plan)
	if e != nil {
		return plan, "", e
	}
	if len(b) > MaxState {
		return plan, "", ErrInvalid
	}
	if e = r.write(gcName(p.Operation), b); e != nil {
		return plan, "", e
	}
	if e = r.point("gc-plan-durable"); e != nil {
		return plan, "", e
	}
	return plan, Hash(b), nil
}
