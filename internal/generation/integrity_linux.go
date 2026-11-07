package generation

import (
	"context"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"io"
	"os"
	"sort"
	"syscall"
	"time"
)

// Detection introduces explicit publication health. Older writers must not
// ignore damaged dependencies and advertise their historical COMPLETE bit.
const IntegrityStateFormat = "outpost-replica-state-4"

type DamageRecord struct {
	Object       Object `json:"object"`
	DetectedUnix int64  `json:"detectedUnix"`
	Repair       string `json:"repair,omitempty"`
}

// Repair records are retained independently of generations and ordinary GC.
// Missing means there were no original bytes to preserve. CompletedUnix is
// the historical verified replacement time, never generation readiness.
type RepairRecord struct {
	Object        Object `json:"object"`
	DetectedUnix  int64  `json:"detectedUnix"`
	OriginalHash  string `json:"originalHash,omitempty"`
	OriginalBytes int    `json:"originalBytes"`
	Missing       bool   `json:"missing"`
	CompletedUnix int64  `json:"completedUnix,omitempty"`
}

func (v RepairRecord) valid() bool {
	return validID(v.Object.ID) && v.Object.Bytes > 0 && v.Object.Bytes <= MaxObject && v.DetectedUnix > 0 && v.CompletedUnix >= 0 && (v.CompletedUnix == 0 || v.CompletedUnix >= v.DetectedUnix) && v.OriginalBytes >= 0 && v.OriginalBytes <= MaxObject && ((!v.Missing && validID(v.OriginalHash) && v.OriginalHash != v.Object.ID) || (v.Missing && v.OriginalHash == "" && v.OriginalBytes == 0))
}

type IntegrityStatus struct {
	Damage  map[string]DamageRecord `json:"damage"`
	Repairs map[string]RepairRecord `json:"repairs"`
}

type RepairNeed struct {
	Generation string `json:"generation"`
	Sequence   uint64 `json:"sequence"`
	Token      string `json:"token"`
}

// Needs are metadata only. The opaque incarnation survives repair and changes
// on the next detected damage, fencing old operations without resetting them.
func (r *Replica) RepairNeeds(ctx context.Context) ([]RepairNeed, error) {
	result := []RepairNeed{}
	e := r.locked(ctx, func(s *state) error {
		for id, item := range s.Generations {
			if item.Damaged {
				result = append(result, RepairNeed{id, item.Sequence, item.RepairToken})
			}
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Sequence < result[j].Sequence })
		return nil
	})
	return result, e
}
func (r *Replica) CheckRepair(ctx context.Context, id, token string) error {
	return r.locked(ctx, func(s *state) error { return checkRepair(s, id, token) })
}
func checkRepair(s *state, id, token string) error {
	item, ok := s.Generations[id]
	if !ok || !validID(token) || item.RepairToken != token {
		return ErrConflict
	}
	return nil
}

// RepairMissing reports known damage and absent entries, without treating
// metadata as proof of health. A subsequent fresh VerifyWindow is mandatory.
func (r *Replica) RepairMissing(ctx context.Context, id string) ([]Object, error) {
	result := []Object{}
	e := r.locked(ctx, func(s *state) error {
		_, refs, e := r.get(s, id, true)
		if e != nil {
			return e
		}
		for _, key := range sortedIDs(refs) {
			if e = ctx.Err(); e != nil {
				return e
			}
			if _, bad := s.Damage[key]; bad {
				result = append(result, refs[key])
				continue
			}
			_, e = r.objectStamp(refs[key])
			if integrityFailure(e) {
				if mark := r.recordDamage(s, refs[key]); mark != nil {
					return mark
				}
				result = append(result, refs[key])
			} else if e != nil {
				return e
			}
		}
		return nil
	})
	return result, e
}

func (r *Replica) Integrity(ctx context.Context) (IntegrityStatus, error) {
	var result IntegrityStatus
	e := r.locked(ctx, func(s *state) error { result = IntegrityStatus{Damage: s.Damage, Repairs: s.Repairs}; return nil })
	return result, e
}

// Quarantine reads permit an empty regular file, but never links, devices,
// oversized entries or a file changing during the bounded read.
func (r *Replica) damagedBytes(name string) ([]byte, error) {
	f, e := localfs.OpenFile(r.root, name, os.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return nil, e
	}
	before, e := stampOf(i)
	if e != nil || before.Size < 0 || before.Size > MaxObject {
		return nil, ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxObject+1))
	if e != nil {
		return nil, e
	}
	i, e = f.Stat()
	if e != nil {
		return nil, e
	}
	after, e := stampOf(i)
	if e != nil || before != after || int64(len(b)) != before.Size {
		return nil, ErrConflict
	}
	return b, nil
}

// RepairPut is explicitly requested by an authorized repair transfer. It
// accepts only the signed catalog's exact hash/size and preserves old bytes
// before atomic replacement. It never publishes a generation on its own.
func (r *Replica) RepairPut(ctx context.Context, generation, id string, b []byte) error {
	return r.repairPut(ctx, generation, id, "", b)
}
func (r *Replica) RepairPutFor(ctx context.Context, generation, id, token string, b []byte) error {
	if !validID(token) {
		return ErrInvalid
	}
	return r.repairPut(ctx, generation, id, token, b)
}
func (r *Replica) repairPut(ctx context.Context, generation, id, token string, b []byte) error {
	if len(b) > MaxObject || !validID(id) || Hash(b) != id {
		return ErrInvalid
	}
	return r.locked(ctx, func(s *state) error {
		if token != "" {
			if e := checkRepair(s, generation, token); e != nil {
				return e
			}
		}
		_, refs, e := r.get(s, generation, true)
		if e != nil {
			return e
		}
		ref, ok := refs[id]
		if !ok || ref.Bytes != len(b) {
			return ErrInvalid
		}
		_, e = r.object(ref)
		_, damaged := s.Damage[id]
		if e == nil && !damaged {
			return nil
		}
		if e != nil && !integrityFailure(e) {
			return e
		}
		if !damaged {
			if e = r.recordDamage(s, ref); e != nil {
				return e
			}
		}
		if token != "" {
			if e := checkRepair(s, generation, token); e != nil {
				return e
			}
		}
		return r.replaceDamaged(ctx, s, ref, b)
	})
}

func (r *Replica) replaceDamaged(ctx context.Context, s *state, ref Object, b []byte) error {
	damage := s.Damage[ref.ID]
	caseID := damage.Repair
	if caseID == "" {
		if len(s.Repairs) >= MaxPins {
			return statefile.ErrCapacity
		}
		bad, e := r.damagedBytes("objects/" + ref.ID)
		missing := errors.Is(e, os.ErrNotExist)
		if e != nil && !missing {
			return e
		}
		// An out-of-band replacement has no matching durable quarantine intent.
		if !missing && Hash(bad) == ref.ID {
			return ErrConflict
		}
		nonce, e := randomID()
		if e != nil {
			return e
		}
		caseID = Hash([]byte(ref.ID + "/" + nonce))
		repair := RepairRecord{Object: ref, DetectedUnix: damage.DetectedUnix, Missing: missing, OriginalBytes: len(bad)}
		if !missing {
			repair.OriginalHash = Hash(bad)
		}
		if s.Repairs == nil {
			s.Repairs = map[string]RepairRecord{}
		}
		s.Repairs[caseID] = repair
		damage.Repair = caseID
		s.Damage[ref.ID] = damage
		s.Revision++
		if e = r.save(*s); e != nil {
			return e
		}
		if e = r.point("repair-intent-durable"); e != nil {
			return e
		}
	}
	repair := s.Repairs[caseID]
	if !repair.Missing {
		dir, e := localfs.OpenAt(r.root, "quarantine/objects", true)
		if e != nil {
			return e
		}
		if e = dir.Close(); e != nil {
			return e
		}
		name := "quarantine/objects/" + caseID
		bad, e := r.damagedBytes(name)
		if errors.Is(e, os.ErrNotExist) {
			bad, e = r.damagedBytes("objects/" + ref.ID)
			if e != nil {
				return e
			}
			if len(bad) != repair.OriginalBytes || Hash(bad) != repair.OriginalHash {
				return ErrConflict
			}
			if e = ctx.Err(); e != nil {
				return e
			}
			if e = r.write(name, bad); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if len(bad) != repair.OriginalBytes || Hash(bad) != repair.OriginalHash {
			return ErrConflict
		}
		if e = r.point("quarantine-durable"); e != nil {
			return e
		}
	}
	current, e := r.damagedBytes("objects/" + ref.ID)
	already := e == nil && len(current) == ref.Bytes && Hash(current) == ref.ID
	if !already {
		if repair.Missing {
			if !errors.Is(e, os.ErrNotExist) {
				return ErrConflict
			}
		} else if e != nil || len(current) != repair.OriginalBytes || Hash(current) != repair.OriginalHash {
			return ErrConflict
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = r.write("objects/"+ref.ID, b); e != nil {
			return e
		}
		if e = r.point("repair-object-durable"); e != nil {
			return e
		}
	}
	if _, e = r.verifyObjectStamp(ctx, ref); e != nil {
		return e
	}
	repair.CompletedUnix = time.Now().Unix()
	if repair.CompletedUnix < repair.DetectedUnix {
		return ErrInvalid
	}
	s.Repairs[caseID] = repair
	delete(s.Damage, ref.ID)
	s.Revision++
	if e = r.save(*s); e != nil {
		return e
	}
	return r.point("repair-result-durable")
}

func integrityFailure(e error) bool {
	return errors.Is(e, ErrIncomplete) || errors.Is(e, ErrInvalid) || errors.Is(e, os.ErrNotExist) || errors.Is(e, syscall.ELOOP)
}

// The caller holds the replica lock. All affected publications lose readiness
// together; their catalogs, original complete history and pins remain intact.
func (r *Replica) recordDamage(s *state, ref Object) error {
	changed := s.Format != IntegrityStateFormat
	if s.Damage == nil {
		s.Damage = map[string]DamageRecord{}
	}
	if old, ok := s.Damage[ref.ID]; ok {
		if old.Object != ref {
			return ErrConflict
		}
	} else {
		if len(s.Damage) >= MaxObjects {
			return ErrInvalid
		}
		s.Damage[ref.ID] = DamageRecord{Object: ref, DetectedUnix: time.Now().Unix()}
		changed = true
	}
	for id, item := range s.Generations {
		_, refs, e := r.get(s, id, true)
		if e != nil {
			return e
		}
		if expected, ok := refs[ref.ID]; ok {
			if expected != ref {
				return ErrConflict
			}
			if !item.Damaged {
				nonce, e := randomID()
				if e != nil {
					return e
				}
				item.RepairToken = Hash([]byte(id + "/" + nonce))
				item.Damaged = true
				s.Generations[id] = item
				changed = true
			}
		}
	}
	if !changed {
		return nil
	}
	s.Format = IntegrityStateFormat
	s.Latest = ""
	highest := uint64(0)
	for id, item := range s.Generations {
		if item.Complete && !item.Damaged && item.Sequence > highest {
			s.Latest = id
			highest = item.Sequence
		}
	}
	s.Revision++
	if e := r.save(*s); e != nil {
		return e
	}
	return r.point("corruption-durable")
}
