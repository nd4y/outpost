package generation

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
)

const VerificationFormat = "outpost-generation-verification-1"
const WindowVerificationFormat = "outpost-generation-window-1"

type objectVerification struct {
	Stamp       catalogStamp `json:"stamp"`
	CheckedUnix int64        `json:"checkedUnix"`
}
type verificationState struct {
	Format      string                        `json:"format"`
	Generation  string                        `json:"generation"`
	Trust       string                        `json:"trust"`
	Window      string                        `json:"window,omitempty"`
	Objects     map[string]objectVerification `json:"objects"`
	CompletedAt int64                         `json:"completedAt,omitempty"`
}
type BatchResult struct {
	Generation      string `json:"generation"`
	Complete        bool   `json:"complete"`
	VerifiedObjects int    `json:"verifiedObjects"`
	TotalObjects    int    `json:"totalObjects"`
	ReadBytes       int64  `json:"readBytes"`
	WrittenBytes    int64  `json:"writtenBytes"`
	VerifiedAt      int64  `json:"verifiedAt,omitempty"`
}

func (r *Replica) objectStamp(ref Object) (catalogStamp, error) {
	f, e := localfs.OpenFile(r.root, "objects/"+ref.ID, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return catalogStamp{}, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return catalogStamp{}, e
	}
	stamp, e := stampOf(i)
	if e != nil || stamp.Size != int64(ref.Bytes) {
		return catalogStamp{}, ErrIncomplete
	}
	return stamp, nil
}
func (r *Replica) verifyObjectStamp(ctx context.Context, ref Object) (catalogStamp, error) {
	if e := ctx.Err(); e != nil {
		return catalogStamp{}, e
	}
	f, e := localfs.OpenFile(r.root, "objects/"+ref.ID, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return catalogStamp{}, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return catalogStamp{}, e
	}
	before, e := stampOf(i)
	if e != nil || before.Size != int64(ref.Bytes) {
		return catalogStamp{}, ErrIncomplete
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(ref.Bytes)+1))
	if e != nil {
		return catalogStamp{}, e
	}
	if len(b) != ref.Bytes || Hash(b) != ref.ID {
		return catalogStamp{}, ErrIncomplete
	}
	i, e = f.Stat()
	if e != nil {
		return catalogStamp{}, e
	}
	after, e := stampOf(i)
	if e != nil || after != before {
		return catalogStamp{}, ErrIncomplete
	}
	return before, ctx.Err()
}
func verificationName(id, window string) string {
	if window == "" {
		return id
	}
	return "window-" + Hash([]byte(id+"/"+window))
}
func (r *Replica) verification(id, window string, refs map[string]Object) (verificationState, error) {
	t, _ := json.Marshal(r.trust)
	v := verificationState{Format: VerificationFormat, Generation: id, Trust: Hash(t), Objects: map[string]objectVerification{}}
	if window != "" {
		v.Format = WindowVerificationFormat
		v.Window = window
	}
	b, e := read(r.root, "verification/"+verificationName(id, window), MaxState)
	if errors.Is(e, os.ErrNotExist) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	var old verificationState
	if canonical(b, &old, MaxState) != nil || old.Format != v.Format || old.Generation != id || old.Trust != v.Trust || old.Window != window || old.Objects == nil || len(old.Objects) > len(refs) || old.CompletedAt < 0 || old.CompletedAt > time.Now().Unix() || old.CompletedAt > 0 && len(old.Objects) != len(refs) {
		return v, ErrInvalid
	}
	for key, checked := range old.Objects {
		ref, ok := refs[key]
		if !ok || checked.Stamp.Size != int64(ref.Bytes) || checked.CheckedUnix <= 0 || checked.CheckedUnix > time.Now().Unix() || old.CompletedAt > 0 && checked.CheckedUnix > old.CompletedAt {
			return v, ErrInvalid
		}
	}
	return old, nil
}
func (r *Replica) saveVerification(v verificationState) error {
	if e := r.root.Mkdir("verification", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	if e := syncDir(r.root, "."); e != nil {
		return e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) > MaxState {
		return statefile.ErrCapacity
	}
	if e = r.write("verification/"+verificationName(v.Generation, v.Window), b); e != nil {
		return e
	}
	return r.point("verification-batch-durable")
}
func (r *Replica) publishComplete(s *state, id string, c Catalog) error {
	refs, e := closure(c)
	if e != nil {
		return e
	}
	for key := range refs {
		if _, damaged := s.Damage[key]; damaged {
			return ErrIncomplete
		}
	}
	if s.Generations[id].Complete && !s.Generations[id].Damaged {
		return nil
	}
	if e := r.point("before-complete"); e != nil {
		return e
	}
	item := s.Generations[id]
	item.Complete = true
	item.Damaged = false
	s.Generations[id] = item
	if s.Latest == "" {
		s.Latest = id
	} else {
		latest, _, e := r.get(s, s.Latest, false)
		if e != nil {
			return e
		}
		if c.Sequence > latest.Sequence {
			s.Latest = id
		}
	}
	s.Revision++
	return r.save(*s)
}

// ReceiveBatch copies and verifies at most maxObjects/maxBytes of payload per
// call, keeping durable verification progress across request/process restarts.
// Receiving references protect every object from maintenance. A verified object
// is reused only while its inode/size/mtime/ctime stamp is unchanged; final
// publication checks all stamps under the replica lock. As with any multi-object
// scrub, this records a verification window, not immunity to later bit rot.
// VerifyComplete always performs a new full content scrub.
func (r *Replica) ReceiveBatch(ctx context.Context, raw []byte, maxObjects int, maxBytes int64, fetch func(Object) ([]byte, error)) (BatchResult, error) {
	var result BatchResult
	if fetch == nil || maxObjects < 1 || maxObjects > 256 || maxBytes < MaxObject || maxBytes > 256<<20 {
		return result, ErrInvalid
	}
	id, e := r.Begin(ctx, raw)
	if e != nil {
		return result, e
	}
	return r.receiveBatch(ctx, id, "", maxObjects, maxBytes, fetch, false, "")
}

// VerifyWindow reads bounded payload of an already admitted generation. The
// caller binds window to authenticated operation/target/scope. A new window
// always starts fresh; replay preserves the oldest supporting read time.
// It neither admits history nor fetches or repairs missing/corrupt objects.
func (r *Replica) VerifyWindow(ctx context.Context, id, window string, maxObjects int, maxBytes int64) (BatchResult, error) {
	if !validID(id) || !validID(window) || maxObjects < 1 || maxObjects > 256 || maxBytes < MaxObject || maxBytes > 256<<20 {
		return BatchResult{}, ErrInvalid
	}
	return r.receiveBatch(ctx, id, window, maxObjects, maxBytes, nil, false, "")
}

// RepairWindow uses an already admitted catalog and an explicitly authorized
// fetcher. A unique operation window rechecks the complete closure, fetching
// only damaged/missing objects and preserving corrupt bytes before replacement.
func (r *Replica) RepairWindow(ctx context.Context, id, window string, maxObjects int, maxBytes int64, fetch func(Object) ([]byte, error)) (BatchResult, error) {
	if !validID(id) || !validID(window) || fetch == nil || maxObjects < 1 || maxObjects > 256 || maxBytes < MaxObject || maxBytes > 256<<20 {
		return BatchResult{}, ErrInvalid
	}
	return r.receiveBatch(ctx, id, window, maxObjects, maxBytes, fetch, true, "")
}

// RepairWindowFor binds every locked checkpoint to the same damage incarnation.
// A nil fetcher verifies already delivered objects without fetching replacements.
func (r *Replica) RepairWindowFor(ctx context.Context, id, window, token string, maxObjects int, maxBytes int64, fetch func(Object) ([]byte, error)) (BatchResult, error) {
	if !validID(id) || !validID(window) || !validID(token) || maxObjects < 1 || maxObjects > 256 || maxBytes < MaxObject || maxBytes > 256<<20 {
		return BatchResult{}, ErrInvalid
	}
	return r.receiveBatch(ctx, id, window, maxObjects, maxBytes, fetch, fetch != nil, token)
}
func verificationTime(v verificationState) int64 {
	oldest := v.CompletedAt
	if v.Window != "" {
		for _, checked := range v.Objects {
			oldest = min(oldest, checked.CheckedUnix)
		}
	}
	return oldest
}
func (r *Replica) receiveBatch(ctx context.Context, id, window string, maxObjects int, maxBytes int64, fetch func(Object) ([]byte, error), repair bool, token string) (BatchResult, error) {
	var result BatchResult
	result.Generation = id
	var todo []Object
	e := r.locked(ctx, func(s *state) error {
		if token != "" {
			if e := checkRepair(s, id, token); e != nil {
				return e
			}
		}
		_, refs, e := r.get(s, id, true)
		if e != nil {
			return e
		}
		result.TotalObjects = len(refs)
		v, e := r.verification(id, window, refs)
		if e != nil {
			return e
		}
		var bytes int64
		for _, key := range sortedIDs(refs) {
			if e := ctx.Err(); e != nil {
				return e
			}
			ref := refs[key]
			_, damaged := s.Damage[key]
			if checked, ok := v.Objects[key]; ok && !damaged {
				stamp, e := r.objectStamp(ref)
				if e == nil && stamp == checked.Stamp {
					continue
				}
			}
			if len(todo) == maxObjects || bytes+int64(ref.Bytes) > maxBytes {
				break
			}
			todo = append(todo, ref)
			bytes += int64(ref.Bytes)
		}
		if len(todo) == 0 && len(v.Objects) == len(refs) && v.CompletedAt > 0 && s.Generations[id].Complete && !s.Generations[id].Damaged {
			result.Complete = true
			result.VerifiedObjects = len(refs)
			result.VerifiedAt = verificationTime(v)
		}
		return nil
	})
	if e != nil || result.Complete {
		return result, e
	}
	verified := map[string]objectVerification{}
	for _, ref := range todo {
		var stamp catalogStamp
		needsRepair := false
		observed := time.Now().Unix()
		e = r.locked(ctx, func(s *state) error {
			if token != "" {
				if e := checkRepair(s, id, token); e != nil {
					return e
				}
			}
			var e error
			_, refs, e := r.get(s, id, false)
			if e != nil {
				return e
			}
			if refs[ref.ID] != ref {
				return ErrInvalid
			}
			stamp, e = r.verifyObjectStamp(ctx, ref)
			if integrityFailure(e) && (!errors.Is(e, os.ErrNotExist) || s.Generations[id].Complete) {
				if mark := r.recordDamage(s, ref); mark != nil {
					return mark
				}
			}
			_, damaged := s.Damage[ref.ID]
			needsRepair = repair && (damaged || integrityFailure(e))
			return e
		})
		if errors.Is(e, os.ErrNotExist) || needsRepair {
			if fetch == nil {
				return result, ErrIncomplete
			}
			b, err := fetch(ref)
			if err != nil {
				return result, err
			}
			if repair {
				err = r.repairPut(ctx, id, ref.ID, token, b)
			} else {
				err = r.Put(ctx, id, ref.ID, b)
			}
			if err != nil {
				return result, err
			}
			result.WrittenBytes += int64(len(b))
			e = r.locked(ctx, func(s *state) error { var err error; stamp, err = r.verifyObjectStamp(ctx, ref); return err })
		}
		if e != nil {
			return result, e
		}
		result.ReadBytes += int64(ref.Bytes)
		verified[ref.ID] = objectVerification{Stamp: stamp, CheckedUnix: observed}
	}
	e = r.locked(ctx, func(s *state) error {
		if token != "" {
			if e := checkRepair(s, id, token); e != nil {
				return e
			}
		}
		c, refs, e := r.get(s, id, true)
		if e != nil {
			return e
		}
		v, e := r.verification(id, window, refs)
		if e != nil {
			return e
		}
		for key, checked := range verified {
			v.Objects[key] = checked
		}
		for key, ref := range refs {
			if e := ctx.Err(); e != nil {
				return e
			}
			checked, ok := v.Objects[key]
			if !ok {
				continue
			}
			stamp, e := r.objectStamp(ref)
			if e != nil || stamp != checked.Stamp {
				delete(v.Objects, key)
			}
		}
		if len(v.Objects) == len(refs) {
			if v.CompletedAt == 0 || len(verified) > 0 {
				v.CompletedAt = time.Now().Unix()
			}
		} else {
			v.CompletedAt = 0
		}
		if e = r.saveVerification(v); e != nil {
			return e
		}
		result.VerifiedObjects = len(v.Objects)
		if len(v.Objects) != len(refs) {
			return nil
		}
		if e = r.publishComplete(s, id, c); e != nil {
			return e
		}
		result.Complete = true
		result.VerifiedAt = verificationTime(v)
		return nil
	})
	return result, e
}
