// Package recovery implements local trusted recovery primitives. Keys and
// output profiles are never supplied by shared worker configuration.
package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const AdmissionFormat = "outpost-recovery-admission-1"
const admissionHeadroom = int64(4 << 20)

var ErrInvalid = errors.New("invalid recovery profile or journal")
var ErrConflict = errors.New("recovery operation binding conflict")
var ErrCapacity = statefile.ErrCapacity

type Limits struct {
	Bytes      int64  `json:"bytes"`
	Entries    int    `json:"entries"`
	FreeBytes  int64  `json:"freeBytes"`
	FreeInodes uint64 `json:"freeInodes"`
}

func (l Limits) valid() bool {
	return l.Bytes >= 16<<20 && l.Bytes <= 1<<60 && l.Entries >= 128 && l.Entries <= 131072 && l.FreeBytes >= 1<<20 && l.FreeBytes <= 1<<60 && l.FreeInodes >= 32 && l.FreeInodes <= 1<<40
}

type Estimate struct {
	Bytes   int64 `json:"bytes"`
	Entries int   `json:"entries"`
}
type ReservationRequest struct {
	Operation string   `json:"operation"`
	Binding   string   `json:"binding"`
	Estimate  Estimate `json:"estimate"`
}
type AdmissionState struct {
	Format  string                        `json:"format"`
	Limits  Limits                        `json:"limits"`
	Pending map[string]ReservationRequest `json:"pending"`
}
type Usage struct {
	Bytes   int64 `json:"bytes"`
	Entries int   `json:"entries"`
}

// Admission owns one private output tree for all presets. Its process lock
// covers the complete restore attempt, including output publication. Retained
// unfinished attempts count as used space; measurement never follows symlinks
// or crosses a mount and never removes files.
type Admission struct {
	root   *os.Root
	state  *statefile.Store
	limits Limits
	guard  func(context.Context) error
	Fault  func(string) error
}

func OpenAdmission(ctx context.Context, root *os.Root, limits Limits, initialize bool, guard func(context.Context) error) (*Admission, error) {
	if root == nil || !limits.valid() || guard == nil {
		return nil, ErrInvalid
	}
	if e := guard(ctx); e != nil {
		return nil, e
	}
	r, e := localfs.OpenAt(root, ".", false)
	if e != nil {
		return nil, e
	}
	closeRoot := true
	defer func() {
		if closeRoot {
			r.Close()
		}
	}()
	if initialize {
		f, e := r.Open(".")
		if e != nil {
			return nil, e
		}
		entries, e := f.ReadDir(-1)
		f.Close()
		if e != nil {
			return nil, e
		}
		if len(entries) != 0 {
			return nil, ErrConflict
		}
	}
	a := &Admission{root: r, limits: limits, guard: guard}
	if e = a.space(ctx, Estimate{}); e != nil {
		return nil, e
	}
	s, e := statefile.OpenAt(r, ".admission", 1<<20, initialize)
	if e != nil {
		return nil, e
	}
	a.state = s
	e = s.WithLock(ctx, func() error {
		if initialize {
			if _, e := s.Read("state.json"); !errors.Is(e, os.ErrNotExist) {
				return ErrConflict
			}
			if e := guard(ctx); e != nil {
				return e
			}
			return a.save(AdmissionState{Format: AdmissionFormat, Limits: limits, Pending: map[string]ReservationRequest{}})
		}
		_, e := a.load()
		return e
	})
	if e != nil {
		s.Close()
		return nil, e
	}
	closeRoot = false
	return a, nil
}
func (a *Admission) Close() error { return errors.Join(a.state.Close(), a.root.Close()) }
func (a *Admission) point(name string) error {
	if a.Fault != nil {
		return a.Fault(name)
	}
	return nil
}
func (a *Admission) load() (AdmissionState, error) {
	var s AdmissionState
	b, e := a.state.Read("state.json")
	if e != nil {
		return s, e
	}
	if storage.Decode(b, &s, 1<<20) != nil || s.Format != AdmissionFormat || s.Limits != a.limits || s.Pending == nil || len(s.Pending) > 1024 {
		return s, ErrInvalid
	}
	for id, r := range s.Pending {
		if id != r.Operation || !a.valid(r) {
			return s, ErrInvalid
		}
	}
	return s, nil
}
func (a *Admission) save(s AdmissionState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return a.state.Write("state.json", b)
}
func (a *Admission) valid(r ReservationRequest) bool {
	return storage.ID(r.Operation) && storage.ID(r.Binding) && r.Estimate.Bytes >= 0 && r.Estimate.Bytes <= a.limits.Bytes && r.Estimate.Entries > 0 && r.Estimate.Entries <= a.limits.Entries
}
func (a *Admission) Status(ctx context.Context) (AdmissionState, error) {
	if e := a.guard(ctx); e != nil {
		return AdmissionState{}, e
	}
	return a.load()
}

func (a *Admission) measure(ctx context.Context) (Usage, error) {
	var u Usage
	if e := a.guard(ctx); e != nil {
		return u, e
	}
	f, e := a.root.Open(".")
	if e != nil {
		return u, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return u, e
	}
	base, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return u, ErrInvalid
	}
	mount, e := localfs.MountID(f)
	if e != nil {
		return u, e
	}
	e = fs.WalkDir(a.root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		u.Entries++
		if u.Entries > a.limits.Entries {
			return ErrCapacity
		}
		i, e := entry.Info()
		if e != nil {
			return e
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Dev != base.Dev || st.Blocks < 0 || st.Blocks > 1<<50 || !i.Mode().IsRegular() && !i.IsDir() && i.Mode()&os.ModeSymlink == 0 {
			return ErrInvalid
		}
		u.Bytes += st.Blocks * 512
		if u.Bytes > a.limits.Bytes {
			return ErrCapacity
		}
		if i.IsDir() {
			d, e := localfs.OpenFile(a.root, name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
			if e != nil {
				return e
			}
			mid, e := localfs.MountID(d)
			d.Close()
			if e != nil {
				return e
			}
			if mid != mount {
				return localfs.ErrBoundary
			}
		}
		return nil
	})
	return u, e
}
func (a *Admission) space(ctx context.Context, reserved Estimate) error {
	if e := a.guard(ctx); e != nil {
		return e
	}
	f, e := a.root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	var st syscall.Statfs_t
	if e = syscall.Fstatfs(int(f.Fd()), &st); e != nil {
		return e
	}
	if st.Bsize <= 0 || uint64(st.Bsize) > 1<<30 || st.Bavail > uint64(1<<60)/uint64(st.Bsize) {
		return ErrInvalid
	}
	free := int64(st.Bavail) * st.Bsize
	if free < a.limits.FreeBytes+reserved.Bytes+admissionHeadroom || st.Ffree < a.limits.FreeInodes+uint64(reserved.Entries)+8 {
		return ErrCapacity
	}
	return nil
}

// Lease is valid only inside WithReservation. Guard is a cheap per-batch
// volume/free-space check. BeforePublish additionally measures actual output
// against the reservation and must run before exposing the atomic bundle.
type Lease struct {
	admission *Admission
	before    Usage
	request   ReservationRequest
	others    Estimate
	active    bool
}

func (l *Lease) Guard(ctx context.Context) error {
	if !l.active {
		return ErrInvalid
	}
	return l.admission.space(ctx, l.others)
}
func (l *Lease) BeforePublish(ctx context.Context) error {
	if e := l.Guard(ctx); e != nil {
		return e
	}
	u, e := l.admission.measure(ctx)
	if e != nil {
		return e
	}
	if u.Bytes > l.before.Bytes+l.request.Estimate.Bytes+admissionHeadroom || u.Entries > l.before.Entries+l.request.Estimate.Entries+8 || u.Bytes+l.others.Bytes > l.admission.limits.Bytes || u.Entries+l.others.Entries > l.admission.limits.Entries {
		return ErrCapacity
	}
	return nil
}

func (a *Admission) WithReservation(ctx context.Context, request ReservationRequest, fn func(*Lease) error) error {
	if !a.valid(request) || fn == nil {
		return ErrInvalid
	}
	return a.state.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		if old, exists := s.Pending[request.Operation]; exists && old != request {
			return ErrConflict
		}
		if _, exists := s.Pending[request.Operation]; !exists && len(s.Pending) >= 1024 {
			return ErrCapacity
		}
		others := Estimate{}
		for id, r := range s.Pending {
			if id != request.Operation {
				others.Bytes += r.Estimate.Bytes
				others.Entries += r.Estimate.Entries
				if others.Bytes > a.limits.Bytes || others.Entries > a.limits.Entries {
					return ErrCapacity
				}
			}
		}
		u, e := a.measure(ctx)
		if e != nil {
			return e
		}
		reserved := Estimate{Bytes: others.Bytes + request.Estimate.Bytes, Entries: others.Entries + request.Estimate.Entries}
		if u.Bytes+reserved.Bytes+admissionHeadroom > a.limits.Bytes || u.Entries+reserved.Entries+8 > a.limits.Entries {
			return ErrCapacity
		}
		if e = a.space(ctx, reserved); e != nil {
			return e
		}
		s.Pending[request.Operation] = request
		if e = a.save(s); e != nil {
			return e
		}
		if e = a.point("recovery-reservation-durable"); e != nil {
			return e
		}
		lease := &Lease{admission: a, before: u, request: request, others: others, active: true}
		workErr := fn(lease)
		if workErr == nil {
			workErr = lease.BeforePublish(ctx)
		}
		lease.active = false
		if e = a.point("recovery-attempt-returned"); e != nil {
			return errors.Join(workErr, e)
		}
		// Cancellation stops payload work; a bounded metadata-only reconciliation
		// then accounts retained files before releasing this process's promise.
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, e = a.measure(finish); e != nil {
			return errors.Join(workErr, e)
		}
		delete(s.Pending, request.Operation)
		if e = a.save(s); e != nil {
			return errors.Join(workErr, e)
		}
		return errors.Join(workErr, a.point("recovery-reservation-released"))
	})
}
