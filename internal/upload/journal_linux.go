package upload

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const maxJournal = 8 << 20

type Progress struct {
	Round          int64  `json:"round"`
	Attempts       uint64 `json:"attempts"`
	Complete       bool   `json:"complete"`
	SubmittedBytes int64  `json:"submittedBytes"`
}
type Receipt struct {
	Target       string `json:"targetProfile"`
	Generation   string `json:"generation"`
	Operation    string `json:"operationId"`
	Executor     string `json:"executor"`
	Verification string `json:"verification"`
	ObservedUnix int64  `json:"observedUnix"`
}
type State struct {
	Format   string              `json:"format"`
	Plan     string              `json:"planDigest"`
	Worker   string              `json:"worker"`
	Revision uint64              `json:"revision"`
	Phase    string              `json:"phase"`
	Parts    map[string]Progress `json:"parts"`
	Receipt  *Receipt            `json:"receipt,omitempty"`
}
type Journal struct {
	root           *os.Root
	plan           Plan
	planID, worker string
	authority      Authority
	tasks          map[string]bool
	Admit          statefile.Admission
}

func regular(root *os.Root, name string, max int) ([]byte, error) {
	f, e := localfs.OpenFile(root, name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() < 1 || s.Size() > int64(max) {
		return nil, ErrDenied
	}
	data, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil {
		return nil, e
	}
	if len(data) > max || int64(len(data)) != s.Size() {
		return nil, ErrDenied
	}
	return data, nil
}
func syncDir(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func atomicFile(root *os.Root, name string, data []byte) error {
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	temp := ".pending-" + hex.EncodeToString(nonce[:])
	f, e := localfs.OpenFile(root, temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(temp)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = root.Rename(temp, name); e != nil {
		return e
	}
	return syncDir(root)
}
func lock(ctx context.Context, root *os.Root, name string) (func(), error) {
	f, e := localfs.OpenFile(root, name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() {
		f.Close()
		return nil, ErrDenied
	}
	for {
		if e = ctx.Err(); e != nil {
			f.Close()
			return nil, e
		}
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func Open(dir string, raw []byte, worker string, a Authority, initialize bool) (*Journal, error) {
	if !filepath.IsAbs(dir) {
		return nil, ErrDenied
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	return openJournalRoot(r, raw, worker, a, initialize)
}
func openJournalRoot(r *os.Root, raw []byte, worker string, a Authority, initialize bool) (*Journal, error) {
	p, e := Verify(raw, a)
	if e != nil {
		r.Close()
		return nil, e
	}
	if _, ok := p.worker(worker); !ok {
		r.Close()
		return nil, ErrDenied
	}
	a.Planner = append([]byte(nil), a.Planner...)
	a.Generation.Writer = append([]byte(nil), a.Generation.Writer...)
	a.Generation.Maintenance = append([]byte(nil), a.Generation.Maintenance...)
	j := &Journal{root: r, plan: p, planID: storage.Hash(raw), worker: worker, authority: a, tasks: map[string]bool{}}
	tasks, _ := p.Tasks()
	for _, task := range tasks {
		j.tasks[task.Part.ID] = true
	}
	if initialize {
		f, e := r.Open(".")
		if e != nil {
			r.Close()
			return nil, e
		}
		entries, e := f.ReadDir(1)
		f.Close()
		if len(entries) != 0 || e != io.EOF {
			r.Close()
			return nil, ErrDenied
		}
		if e = atomicFile(r, "plan.json", raw); e != nil {
			r.Close()
			return nil, e
		}
		if e = j.save(State{Format: Format, Plan: j.planID, Worker: worker, Phase: "PENDING", Parts: map[string]Progress{}}); e != nil {
			r.Close()
			return nil, e
		}
	}
	saved, e := regular(r, "plan.json", MaxPlan)
	if e != nil || !bytes.Equal(saved, raw) {
		r.Close()
		return nil, ErrConflict
	}
	if _, e = j.load(); e != nil {
		r.Close()
		return nil, e
	}
	return j, nil
}
func (j *Journal) Close() error { return j.root.Close() }
func (j *Journal) save(s State) error {
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if len(raw) > maxJournal {
		return ErrDenied
	}
	return statefile.Guard(j.Admit, "state.json", len(raw), func() error { return atomicFile(j.root, "state.json", raw) })
}
func (j *Journal) load() (State, error) {
	var s State
	raw, e := regular(j.root, "state.json", maxJournal)
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, maxJournal) != nil || s.Format != Format || s.Plan != j.planID || s.Worker != j.worker || s.Parts == nil || len(s.Parts) > MaxTasks {
		return s, ErrConflict
	}
	if s.Phase != "PENDING" && s.Phase != "TRANSFERRING" && s.Phase != "RETRYABLE" && s.Phase != "COMPLETE" {
		return s, ErrDenied
	}
	for id, p := range s.Parts {
		if !j.tasks[id] || p.Round < 0 || p.Attempts == 0 || p.SubmittedBytes < 0 {
			return s, ErrDenied
		}
	}
	if s.Receipt != nil {
		r := s.Receipt
		if r.Target != j.plan.Profile.ID() || r.Generation != j.plan.Generation || r.Operation != j.plan.Operation || r.Executor != j.worker || r.Verification != "full-target-readback" || r.ObservedUnix < 1 {
			return s, ErrDenied
		}
	}
	if s.Phase == "COMPLETE" && s.Receipt == nil {
		return s, ErrDenied
	}
	return s, nil
}
func (j *Journal) edit(ctx context.Context, fn func(*State) error) error {
	unlock, e := lock(ctx, j.root, "state.lock")
	if e != nil {
		return e
	}
	defer unlock()
	s, e := j.load()
	if e != nil {
		return e
	}
	if e = fn(&s); e != nil {
		return e
	}
	if s.Revision == ^uint64(0) {
		return ErrDenied
	}
	s.Revision++
	return j.save(s)
}
func (j *Journal) Status(ctx context.Context) (State, error) {
	unlock, e := lock(ctx, j.root, "state.lock")
	if e != nil {
		return State{}, e
	}
	defer unlock()
	return j.load()
}
func (j *Journal) beginPart(ctx context.Context, id string, round int64) error {
	return j.edit(ctx, func(s *State) error {
		p := s.Parts[id]
		if !j.tasks[id] || round < 0 || p.Attempts == ^uint64(0) {
			return ErrDenied
		}
		p.Round = round
		p.Attempts++
		p.Complete = false
		s.Parts[id] = p
		s.Phase = "TRANSFERRING"
		return nil
	})
}
func (j *Journal) donePart(ctx context.Context, id string, submitted int64) error {
	return j.edit(ctx, func(s *State) error {
		p, ok := s.Parts[id]
		if !ok || submitted < 0 || p.SubmittedBytes > int64(^uint64(0)>>1)-submitted {
			return ErrDenied
		}
		p.Complete = true
		p.SubmittedBytes += submitted
		s.Parts[id] = p
		return nil
	})
}
