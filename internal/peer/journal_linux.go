package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
)

const maxJobs = 1024
const maxJournal = 4 << 20

type Binding struct {
	Operation  string `json:"operationId"`
	Kind       string `json:"kind"`
	Domain     string `json:"domain"`
	Repository string `json:"repository"`
	Epoch      uint64 `json:"epoch"`
	Generation string `json:"generation"`
	Peer       string `json:"peer"`
	Executor   string `json:"executor"`
	Expected   string `json:"expectedResultDigest"`
}
type Counters struct {
	ObjectBytesSubmitted int64 `json:"objectBytesSubmitted"`
	ObjectBytesReceived  int64 `json:"objectBytesReceived"`
	ReadbackBytes        int64 `json:"readbackBytes"`
}
type Receipt struct {
	Format        string `json:"format"`
	Target        string `json:"target"`
	Generation    string `json:"generation"`
	CatalogDigest string `json:"catalogDigest"`
	Operation     string `json:"operationId"`
	Verification  string `json:"verification"`
	ObservedUnix  int64  `json:"observedUnix"`
}
type Job struct {
	Binding     Binding  `json:"binding"`
	Attempt     uint64   `json:"attempt"`
	Phase       string   `json:"phase"`
	UpdatedUnix int64    `json:"updatedUnix"`
	LastReceipt *Receipt `json:"lastReceipt,omitempty"`
	Counters    Counters `json:"lastAttemptCounters"`
}
type journalState struct {
	Format     string         `json:"format"`
	Self       string         `json:"self"`
	Domain     string         `json:"domain"`
	Repository string         `json:"repository"`
	Epoch      uint64         `json:"epoch"`
	Jobs       map[string]Job `json:"jobs"`
}
type Journal struct {
	root     *os.Root
	identity journalState
	Admit    statefile.Admission
}

func decode(raw []byte, v any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return ErrProtocol
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return ErrProtocol
	}
	return nil
}
func regularRead(root *os.Root, name string, limit int) ([]byte, error) {
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Size() < 1 || i.Size() > int64(limit) {
		return nil, ErrProtocol
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != i.Size() || len(b) > limit {
		return nil, ErrProtocol
	}
	return b, nil
}
func syncRoot(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (j *Journal) save(s journalState) error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if len(b) > maxJournal {
		return ErrProtocol
	}
	return statefile.Guard(j.Admit, "jobs.json", len(b), func() error { return j.writeState(b) })
}
func (j *Journal) writeState(b []byte) error {
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	temp := ".pending-" + hex.EncodeToString(nonce[:])
	f, e := j.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer j.root.Remove(temp)
	_, e = f.Write(b)
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
	if e = j.root.Rename(temp, "jobs.json"); e != nil {
		return e
	}
	return syncRoot(j.root)
}
func (j *Journal) binding(b Binding) bool {
	return validID(b.Operation) && validID(b.Generation) && validID(b.Peer) && b.Peer != b.Executor && b.Expected == b.Generation && b.Domain == j.identity.Domain && b.Repository == j.identity.Repository && b.Epoch == j.identity.Epoch && b.Executor == j.identity.Self && (b.Kind == "push" || b.Kind == "pull" || b.Kind == "receive" || b.Kind == "serve")
}
func jobKey(b Binding) string {
	return generation.Hash([]byte(b.Executor + "/" + b.Peer + "/" + b.Operation))
}
func phase(s string) bool {
	return s == "PENDING" || s == "TRANSFERRING" || s == "VERIFYING" || s == "COMPLETE" || s == "RETRYABLE" || s == "RELEASED"
}
func (j *Journal) load() (journalState, error) {
	var s journalState
	b, e := regularRead(j.root, "jobs.json", maxJournal)
	if e != nil {
		return s, e
	}
	if e = decode(b, &s, maxJournal); e != nil {
		return s, e
	}
	canonical, e := json.Marshal(s)
	if e != nil || !bytes.Equal(canonical, b) || s.Format != Format || s.Self != j.identity.Self || s.Domain != j.identity.Domain || s.Repository != j.identity.Repository || s.Epoch != j.identity.Epoch || s.Jobs == nil || len(s.Jobs) > maxJobs {
		return s, ErrProtocol
	}
	for id, job := range s.Jobs {
		if !j.binding(job.Binding) || id != jobKey(job.Binding) || job.Attempt == 0 || !phase(job.Phase) || job.UpdatedUnix < 1 || job.Counters.ObjectBytesSubmitted < 0 || job.Counters.ObjectBytesReceived < 0 || job.Counters.ReadbackBytes < 0 {
			return s, ErrProtocol
		}
		if job.LastReceipt != nil && !validReceipt(*job.LastReceipt, job.Binding) {
			return s, ErrProtocol
		}
		if job.Phase == "COMPLETE" && job.LastReceipt == nil {
			return s, ErrProtocol
		}
	}
	return s, nil
}
func OpenJournal(dir, self string, trust generation.Trust, initialize bool) (*Journal, error) {
	if !filepath.IsAbs(dir) || !validID(self) || !validID(trust.Domain) || !validID(trust.Repository) || trust.Epoch == 0 {
		return nil, ErrDenied
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	j := &Journal{root: r, identity: journalState{Format: Format, Self: self, Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch}}
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
		s := j.identity
		s.Jobs = map[string]Job{}
		if e = j.save(s); e != nil {
			r.Close()
			return nil, e
		}
	}
	if _, e = j.load(); e != nil {
		r.Close()
		return nil, e
	}
	return j, nil
}
func (j *Journal) Close() error { return j.root.Close() }
func lockFile(ctx context.Context, root *os.Root, name string) (func(), error) {
	f, e := root.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() {
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
func (j *Journal) with(ctx context.Context, fn func(*journalState) error) error {
	unlock, e := lockFile(ctx, j.root, ".lock")
	if e != nil {
		return e
	}
	defer unlock()
	s, e := j.load()
	if e != nil {
		return e
	}
	return fn(&s)
}
func (j *Journal) Begin(ctx context.Context, b Binding) (Job, error) {
	var result Job
	if !j.binding(b) {
		return result, ErrDenied
	}
	e := j.with(ctx, func(s *journalState) error {
		k := jobKey(b)
		job, exists := s.Jobs[k]
		if exists && job.Binding != b {
			return ErrConflict
		}
		if !exists {
			if len(s.Jobs) >= maxJobs {
				return ErrUnavailable
			}
			job = Job{Binding: b, Phase: "PENDING"}
		}
		if job.Attempt == ^uint64(0) {
			return ErrUnavailable
		}
		job.Attempt++
		job.UpdatedUnix = time.Now().Unix()
		s.Jobs[k] = job
		result = job
		return j.save(*s)
	})
	return result, e
}
func (j *Journal) Read(ctx context.Context, b Binding) (Job, error) {
	var result Job
	if !j.binding(b) {
		return result, ErrDenied
	}
	e := j.with(ctx, func(s *journalState) error {
		job, ok := s.Jobs[jobKey(b)]
		if !ok {
			return ErrUnavailable
		}
		if job.Binding != b {
			return ErrConflict
		}
		result = job
		return nil
	})
	return result, e
}
func (j *Journal) Update(ctx context.Context, b Binding, state string, receipt *Receipt, c Counters) error {
	if !j.binding(b) || !phase(state) || (receipt != nil && !validReceipt(*receipt, b)) || (state == "COMPLETE" && receipt == nil) || c.ObjectBytesSubmitted < 0 || c.ObjectBytesReceived < 0 || c.ReadbackBytes < 0 {
		return ErrProtocol
	}
	return j.with(ctx, func(s *journalState) error {
		k := jobKey(b)
		job, ok := s.Jobs[k]
		if !ok || job.Binding != b {
			return ErrConflict
		}
		job.Phase = state
		job.UpdatedUnix = time.Now().Unix()
		job.Counters = c
		if receipt != nil {
			copy := *receipt
			job.LastReceipt = &copy
		}
		s.Jobs[k] = job
		return j.save(*s)
	})
}
func validReceipt(r Receipt, b Binding) bool {
	target := b.Peer
	if b.Kind == "receive" || b.Kind == "pull" {
		target = b.Executor
	}
	return r.Format == Format && r.Target == target && r.Generation == b.Generation && r.CatalogDigest == b.Expected && r.Operation == b.Operation && r.ObservedUnix > 0 && (r.Verification == "target-full-read" || r.Verification == "client-full-readback" || r.Verification == "local-full-read")
}
