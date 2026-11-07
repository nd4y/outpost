// Package statefile provides private, bounded, fsync-backed local state files.
// It is for a persistent local filesystem, never a synchronised folder or NFS.
package statefile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

var ErrInvalid = errors.New("invalid private state")
var ErrCapacity = errors.New("capacity reservation denied")

type Store struct {
	root  *os.Root
	limit int
	gate  chan struct{}
	Admit Admission
}

type Admission func(string, int) (func(bool) error, error)

func Guard(admit Admission, name string, size int, write func() error) error {
	if admit == nil {
		return write()
	}
	finish, e := admit(name, size)
	if e != nil {
		return e
	}
	e = write()
	return errors.Join(e, finish(e == nil))
}
func (s *Store) SetAdmission(ctx context.Context, admit Admission) error {
	return s.WithLock(ctx, func() error { s.Admit = admit; return nil })
}

func Open(dir string, limit int, initialize bool) (*Store, error) {
	return OpenAt(nil, dir, limit, initialize)
}

// OpenAt retains an independent descriptor rooted under parent. A nil parent
// requires an absolute path and is intended for standalone local tools.
func OpenAt(parent *os.Root, dir string, limit int, initialize bool) (*Store, error) {
	if limit < 1 || limit > 64<<20 {
		return nil, ErrInvalid
	}
	r, e := localfs.Directory(parent, dir, initialize)
	if e != nil {
		return nil, e
	}
	i, e := r.Stat(".")
	if e != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		r.Close()
		return nil, ErrInvalid
	}
	return &Store{root: r, limit: limit, gate: make(chan struct{}, 1)}, nil
}
func (s *Store) Close() error { return s.root.Close() }
func nameOK(name string) bool {
	return len(name) > 0 && len(name) <= 128 && !strings.ContainsAny(name, "/\\\x00") && name != "." && name != ".." && !strings.HasPrefix(name, ".tmp-") && name != ".lock"
}
func (s *Store) Read(name string) ([]byte, error) {
	if !nameOK(name) {
		return nil, ErrInvalid
	}
	f, e := localfs.OpenFile(s.root, name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() < 1 || i.Size() > int64(s.limit) {
		return nil, ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(s.limit)+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != i.Size() {
		return nil, ErrInvalid
	}
	return b, nil
}
func (s *Store) Write(name string, b []byte) error {
	return Guard(s.Admit, name, len(b), func() error { return s.write(name, b) })
}
func (s *Store) write(name string, b []byte) error {
	if !nameOK(name) || len(b) < 1 || len(b) > s.limit {
		return ErrInvalid
	}
	var random [16]byte
	if _, e := rand.Read(random[:]); e != nil {
		return e
	}
	temp := ".tmp-" + hex.EncodeToString(random[:])
	f, e := localfs.OpenFile(s.root, temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer s.root.Remove(temp)
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
	if e = s.root.Rename(temp, name); e != nil {
		return e
	}
	d, e := s.root.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// WithLock serializes both goroutines and independent processes. A caller must
// hold it for each read-modify-write transaction. Never re-enter the same Store.
func (s *Store) WithLock(ctx context.Context, fn func() error) error {
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.gate }()
	f, e := localfs.OpenFile(s.root, ".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if e = ctx.Err(); e != nil {
		return e
	}
	return fn()
}
