// Package diskbudget accounts for a private worker volume before writes. Its
// persistent reservations are shared by independent processes on the same
// local filesystem. Reconciliation never removes payloads or abandoned files.
package diskbudget

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

const Format = "outpost-capacity-1"
const ledgerReserve = int64(2 << 20)
const overhead = int64(64 << 10)

var ErrCapacity = statefile.ErrCapacity
var ErrInvalid = errors.New("invalid capacity ledger")
var ErrBusy = errors.New("capacity reconciliation or path busy")

type Limits struct {
	Capacity  int64 `json:"capacity"`
	Reserve   int64 `json:"reserve"`
	Spool     int64 `json:"spool"`
	Telemetry int64 `json:"telemetry"`
}

func (l Limits) valid() bool {
	return l.Capacity >= 16<<20 && l.Capacity <= 1<<60 && l.Reserve >= 1<<20 && l.Spool >= 4<<20 && l.Telemetry >= 65536 && l.Reserve < l.Capacity && l.Spool < l.Capacity-l.Reserve && l.Telemetry < l.Capacity-l.Reserve-l.Spool
}
func (l Limits) maximum(class string) int64 {
	switch class {
	case "data":
		return l.Capacity - l.Reserve - l.Spool - l.Telemetry
	case "spool":
		return l.Spool - ledgerReserve
	case "telemetry":
		return l.Telemetry
	}
	return -1
}

type Reservation struct {
	Path     string `json:"path"`
	Class    string `json:"class"`
	Bytes    int64  `json:"bytes"`
	Previous int64  `json:"previous"`
}
type State struct {
	Format   string                 `json:"format"`
	Limits   Limits                 `json:"limits"`
	Used     map[string]int64       `json:"used"`
	Pending  map[string]Reservation `json:"pending"`
	Revision uint64                 `json:"revision"`
}
type Budget struct {
	root  *os.Root
	store *statefile.Store
}

func validPath(name string) bool {
	return name != "" && name != "." && len(name) <= 4096 && !strings.ContainsAny(name, "\\\x00") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../") && name != ".capacity" && !strings.HasPrefix(name, ".capacity/")
}
func category(name string) string {
	parts := strings.Split(name, "/")
	if parts[0] == "telemetry" {
		return "telemetry"
	}
	for _, p := range parts {
		if p == "objects" {
			return "data"
		}
	}
	return "spool"
}
func allocated(info fs.FileInfo) (int64, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Blocks < 0 || st.Blocks > 1<<50 || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
		return 0, ErrInvalid
	}
	return st.Blocks * 512, nil
}
func (b *Budget) size(name string) (int64, error) {
	i, e := b.root.Lstat(name)
	if errors.Is(e, os.ErrNotExist) {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	if !i.Mode().IsRegular() {
		return 0, ErrInvalid
	}
	return allocated(i)
}
func Open(ctx context.Context, dir string, limits Limits, initialize bool) (*Budget, error) {
	if !filepath.IsAbs(dir) || !limits.valid() {
		return nil, ErrInvalid
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	volume, e := root.Open(".")
	if e != nil {
		root.Close()
		return nil, e
	}
	var filesystem syscall.Statfs_t
	e = syscall.Fstatfs(int(volume.Fd()), &filesystem)
	volume.Close()
	if e != nil || filesystem.Type != unix.EXT4_SUPER_MAGIC && filesystem.Type != unix.BTRFS_SUPER_MAGIC && filesystem.Type != unix.XFS_SUPER_MAGIC {
		root.Close()
		return nil, ErrInvalid
	}
	s, e := statefile.Open(filepath.Join(dir, ".capacity"), 1<<20, initialize)
	if e != nil {
		root.Close()
		return nil, e
	}
	b := &Budget{root, s}
	e = b.exclusive(ctx, func() error {
		return s.WithLock(ctx, func() error {
			_, err := b.load()
			if errors.Is(err, os.ErrNotExist) && initialize {
				return b.reconcile(ctx, limits)
			}
			return err
		})
	})
	if e != nil {
		b.Close()
		return nil, e
	}
	return b, nil
}
func (b *Budget) Close() error { return errors.Join(b.store.Close(), b.root.Close()) }
func (b *Budget) load() (State, error) {
	var s State
	raw, e := b.store.Read("ledger.json")
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, 1<<20) != nil || s.Format != Format || !s.Limits.valid() || len(s.Used) != 3 || s.Pending == nil || len(s.Pending) > 128 {
		return s, ErrInvalid
	}
	for _, class := range []string{"data", "spool", "telemetry"} {
		v, ok := s.Used[class]
		if !ok || v < 0 || v > 1<<61 {
			return s, ErrInvalid
		}
	}
	paths := map[string]bool{}
	for id, r := range s.Pending {
		if !storage.ID(id) || !validPath(r.Path) || r.Class != category(r.Path) || r.Bytes <= 0 || r.Bytes > 65<<20 || r.Previous < 0 || r.Previous > 1<<60 || paths[r.Path] {
			return s, ErrInvalid
		}
		paths[r.Path] = true
	}
	return s, nil
}
func (b *Budget) save(s State) error {
	if s.Revision == ^uint64(0) {
		return ErrInvalid
	}
	s.Revision++
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return b.store.Write("ledger.json", raw)
}
func (b *Budget) lock(ctx context.Context, exclusive bool) (func(), error) {
	f, e := b.root.OpenFile(".capacity/inflight.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, ErrInvalid
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	for {
		e = syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
		if e == nil {
			break
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
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func (b *Budget) exclusive(ctx context.Context, fn func() error) error {
	unlock, e := b.lock(ctx, true)
	if e != nil {
		return e
	}
	defer unlock()
	return fn()
}
func (b *Budget) reconcile(ctx context.Context, limits Limits) error {
	if !limits.valid() {
		return ErrInvalid
	}
	s := State{Format: Format, Limits: limits, Used: map[string]int64{"data": 0, "spool": 0, "telemetry": 0}, Pending: map[string]Reservation{}}
	if old, e := b.load(); e == nil {
		s.Revision = old.Revision
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	count := 0
	add := func(name string, info fs.FileInfo) error {
		count++
		if count > 1000000 {
			return ErrCapacity
		}
		n, e := allocated(info)
		if e != nil {
			return e
		}
		class := category(name)
		if s.Used[class] > (1<<60)-n {
			return ErrInvalid
		}
		s.Used[class] += n
		return nil
	}
	var scan func(string, int) error
	scan = func(name string, depth int) error {
		if depth > 32 {
			return ErrInvalid
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		directory, e := b.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
		if e != nil {
			return e
		}
		defer directory.Close()
		info, e := directory.Stat()
		if e != nil {
			return e
		}
		if e = add(name, info); e != nil {
			return e
		}
		for {
			entries, e := directory.ReadDir(128)
			if e != nil && !errors.Is(e, io.EOF) {
				return e
			}
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					return err
				}
				child := path.Join(name, entry.Name())
				if child == ".capacity" {
					continue
				}
				if entry.IsDir() {
					if err := scan(child, depth+1); err != nil {
						return err
					}
				} else {
					info, err := entry.Info()
					if err != nil {
						return err
					}
					if err = add(child, info); err != nil {
						return err
					}
				}
			}
			if errors.Is(e, io.EOF) {
				return nil
			}
		}
	}
	e := scan(".", 0)
	if e != nil {
		return e
	}
	// Retained data may exceed a newly reduced budget. Persist the honest usage;
	// subsequent reservations fail, and no old copy is deleted to make room.
	return b.save(s)
}

// Reconcile holds an exclusive write lease. Kernel-released leases after a
// process crash allow orphan reservations to be replaced by measured usage.
func (b *Budget) Reconcile(ctx context.Context, limits Limits) error {
	return b.exclusive(ctx, func() error {
		return b.store.WithLock(ctx, func() error {
			if _, e := b.load(); e != nil {
				return e
			}
			return b.reconcile(ctx, limits)
		})
	})
}
func (b *Budget) Status(ctx context.Context) (State, error) {
	var s State
	e := b.store.WithLock(ctx, func() error { var e error; s, e = b.load(); return e })
	return s, e
}
func (b *Budget) free() (int64, error) {
	f, e := b.root.Open(".")
	if e != nil {
		return 0, e
	}
	defer f.Close()
	var s syscall.Statfs_t
	if e = syscall.Fstatfs(int(f.Fd()), &s); e != nil {
		return 0, e
	}
	if s.Bsize <= 0 || s.Bavail > uint64(1<<61)/uint64(s.Bsize) || s.Ffree < 256 {
		return 0, ErrCapacity
	}
	return int64(s.Bavail) * s.Bsize, nil
}

// Reserve returns a completion function that MUST run after the filesystem
// operation, even on failure. Success means the rename and directory fsync
// finished. Uncertain failures conservatively charge the full reservation.
func (b *Budget) Reserve(ctx context.Context, name string, size int) (func(bool) error, error) {
	if !validPath(name) || size < 1 || size > 64<<20 {
		return nil, ErrInvalid
	}
	unlock, e := b.lock(ctx, false)
	if e != nil {
		return nil, e
	}
	var random [32]byte
	if _, e = rand.Read(random[:]); e != nil {
		unlock()
		return nil, e
	}
	id := hex.EncodeToString(random[:])
	amount := (int64(size)+4095)/4096*4096 + overhead
	e = b.store.WithLock(ctx, func() error {
		s, e := b.load()
		if e != nil {
			return e
		}
		if len(s.Pending) >= 128 {
			return ErrCapacity
		}
		reserved := map[string]int64{}
		total := ledgerReserve
		for _, used := range s.Used {
			total += used
		}
		for _, r := range s.Pending {
			if r.Path == name {
				return ErrBusy
			}
			reserved[r.Class] += r.Bytes
			total += r.Bytes
		}
		class := category(name)
		if s.Used[class]+reserved[class]+amount > s.Limits.maximum(class) || total+amount > s.Limits.Capacity-s.Limits.Reserve {
			return ErrCapacity
		}
		free, e := b.free()
		if e != nil {
			return e
		}
		var pending int64
		for _, n := range reserved {
			pending += n
		}
		if free < s.Limits.Reserve+pending+amount+ledgerReserve {
			return ErrCapacity
		}
		previous, e := b.size(name)
		if e != nil {
			return e
		}
		s.Pending[id] = Reservation{name, class, amount, previous}
		return b.save(s)
	})
	if e != nil {
		unlock()
		return nil, e
	}
	done := false
	return func(committed bool) error {
		if done {
			return ErrInvalid
		}
		done = true
		defer unlock()
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return b.store.WithLock(finish, func() error {
			s, e := b.load()
			if e != nil {
				return e
			}
			r, ok := s.Pending[id]
			if !ok {
				return ErrInvalid
			}
			delta := r.Bytes
			if committed {
				current, e := b.size(name)
				if e != nil {
					return e
				}
				if current > r.Bytes {
					return ErrCapacity
				}
				delta = current - r.Previous
				if r.Previous == 0 {
					delta += overhead
				}
			}
			if delta < 0 && s.Used[r.Class] < -delta {
				return ErrInvalid
			}
			s.Used[r.Class] += delta
			delete(s.Pending, id)
			return b.save(s)
		})
	}, nil
}

// Admission binds an existing writer's relative filenames to its admitted root.
func (b *Budget) Admission(prefix string) func(string, int) (func(bool) error, error) {
	return func(name string, size int) (func(bool) error, error) {
		if !validPath(name) || prefix != "" && !validPath(prefix) {
			return nil, ErrInvalid
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return b.Reserve(ctx, path.Join(prefix, name), size)
	}
}
