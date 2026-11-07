// Package volume verifies a local owner-enrolled runtime filesystem binding.
package volume

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const Format = "outpost-volume-1"
const Sentinel = ".outpost-volume-1"

var ErrUnavailable = errors.New("required runtime volume unavailable")

type Observation struct {
	Filesystem int64    `json:"filesystem"`
	FSID       [2]int32 `json:"fsid"`
	RootInode  uint64   `json:"rootInode"`
	MountID    uint64   `json:"mountId"`
	ReadOnly   bool     `json:"readOnly"`
}
type Binding struct {
	Format         string   `json:"format"`
	Scope          string   `json:"scope"`
	Epoch          uint64   `json:"epoch"`
	Root           string   `json:"root"`
	Filesystem     int64    `json:"filesystem"`
	FSID           [2]int32 `json:"fsid"`
	RootInode      uint64   `json:"rootInode"`
	SentinelDigest string   `json:"sentinelDigest"`
}
type marker struct {
	Format string `json:"format"`
	Scope  string `json:"scope"`
	Epoch  uint64 `json:"epoch"`
	Nonce  string `json:"nonce"`
}

func observe(f *os.File) (Observation, error) {
	var s unix.Statfs_t
	var i unix.Stat_t
	if e := unix.Fstatfs(int(f.Fd()), &s); e != nil {
		return Observation{}, e
	}
	if e := unix.Fstat(int(f.Fd()), &i); e != nil {
		return Observation{}, e
	}
	m, e := localfs.MountID(f)
	if e != nil {
		return Observation{}, e
	}
	if s.Type != unix.EXT4_SUPER_MAGIC && s.Type != unix.BTRFS_SUPER_MAGIC && s.Type != unix.XFS_SUPER_MAGIC || s.Fsid.Val == [2]int32{} || i.Ino == 0 {
		return Observation{}, ErrUnavailable
	}
	return Observation{Filesystem: s.Type, FSID: s.Fsid.Val, RootInode: i.Ino, MountID: m, ReadOnly: s.Flags&unix.ST_RDONLY != 0}, nil
}
func Probe(ctx context.Context, path string) (Observation, error) {
	if e := ctx.Err(); e != nil {
		return Observation{}, e
	}
	f, e := localfs.OpenDirectory(path)
	if e != nil {
		return Observation{}, errors.Join(ErrUnavailable, e)
	}
	defer f.Close()
	o, e := observe(f)
	if e != nil {
		return o, errors.Join(ErrUnavailable, e)
	}
	return o, ctx.Err()
}
func sentinel(root *os.Root) ([]byte, error) {
	f, e := localfs.OpenFile(root, Sentinel, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() < 1 || i.Size() > 1024 {
		return nil, ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, 1025))
	var m marker
	if e != nil || storage.Decode(b, &m, 1024) != nil || m.Format != Format || !storage.ID(m.Scope) || m.Epoch == 0 || !storage.ID(m.Nonce) {
		return nil, ErrUnavailable
	}
	canonical, _ := json.Marshal(m)
	if !bytes.Equal(b, canonical) {
		return nil, ErrUnavailable
	}
	return b, nil
}

// Enroll is an explicit local owner operation. A supplied prior observation is
// compared before writing; absent roots are never created or auto-selected.
func Enroll(ctx context.Context, path string, expected Observation, scope string, epoch uint64) (Binding, error) {
	var result Binding
	if path == "/" || !storage.ID(scope) || epoch == 0 {
		return result, ErrUnavailable
	}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	r, e := localfs.OpenRoot(path)
	if e != nil {
		return result, errors.Join(ErrUnavailable, e)
	}
	defer r.Close()
	f, e := r.Open(".")
	if e != nil {
		return result, e
	}
	defer f.Close()
	current, e := observe(f)
	if e != nil || current != expected || current.ReadOnly {
		return result, ErrUnavailable
	}
	b, e := sentinel(r)
	if errors.Is(e, os.ErrNotExist) {
		entries, err := f.ReadDir(1)
		if len(entries) != 0 || err != io.EOF {
			return result, ErrUnavailable
		}
		var nonce [32]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return result, e
		}
		b, _ = json.Marshal(marker{Format: Format, Scope: scope, Epoch: epoch, Nonce: hex.EncodeToString(nonce[:])})
		out, e := localfs.OpenFile(r, Sentinel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return result, e
		}
		_, e = out.Write(b)
		if e == nil {
			e = out.Sync()
		}
		e = errors.Join(e, out.Close())
		if e != nil {
			return result, e
		}
		if e = f.Sync(); e != nil {
			return result, e
		}
	} else if e != nil {
		return result, errors.Join(ErrUnavailable, e)
	}
	var m marker
	if json.Unmarshal(b, &m) != nil || m.Scope != scope || m.Epoch != epoch {
		return result, ErrUnavailable
	}
	result = Binding{Format: Format, Scope: scope, Epoch: epoch, Root: path, Filesystem: current.Filesystem, FSID: current.FSID, RootInode: current.RootInode, SentinelDigest: storage.Hash(b)}
	return result, ctx.Err()
}
func (b Binding) Check(ctx context.Context, directory string, initialize bool) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if b.Format != Format || !storage.ID(b.Scope) || b.Epoch == 0 || b.Root == "/" || !filepath.IsAbs(b.Root) || filepath.Clean(b.Root) != b.Root || !storage.ID(b.SentinelDigest) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrUnavailable
	}
	rel, e := filepath.Rel(b.Root, directory)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return ErrUnavailable
	}
	r, e := localfs.OpenRoot(b.Root)
	if e != nil {
		return errors.Join(ErrUnavailable, e)
	}
	defer r.Close()
	f, e := r.Open(".")
	if e != nil {
		return errors.Join(ErrUnavailable, e)
	}
	defer f.Close()
	o, e := observe(f)
	if e != nil || o.ReadOnly || o.Filesystem != b.Filesystem || o.FSID != b.FSID || o.RootInode != b.RootInode {
		return ErrUnavailable
	}
	raw, e := sentinel(r)
	if e != nil || storage.Hash(raw) != b.SentinelDigest {
		return ErrUnavailable
	}
	var m marker
	if json.Unmarshal(raw, &m) != nil || m.Scope != b.Scope || m.Epoch != b.Epoch {
		return ErrUnavailable
	}
	path := b.Root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		path = filepath.Join(path, part)
		child, e := localfs.OpenDirectory(path)
		if errors.Is(e, os.ErrNotExist) && initialize {
			return ctx.Err()
		}
		if e != nil {
			return errors.Join(ErrUnavailable, e)
		}
		m, e := localfs.MountID(child)
		child.Close()
		if e != nil || m != o.MountID {
			return ErrUnavailable
		}
	}
	return ctx.Err()
}

// Open validates the binding and creates/opens only through the verified root.
// It never reopens the requested worker directory by its absolute pathname.
func (b Binding) Open(ctx context.Context, directory string, initialize bool) (*os.Root, error) {
	if e := b.Check(ctx, directory, initialize); e != nil {
		return nil, e
	}
	r, e := localfs.OpenRoot(b.Root)
	if e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	defer r.Close()
	f, e := r.Open(".")
	if e != nil {
		return nil, e
	}
	o, e := observe(f)
	f.Close()
	if e != nil || o.ReadOnly || o.Filesystem != b.Filesystem || o.FSID != b.FSID || o.RootInode != b.RootInode {
		return nil, ErrUnavailable
	}
	raw, e := sentinel(r)
	if e != nil || storage.Hash(raw) != b.SentinelDigest {
		return nil, ErrUnavailable
	}
	rel, e := filepath.Rel(b.Root, directory)
	if e != nil {
		return nil, ErrUnavailable
	}
	if initialize {
		if _, e = r.Lstat(rel); !errors.Is(e, os.ErrNotExist) {
			return nil, ErrUnavailable
		}
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return localfs.OpenAt(r, rel, initialize)
}

// CheckHandle additionally detects replacement of the worker directory itself.
// The existing descriptor stays on the old volume; new work must stop.
func (b Binding) CheckHandle(ctx context.Context, directory string, held *os.Root) error {
	r, e := b.Open(ctx, directory, false)
	if e != nil {
		return e
	}
	defer r.Close()
	a, e := r.Open(".")
	if e != nil {
		return e
	}
	defer a.Close()
	c, e := held.Open(".")
	if e != nil {
		return e
	}
	defer c.Close()
	ai, e := a.Stat()
	if e != nil {
		return e
	}
	ci, e := c.Stat()
	if e != nil {
		return e
	}
	am, e := localfs.MountID(a)
	if e != nil {
		return e
	}
	cm, e := localfs.MountID(c)
	if e != nil {
		return e
	}
	if !os.SameFile(ai, ci) || am != cm {
		return ErrUnavailable
	}
	return ctx.Err()
}
