package volume

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/nd4y/outpost/internal/localfs"
	"golang.org/x/sys/unix"
)

// compareCopy checks an owner-prepared cold copy with bounded memory. Both
// trees must be private and remain under the admitted service's exclusive
// control. Links and nested mounts have no portable writable-copy semantics.
func compareCopy(ctx context.Context, oldRoot, newRoot *os.Root) error {
	old, fresh := make([]byte, 64<<10), make([]byte, 64<<10)
	return compareDirectory(ctx, oldRoot, newRoot, old, fresh, 0)
}

func compareDirectory(ctx context.Context, old, fresh *os.Root, a, b []byte, depth int) error {
	if depth > 64 {
		return ErrUnavailable
	}
	x, e := old.Open(".")
	if e != nil {
		return e
	}
	defer x.Close()
	y, e := fresh.Open(".")
	if e != nil {
		return e
	}
	defer y.Close()
	xi, e := x.Stat()
	if e != nil {
		return e
	}
	yi, e := y.Stat()
	if e != nil || !sameCopyMetadata(xi, yi, true) || !sameCopyOwnership(x, y, false) {
		return ErrUnavailable
	}
	var originalCount, copiedCount uint64
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		entries, readErr := x.ReadDir(32)
		originalCount += uint64(len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				e = compareChildDirectory(ctx, old, fresh, entry.Name(), a, b, depth)
			} else if entry.Type().IsRegular() {
				e = compareFile(ctx, old, fresh, entry.Name(), a, b)
			} else {
				return ErrUnavailable
			}
			if e != nil {
				return e
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		entries, readErr := y.ReadDir(32)
		copiedCount += uint64(len(entries))
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if originalCount != copiedCount {
		return ErrUnavailable
	}
	return y.Sync()
}

func compareChildDirectory(ctx context.Context, old, fresh *os.Root, name string, a, b []byte, depth int) error {
	x, e := localfs.OpenAt(old, name, false)
	if e != nil {
		return e
	}
	defer x.Close()
	y, e := localfs.OpenAt(fresh, name, false)
	if e != nil {
		return e
	}
	defer y.Close()
	return compareDirectory(ctx, x, y, a, b, depth+1)
}

func sameCopyMetadata(a, b os.FileInfo, directory bool) bool {
	if a.Mode() != b.Mode() || a.Mode().Perm()&0077 != 0 || os.SameFile(a, b) {
		return false
	}
	if directory {
		return a.IsDir() && b.IsDir()
	}
	return a.Mode().IsRegular() && b.Mode().IsRegular() && a.Size() == b.Size()
}

func compareFile(ctx context.Context, old, fresh *os.Root, name string, a, b []byte) error {
	x, e := localfs.OpenFile(old, name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer x.Close()
	y, e := localfs.OpenFile(fresh, name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer y.Close()
	xi, e := x.Stat()
	if e != nil {
		return e
	}
	yi, e := y.Stat()
	if e != nil || !sameCopyMetadata(xi, yi, false) {
		return ErrUnavailable
	}
	if !sameCopyOwnership(x, y, true) || !onRootMount(old, x) || !onRootMount(fresh, y) {
		return ErrUnavailable
	}
	var checked int64
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, ea := io.ReadFull(x, a)
		m, eb := io.ReadFull(y, b)
		checked += int64(n)
		if n != m || !bytes.Equal(a[:n], b[:m]) || (ea == nil) != (eb == nil) {
			return ErrUnavailable
		}
		if ea == nil {
			continue
		}
		if !(errors.Is(ea, io.EOF) || errors.Is(ea, io.ErrUnexpectedEOF)) ||
			!(errors.Is(eb, io.EOF) || errors.Is(eb, io.ErrUnexpectedEOF)) {
			return errors.Join(ea, eb)
		}
		if checked != xi.Size() {
			return ErrUnavailable
		}
		return y.Sync()
	}
}

func onRootMount(root *os.Root, file *os.File) bool {
	dir, e := root.Open(".")
	if e != nil {
		return false
	}
	defer dir.Close()
	a, e := localfs.MountID(dir)
	if e != nil {
		return false
	}
	b, e := localfs.MountID(file)
	return e == nil && a == b
}

func sameCopyOwnership(a, b *os.File, singleLink bool) bool {
	var x, y unix.Stat_t
	return unix.Fstat(int(a.Fd()), &x) == nil && unix.Fstat(int(b.Fd()), &y) == nil &&
		x.Uid == y.Uid && x.Gid == y.Gid && (!singleLink || x.Nlink == 1 && y.Nlink == 1)
}
