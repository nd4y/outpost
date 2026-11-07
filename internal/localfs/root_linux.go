// Package localfs opens private local state paths without symlink ancestors.
package localfs

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

var ErrBoundary = errors.New("local filesystem boundary rejected")

func openDirectory(path string, create bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4095 {
		return nil, ErrBoundary
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 128 {
		return nil, ErrBoundary
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && create {
			e = unix.Mkdirat(fd, part, 0700)
			if e != nil && !errors.Is(e, unix.EEXIST) {
				unix.Close(fd)
				return nil, e
			}
			// Persist the parent entry before allowing any child state to commit.
			if e = unix.Fsync(fd); e != nil {
				unix.Close(fd)
				return nil, e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
func OpenDirectory(path string) (*os.File, error) { return openDirectory(path, false) }

// MkdirAll never follows an existing symlink and never changes existing modes.
// Each newly created parent entry is fsynced before creating descendants.
func MkdirAll(path string) error {
	f, e := openDirectory(path, true)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func MountID(f *os.File) (uint64, error) {
	var st unix.Statx_t
	if e := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st); e != nil {
		return 0, e
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, ErrBoundary
	}
	return st.Mnt_id, nil
}

// OpenRoot compares the rooted handle with a component-wise no-follow walk.
// A rename or mount substitution between the two opens cannot switch identity.
func OpenRoot(path string) (*os.Root, error) {
	f, e := OpenDirectory(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, e
	}
	g, e := r.Open(".")
	if e != nil {
		r.Close()
		return nil, e
	}
	defer g.Close()
	a, e := f.Stat()
	if e != nil {
		r.Close()
		return nil, e
	}
	b, e := g.Stat()
	if e != nil {
		r.Close()
		return nil, e
	}
	am, e := MountID(f)
	if e != nil {
		r.Close()
		return nil, e
	}
	bm, e := MountID(g)
	if e != nil || am != bm || !os.SameFile(a, b) {
		r.Close()
		return nil, ErrBoundary
	}
	return r, nil
}

// OpenAt keeps every lookup and mkdir relative to an already opened directory.
// It rejects symlinks and nested mounts, and owns the returned handle. The caller
// retains parent. A moved or detached parent cannot redirect writes elsewhere.
func OpenAt(parent *os.Root, name string, create bool) (*os.Root, error) {
	if parent == nil || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00") || len(name) > 4095 {
		return nil, ErrBoundary
	}
	parts := strings.Split(name, "/")
	if len(parts) > 128 {
		return nil, ErrBoundary
	}
	current, e := parent.OpenRoot(".")
	if e != nil {
		return nil, e
	}
	base, e := current.Open(".")
	if e != nil {
		current.Close()
		return nil, e
	}
	mount, e := MountID(base)
	base.Close()
	if e != nil {
		current.Close()
		return nil, e
	}
	for _, part := range parts {
		if part == "." {
			continue
		}
		f, e := openOne(current, part, os.O_RDONLY|unix.O_DIRECTORY, 0)
		if errors.Is(e, os.ErrNotExist) && create {
			e = current.Mkdir(part, 0700)
			if e != nil && !errors.Is(e, os.ErrExist) {
				current.Close()
				return nil, e
			}
			d, err := current.Open(".")
			if err != nil {
				current.Close()
				return nil, err
			}
			err = errors.Join(d.Sync(), d.Close())
			if err != nil {
				current.Close()
				return nil, err
			}
			f, e = openOne(current, part, os.O_RDONLY|unix.O_DIRECTORY, 0)
		}
		if e != nil {
			current.Close()
			return nil, e
		}
		i, ie := f.Stat()
		m, me := MountID(f)
		if ie != nil || me != nil || m != mount || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
			f.Close()
			current.Close()
			return nil, ErrBoundary
		}
		next, e := current.OpenRoot(part)
		current.Close()
		if e != nil {
			f.Close()
			return nil, e
		}
		g, e := next.Open(".")
		if e != nil {
			f.Close()
			next.Close()
			return nil, e
		}
		j, je := g.Stat()
		n, ne := MountID(g)
		f.Close()
		g.Close()
		if je != nil || ne != nil || n != mount || !os.SameFile(i, j) {
			next.Close()
			return nil, ErrBoundary
		}
		current = next
	}
	return current, nil
}

func openOne(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	d, e := root.Open(".")
	if e != nil {
		return nil, e
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), name), nil
}

// OpenFile rejects all link ancestors and the final link using kernel-relative
// operations. It never delegates symbolic-link resolution to os.Root.OpenFile.
func OpenFile(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	if root == nil || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00") || len(name) > 4095 {
		return nil, ErrBoundary
	}
	parts := strings.Split(name, "/")
	if len(parts) > 128 {
		return nil, ErrBoundary
	}
	current, e := root.Open(".")
	if e != nil {
		return nil, e
	}
	mount, e := MountID(current)
	if e != nil {
		current.Close()
		return nil, e
	}
	for index, part := range parts {
		openFlags := unix.O_RDONLY | unix.O_DIRECTORY
		if index == len(parts)-1 {
			openFlags = flags | unix.O_NONBLOCK
		}
		fd, err := unix.Openat(int(current.Fd()), part, openFlags|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
		current.Close()
		if err != nil {
			return nil, err
		}
		current = os.NewFile(uintptr(fd), part)
		next, err := MountID(current)
		if err != nil || next != mount {
			current.Close()
			return nil, ErrBoundary
		}
	}
	return current, nil
}

// Directory is for constructors supporting both stand-alone and rooted callers.
// With a parent, name must be relative; without it, name must be absolute.
func Directory(parent *os.Root, name string, create bool) (*os.Root, error) {
	if parent != nil {
		return OpenAt(parent, name, create)
	}
	if create {
		if e := MkdirAll(name); e != nil {
			return nil, e
		}
	}
	return OpenRoot(name)
}

// Stat inspects the exact opened entry, including a final symlink itself. It
// avoids DirEntry.Info's dependence on a pathname after a directory was moved.
func Stat(root *os.Root, name string) (os.FileInfo, error) {
	f, e := OpenFile(root, name, unix.O_PATH, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return f.Stat()
}

// Disjoint rejects equal roots and ancestor relationships by held inode
// identities, including aliases. It only reads parents and never creates paths.
func Disjoint(ctx context.Context, a, b *os.Root) error {
	for _, pair := range [][2]*os.Root{{a, b}, {b, a}} {
		contains, e := Contains(ctx, pair[0], pair[1])
		if e != nil {
			return e
		}
		if contains {
			return ErrBoundary
		}
	}
	return nil
}

// Contains compares identities while walking candidate's parents. A true
// result includes equality. No pathname is created or resolved through links.
func Contains(ctx context.Context, ancestor, candidate *os.Root) (bool, error) {
	if ancestor == nil || candidate == nil {
		return false, ErrBoundary
	}
	target, e := ancestor.Stat(".")
	if e != nil {
		return false, e
	}
	f, e := candidate.Open(".")
	if e != nil {
		return false, e
	}
	for depth := 0; depth < 128; depth++ {
		if e = ctx.Err(); e != nil {
			f.Close()
			return false, e
		}
		info, e := f.Stat()
		if e != nil {
			f.Close()
			return false, e
		}
		if os.SameFile(info, target) {
			f.Close()
			return true, nil
		}
		fd, e := unix.Openat(int(f.Fd()), "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		f.Close()
		if e != nil {
			return false, e
		}
		f = os.NewFile(uintptr(fd), "ancestor")
		parent, e := f.Stat()
		if e != nil {
			f.Close()
			return false, e
		}
		if os.SameFile(info, parent) {
			f.Close()
			return false, nil
		}
	}
	f.Close()
	return false, ErrBoundary
}
