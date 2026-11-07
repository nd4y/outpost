package filekit

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// rootedParent refuses symlinks in every ancestor, not just the final name.
// Holding the opened parent prevents rename/symlink races from escaping the
// approved tree or changing the object being inspected through a path prefix.
func rootedParent(root *os.Root, relative string) (*os.File, string, error) {
	if root == nil || (relative != "." && !safeName(relative)) {
		return nil, "", ErrInvalid
	}
	parent, e := root.Open(".")
	if e != nil {
		return nil, "", e
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts[:len(parts)-1] {
		fd, e := unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			parent.Close()
			return nil, "", e
		}
		parent.Close()
		parent = os.NewFile(uintptr(fd), "source-directory")
	}
	return parent, parts[len(parts)-1], nil
}
func linkTarget(parent *os.File, name string) (string, error) {
	b := make([]byte, 4096)
	n, e := unix.Readlinkat(int(parent.Fd()), name, b)
	if e != nil {
		return "", e
	}
	if n == 0 || n >= len(b) {
		return "", ErrInvalid
	}
	return string(b[:n]), nil
}
func sameLink(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func linkMetadata(parent *os.File, name string) (Metadata, string, unix.Stat_t, error) {
	var stat unix.Stat_t
	var m Metadata
	if e := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return m, "", stat, e
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFLNK {
		return m, "", stat, ErrInvalid
	}
	target, e := linkTarget(parent, name)
	if e != nil {
		return m, "", stat, e
	}
	p := fdPath(parent) + "/" + name
	attrs, e := readAttributeSet(func(b []byte) (int, error) { return unix.Llistxattr(p, b) }, func(n string, b []byte) (int, error) { return unix.Lgetxattr(p, n, b) })
	if e != nil {
		return m, "", stat, e
	}
	m = Metadata{Mode: stat.Mode & 07777, UID: stat.Uid, GID: stat.Gid, MtimeNS: stat.Mtim.Sec*1e9 + stat.Mtim.Nsec, Xattrs: attrs}
	var after unix.Stat_t
	if e = unix.Fstatat(int(parent.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return m, "", stat, e
	}
	if !sameLink(stat, after) {
		return m, "", stat, ErrInvalid
	}
	return m, target, stat, validateMetadata(m)
}

// BackupEntry captures a regular file, directory or symlink from an approved
// root without following any symlink. It does not recursively scan or establish
// application consistency. The source planner must approve aliases and policy.
func (s *Store) BackupEntry(ctx context.Context, root *os.Root, relative string, opt BackupOptions) (Stats, error) {
	parent, name, e := rootedParent(root, relative)
	if e != nil {
		return Stats{}, e
	}
	defer parent.Close()
	var initial unix.Stat_t
	if e = unix.Fstatat(int(parent.Fd()), name, &initial, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return Stats{}, e
	}
	if initial.Mode&unix.S_IFMT == unix.S_IFREG {
		fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return Stats{}, e
		}
		f := os.NewFile(uintptr(fd), "source-file")
		defer f.Close()
		var opened unix.Stat_t
		if e = unix.Fstat(fd, &opened); e != nil {
			return Stats{}, e
		}
		if !sameLink(initial, opened) {
			return Stats{}, ErrInvalid
		}
		result, e := s.BackupFile(ctx, f, opt)
		var after unix.Stat_t
		if e == nil {
			e = unix.Fstatat(int(parent.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW)
			if e == nil && !sameLink(opened, after) {
				e = ErrInvalid
			}
		}
		return result, e
	}
	if initial.Mode&unix.S_IFMT != unix.S_IFDIR && initial.Mode&unix.S_IFMT != unix.S_IFLNK {
		return Stats{}, ErrInvalid
	}
	if initial.Mode&unix.S_IFMT == unix.S_IFLNK && initial.Nlink != 1 {
		return Stats{}, ErrInvalid
	}
	unlock, e := s.lock(ctx, true)
	if e != nil {
		return Stats{}, e
	}
	defer unlock()
	s.Stats = Stats{}
	if opt.File == "" {
		opt.File = randomID()
	}
	if !validID(opt.File) || len(opt.Names) != 1 || !safeName(opt.Names[0]) {
		return s.Stats, ErrInvalid
	}
	if opt.Previous != "" {
		_, old, e := s.LoadVersion(opt.Previous)
		if e != nil {
			return s.Stats, e
		}
		if old.File != opt.File {
			return s.Stats, ErrInvalid
		}
	}
	d := Descriptor{Format: TypedFormat, Domain: s.Owner.Domain, File: opt.File, Names: append([]string(nil), opt.Names...), SHA256: digest(nil)}
	if initial.Mode&unix.S_IFMT == unix.S_IFDIR {
		fd, e := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return s.Stats, e
		}
		f := os.NewFile(uintptr(fd), "source-directory")
		defer f.Close()
		var opened unix.Stat_t
		if e = unix.Fstat(fd, &opened); e != nil {
			return s.Stats, e
		}
		if !sameLink(initial, opened) {
			return s.Stats, ErrInvalid
		}
		d.Kind = "directory"
		d.Metadata, e = captureMetadata(f)
		if e != nil {
			return s.Stats, e
		}
	} else {
		var observed unix.Stat_t
		d.Kind = "symlink"
		d.Metadata, d.LinkTarget, observed, e = linkMetadata(parent, name)
		if e != nil {
			return s.Stats, e
		}
		if !sameLink(initial, observed) {
			return s.Stats, ErrInvalid
		}
		d.Size = int64(len(d.LinkTarget))
		d.SHA256 = digest([]byte(d.LinkTarget))
	}
	var after unix.Stat_t
	if e = unix.Fstatat(int(parent.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return s.Stats, e
	}
	if !sameLink(initial, after) {
		return s.Stats, ErrInvalid
	}
	if e = ctx.Err(); e != nil {
		return s.Stats, e
	}
	version, e := s.Owner.version(d)
	if e != nil {
		return s.Stats, e
	}
	s.Stats.File = opt.File
	s.Stats.Version = version
	if _, _, e = s.LoadVersion(version); e == nil {
		return s.Stats, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return s.Stats, e
	}
	envelope, e := s.sealDescriptor(d)
	if e != nil {
		return s.Stats, e
	}
	e = s.writeEnvelope("versions/"+version+".json", envelope)
	if e == nil {
		e = unix.Fstatat(int(parent.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW)
		if e == nil && !sameLink(initial, after) {
			e = ErrInvalid
		}
	}
	return s.Stats, e
}

func applyLinkMetadata(root *os.Root, name, target string, m Metadata) error {
	parent, base, e := rootedParent(root, name)
	if e != nil {
		return e
	}
	defer parent.Close()
	old, actual, initial, e := linkMetadata(parent, base)
	if e != nil {
		return e
	}
	if actual != target || m.Mode != 0777 {
		return ErrInvalid
	}
	p := fdPath(parent) + "/" + base
	if old.UID != m.UID || old.GID != m.GID {
		if e = unix.Fchownat(int(parent.Fd()), base, int(m.UID), int(m.GID), unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return e
		}
	}
	for n := range old.Xattrs {
		if _, ok := m.Xattrs[n]; !ok {
			if e = unix.Lremovexattr(p, n); e != nil {
				return e
			}
		}
	}
	for n, b := range m.Xattrs {
		if e = unix.Lsetxattr(p, n, b, 0); e != nil {
			return e
		}
	}
	times := []unix.Timespec{unix.NsecToTimespec(m.MtimeNS), unix.NsecToTimespec(m.MtimeNS)}
	if e = unix.UtimesNanoAt(int(parent.Fd()), base, times, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	final, actual, stat, e := linkMetadata(parent, base)
	if e != nil {
		return e
	}
	if stat.Dev != initial.Dev || stat.Ino != initial.Ino || actual != target || !sameMetadata(m, final) {
		return ErrInvalid
	}
	return parent.Sync()
}
func restoreSpecial(root *os.Root, d Descriptor) error {
	if e := validateDescriptor(d); e != nil {
		return e
	}
	switch d.Kind {
	case "directory":
		if e := root.Mkdir(d.Names[0], 0700); e != nil {
			return e
		}
		f, e := root.OpenFile(d.Names[0], os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		return applyMetadata(f, d.Metadata)
	case "symlink":
		if e := root.Symlink(d.LinkTarget, d.Names[0]); e != nil {
			return e
		}
		return applyLinkMetadata(root, d.Names[0], d.LinkTarget, d.Metadata)
	default:
		return ErrInvalid
	}
}
