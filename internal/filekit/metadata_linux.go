package filekit

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"strings"
	"syscall"
	"time"
)

func validateMetadata(m Metadata) error {
	if m.Mode & ^uint32(07777) != 0 || m.UID == ^uint32(0) || m.GID == ^uint32(0) || len(m.Xattrs) > 256 {
		return ErrInvalid
	}
	total := 0
	for name, value := range m.Xattrs {
		if name == "" || len(name) > 255 || strings.ContainsRune(name, 0) || len(value) > 65536 {
			return ErrInvalid
		}
		total += len(name) + len(value)
	}
	if total > 1<<20 {
		return ErrInvalid
	}
	return nil
}
func fdPath(f *os.File) string { return fmt.Sprintf("/proc/self/fd/%d", f.Fd()) }
func readXattrs(f *os.File) (map[string][]byte, error) {
	p := fdPath(f)
	n, err := syscall.Listxattr(p, nil)
	if err != nil {
		return nil, err
	}
	if n > 65536 {
		return nil, ErrInvalid
	}
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	n, err = syscall.Listxattr(p, b)
	if err != nil {
		return nil, err
	}
	b = b[:n]
	if n == 0 || b[n-1] != 0 {
		return nil, ErrInvalid
	}
	names := strings.Split(string(b[:n-1]), "\x00")
	if len(names) > 256 {
		return nil, ErrInvalid
	}
	attrs := make(map[string][]byte, len(names))
	total := 0
	for _, name := range names {
		if name == "" || len(name) > 255 {
			return nil, ErrInvalid
		}
		size, err := syscall.Getxattr(p, name, nil)
		if err != nil {
			return nil, err
		}
		if size > 65536 {
			return nil, ErrInvalid
		}
		value := make([]byte, size)
		got, err := syscall.Getxattr(p, name, value)
		if err != nil {
			return nil, err
		}
		if got != size {
			return nil, ErrInvalid
		}
		total += len(name) + size
		if total > 1<<20 {
			return nil, ErrInvalid
		}
		attrs[name] = value
	}
	return attrs, nil
}
func captureMetadata(f *os.File) (Metadata, error) {
	var m Metadata
	st, err := f.Stat()
	if err != nil {
		return m, err
	}
	if !st.Mode().IsRegular() {
		return m, ErrInvalid
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return m, ErrInvalid
	}
	m = Metadata{Mode: s.Mode & 07777, UID: s.Uid, GID: s.Gid, MtimeNS: st.ModTime().UnixNano()}
	m.Xattrs, err = readXattrs(f)
	if err != nil {
		return m, err
	}
	return m, validateMetadata(m)
}
func sameMetadata(a, b Metadata) bool {
	return a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID && a.MtimeNS == b.MtimeNS && maps.EqualFunc(a.Xattrs, b.Xattrs, bytes.Equal)
}
func applyMetadata(f *os.File, m Metadata) error {
	if err := validateMetadata(m); err != nil {
		return err
	}
	old, err := captureMetadata(f)
	if err != nil {
		return err
	}
	if old.UID != m.UID || old.GID != m.GID {
		if err = syscall.Fchown(int(f.Fd()), int(m.UID), int(m.GID)); err != nil {
			return err
		}
	}
	if err = syscall.Fchmod(int(f.Fd()), m.Mode); err != nil {
		return err
	}
	for name := range old.Xattrs {
		if _, ok := m.Xattrs[name]; !ok {
			if err = syscall.Removexattr(fdPath(f), name); err != nil {
				return err
			}
		}
	}
	for name, value := range m.Xattrs {
		if err = syscall.Setxattr(fdPath(f), name, value, 0); err != nil {
			return err
		}
	}
	t := time.Unix(0, m.MtimeNS)
	if err = os.Chtimes(fdPath(f), t, t); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	actual, err := captureMetadata(f)
	if err != nil {
		return err
	}
	if !sameMetadata(actual, m) {
		return fmt.Errorf("restored attributes differ: %w", ErrInvalid)
	}
	return nil
}
