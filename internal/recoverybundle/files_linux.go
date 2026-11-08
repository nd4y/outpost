package recoverybundle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

// Options selects an independently trusted distribution. Guard and Fault are
// local hooks, never deserialized remote configuration. Guard is checked before
// creating private material and again before publication.
type Options struct {
	ToolsDirectory string
	ManifestSHA256 string
	Revision       string
	Guard          func(context.Context) error
	Fault          func(string) error
}

func (o Options) guard(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if o.Guard != nil {
		return o.Guard(ctx)
	}
	return nil
}
func (o Options) point(name string) error {
	if o.Fault != nil {
		return o.Fault(name)
	}
	return nil
}

func privateParent(output string) (*os.Root, string, error) {
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || filepath.Base(output) == "." || filepath.Base(output) == string(filepath.Separator) {
		return nil, "", ErrInvalid
	}
	root, e := localfs.OpenRoot(filepath.Dir(output))
	if e != nil {
		return nil, "", e
	}
	st, e := root.Stat(".")
	if e != nil || st.Mode().Perm()&0077 != 0 {
		root.Close()
		return nil, "", ErrDenied
	}
	return root, filepath.Base(output), nil
}

func checkParent(root *os.Root, output string) error {
	current, _, e := privateParent(output)
	if e != nil {
		return e
	}
	defer current.Close()
	a, e := current.Stat(".")
	if e != nil {
		return e
	}
	b, e := root.Stat(".")
	if e != nil {
		return e
	}
	if !os.SameFile(a, b) || b.Mode().Perm()&0077 != 0 {
		return ErrConflict
	}
	return nil
}

// reserve holds the directory lock only while admitting a candidate, never
// during tool copying. Failed candidates remain private and bounded (four per
// target); the owner must inspect them before manually removing any of them.
func reserve(ctx context.Context, root *os.Root, name string, directory bool) (string, error) {
	d, e := root.Open(".")
	if e != nil {
		return "", e
	}
	defer d.Close()
	for {
		if e = ctx.Err(); e != nil {
			return "", e
		}
		e = unix.Flock(int(d.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			break
		}
		if e != unix.EWOULDBLOCK && e != unix.EAGAIN {
			return "", e
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer unix.Flock(int(d.Fd()), unix.LOCK_UN)
	if _, e = root.Lstat(name); !errors.Is(e, os.ErrNotExist) {
		return "", ErrConflict
	}
	entries, e := d.ReadDir(4097)
	if e != nil && !errors.Is(e, io.EOF) {
		return "", e
	}
	if len(entries) > 4096 {
		return "", ErrCapacity
	}
	prefix := ".partial-recovery-" + storage.Hash([]byte(name)) + "-"
	count := 0
	for _, item := range entries {
		if strings.HasPrefix(item.Name(), prefix) {
			count++
		}
	}
	if count >= 4 {
		return "", ErrCapacity
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return "", e
	}
	stage := prefix + hex.EncodeToString(nonce[:])
	if directory {
		e = root.Mkdir(stage, 0700)
	} else {
		var f *os.File
		f, e = localfs.OpenFile(root, stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e == nil {
			e = f.Close()
		}
	}
	if e != nil {
		return "", e
	}
	if e = d.Sync(); e != nil {
		return "", e
	}
	return stage, nil
}

func syncRoot(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}

// Export creates a new private package without replacing any existing result.
// A lost reply may leave a complete result: inspect it using its independently
// retained digest before deciding how to proceed. No failed artifact is erased.
func Export(ctx context.Context, material Material, options Options, output string) (Receipt, error) {
	var out Receipt
	if e := material.validate(); e != nil {
		return out, e
	}
	root, name, e := privateParent(output)
	if e != nil {
		return out, e
	}
	defer root.Close()
	if e = options.guard(ctx); e != nil {
		return out, e
	}
	t, e := openTools(ctx, options.ToolsDirectory, options.ManifestSHA256, options.Revision)
	if e != nil {
		return out, e
	}
	defer t.root.Close()
	if e = localfs.Disjoint(ctx, root, t.root); e != nil {
		return out, ErrDenied
	}
	if e = options.guard(ctx); e != nil {
		return out, e
	}
	stage, e := reserve(ctx, root, name, false)
	if e != nil {
		return out, e
	}
	f, e := localfs.OpenFile(root, stage, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return out, e
	}
	defer f.Close()
	identity, e := f.Stat()
	if e != nil || !identity.Mode().IsRegular() || identity.Size() != 0 || identity.Mode().Perm()&0077 != 0 {
		return out, ErrDenied
	}
	if e = options.point("recovery-export-created"); e != nil {
		return out, e
	}
	out, e = writePackage(ctx, f, material, t)
	if e != nil {
		return Receipt{}, e
	}
	if e = f.Sync(); e != nil {
		return Receipt{}, e
	}
	if e = f.Close(); e != nil {
		return Receipt{}, e
	}
	if e = options.point("recovery-export-file-durable"); e != nil {
		return Receipt{}, e
	}
	if e = options.guard(ctx); e != nil {
		return Receipt{}, e
	}
	if e = checkParent(root, output); e != nil {
		return Receipt{}, e
	}
	current, e := root.Lstat(stage)
	if e != nil || !os.SameFile(current, identity) || !current.Mode().IsRegular() || current.Mode().Perm()&0077 != 0 {
		return Receipt{}, ErrConflict
	}
	if e = root.Link(stage, name); e != nil {
		return Receipt{}, e
	}
	if e = syncRoot(root); e != nil {
		return Receipt{}, e
	}
	if e = options.point("recovery-export-published"); e != nil {
		return Receipt{}, e
	}
	if e = root.Remove(stage); e != nil {
		return Receipt{}, e
	}
	if e = syncRoot(root); e != nil {
		return Receipt{}, e
	}
	return out, nil
}

// Open opens only a private regular artifact through a held, symlink-free
// private parent. Its caller owns the returned descriptor.
func Open(input string) (*os.File, error) {
	root, name, e := privateParent(input)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	return regular(root, name, MaxPackageBytes, true)
}

type syncedFile struct{ *os.File }

func (f syncedFile) Close() error { return errors.Join(f.Sync(), f.File.Close()) }

// Extract authenticates before creating a result, then validates all bytes
// again while writing a private candidate. It never unpacks or runs the nested
// executable archives. Only a fully synced candidate gets the new output name.
func Extract(ctx context.Context, input *os.File, expected, output string) (Receipt, error) {
	return extract(ctx, input, expected, output, nil)
}

func extract(ctx context.Context, input *os.File, expected, output string, fault func(string) error) (Receipt, error) {
	out, e := Inspect(ctx, input, expected)
	if e != nil {
		return Receipt{}, e
	}
	root, name, e := privateParent(output)
	if e != nil {
		return Receipt{}, e
	}
	defer root.Close()
	stage, e := reserve(ctx, root, name, true)
	if e != nil {
		return Receipt{}, e
	}
	destination, e := localfs.OpenAt(root, stage, false)
	if e != nil {
		return Receipt{}, e
	}
	defer destination.Close()
	if e = destination.Mkdir("tools", 0700); e != nil {
		return Receipt{}, e
	}
	if fault != nil {
		if e = fault("recovery-extract-created"); e != nil {
			return Receipt{}, e
		}
	}
	if _, e = input.Seek(0, io.SeekStart); e != nil {
		return Receipt{}, e
	}
	sink := func(name string) (io.WriteCloser, error) {
		f, e := localfs.OpenFile(destination, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		return syncedFile{f}, nil
	}
	written, e := readPackage(ctx, input, sink)
	if e != nil {
		return Receipt{}, e
	}
	if written.SHA256 != expected || written.Bytes != out.Bytes {
		return Receipt{}, ErrInvalid
	}
	toolRoot, e := localfs.OpenAt(destination, "tools", false)
	if e != nil {
		return Receipt{}, e
	}
	e = errors.Join(syncRoot(toolRoot), toolRoot.Close())
	if e != nil {
		return Receipt{}, e
	}
	if e = syncRoot(destination); e != nil {
		return Receipt{}, e
	}
	if fault != nil {
		if e = fault("recovery-extract-files-durable"); e != nil {
			return Receipt{}, e
		}
	}
	if e = ctx.Err(); e != nil {
		return Receipt{}, e
	}
	if e = checkParent(root, output); e != nil {
		return Receipt{}, e
	}
	a, e := root.Lstat(stage)
	if e != nil {
		return Receipt{}, e
	}
	b, e := destination.Stat(".")
	if e != nil || !os.SameFile(a, b) || !a.IsDir() || a.Mode().Perm()&0077 != 0 {
		return Receipt{}, ErrConflict
	}
	parent, e := root.Open(".")
	if e != nil {
		return Receipt{}, e
	}
	defer parent.Close()
	if e = unix.Renameat2(int(parent.Fd()), stage, int(parent.Fd()), name, unix.RENAME_NOREPLACE); e != nil {
		return Receipt{}, e
	}
	if e = parent.Sync(); e != nil {
		return Receipt{}, e
	}
	if fault != nil {
		if e = fault("recovery-extract-published"); e != nil {
			return Receipt{}, e
		}
	}
	return out, nil
}
