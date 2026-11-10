package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/localfs"
	"golang.org/x/sys/unix"
)

// StageSnapshotFile materializes the authenticated historical dependencies.
// It publishes a new directory and never opens a registry or starts a service.
func StageSnapshotFile(ctx context.Context, input, output string, trust SnapshotTrust, maxBytes int64) (SnapshotReceipt, error) {
	var out SnapshotReceipt
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return out, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	f, e := openSnapshotFile(input, maxBytes)
	if e != nil {
		return out, e
	}
	defer f.Close()
	root, e := localfs.OpenRoot(filepath.Dir(output))
	if e != nil {
		return out, e
	}
	defer root.Close()
	parent, e := root.Open(".")
	if e != nil {
		return out, e
	}
	defer parent.Close()
	info, e := parent.Stat()
	if e != nil {
		return out, e
	}
	if info.Mode().Perm()&0077 != 0 {
		return out, ErrDenied
	}
	name := filepath.Base(output)
	if _, e = localfs.Stat(root, name); !errors.Is(e, os.ErrNotExist) {
		return out, ErrConflict
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return out, e
	}
	tmp := ".partial-management-" + hex.EncodeToString(nonce[:])
	if e = root.Mkdir(tmp, 0700); e != nil {
		return out, e
	}
	stage, e := localfs.OpenAt(root, tmp, false)
	if e != nil {
		return out, e
	}
	defer stage.Close()
	dirs := map[string]bool{}
	inspection, e := inspectSnapshot(ctx, f, trust, maxBytes, func(path string, raw []byte) error {
		dir := filepath.Dir(path)
		if dir != "." && !dirs[dir] {
			if e := stage.Mkdir(dir, 0700); e != nil {
				return e
			}
			dirs[dir] = true
		}
		file, e := localfs.OpenFile(stage, path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		if e = writeSnapshot(ctx, file, raw); e != nil {
			return errors.Join(e, file.Close())
		}
		return errors.Join(file.Sync(), file.Close())
	})
	if e != nil {
		return out, e
	}
	for dir := range dirs {
		if e = syncSnapshotDir(stage, dir); e != nil {
			return out, e
		}
	}
	if e = syncSnapshotDir(stage, "."); e != nil {
		return out, e
	}
	if e = ctx.Err(); e != nil {
		return out, e
	}
	staged, e := stage.Stat(".")
	if e != nil {
		return out, e
	}
	entry, e := localfs.Stat(root, tmp)
	if e != nil || !os.SameFile(staged, entry) {
		return out, ErrConflict
	}
	fd := int(parent.Fd())
	if e = unix.Renameat2(fd, tmp, fd, name, unix.RENAME_NOREPLACE); e != nil {
		return out, e
	}
	if e = parent.Sync(); e != nil {
		return out, e
	}
	return inspection.SnapshotReceipt, nil
}

func syncSnapshotDir(root *os.Root, name string) error {
	dir, e := localfs.OpenFile(root, name, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return e
	}
	return errors.Join(dir.Sync(), dir.Close())
}
