package sourceagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

const installPrefix = ".outpost-source-install-"
const maxInstallCandidates = 4

func lockInstallParent(ctx context.Context, directory *os.File) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		e := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			return nil
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			return e
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

// initializeAgent publishes a complete idle runtime, never a half-created final
// directory. Failed candidates stay private on the admitted volume; retry does
// not reuse, remove or reset them. Only this local constructor can select the
// temporary physical directory; the signed binding uses the final bootstrap.
func initializeAgent(ctx context.Context, b Bootstrap, fault func(string) error) (*Agent, error) {
	if e := b.Limits.Validate(); e != nil {
		return nil, e
	}
	if e := b.Local.Volume.Check(ctx, b.Local.Directory, true); e != nil {
		return nil, e
	}
	parent, e := localfs.OpenRoot(filepath.Dir(b.Local.Directory))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	from, e := parent.Open(".")
	if e != nil {
		return nil, e
	}
	defer from.Close()
	if e = lockInstallParent(ctx, from); e != nil {
		return nil, e
	}
	locked := true
	defer func() {
		if locked {
			unix.Flock(int(from.Fd()), unix.LOCK_UN)
		}
	}()
	name := filepath.Base(b.Local.Directory)
	if _, e = parent.Lstat(name); !errors.Is(e, os.ErrNotExist) {
		return nil, ErrInvalid
	}
	prefix := installPrefix + storage.Hash([]byte(b.Local.Directory)) + "-"
	entries, e := from.ReadDir(4097)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(entries) > 4096 {
		return nil, statefile.ErrCapacity
	}
	retained := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			retained++
		}
	}
	if retained >= maxInstallCandidates {
		return nil, statefile.ErrCapacity
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	stage := prefix + hex.EncodeToString(nonce[:])
	a, e := openAt(ctx, b, true, false, filepath.Join(filepath.Dir(b.Local.Directory), stage), fault)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Agent, error) { a.Close(); return nil, e }
	if e = unix.Flock(int(from.Fd()), unix.LOCK_UN); e != nil {
		return fail(e)
	}
	locked = false
	if e = a.point("source-install-state-durable"); e != nil {
		return fail(e)
	}
	if e = a.guard(ctx); e != nil {
		return fail(e)
	}
	dir, e := a.root.Open(".")
	if e != nil {
		return fail(e)
	}
	e = errors.Join(dir.Sync(), dir.Close())
	if e != nil {
		return fail(e)
	}
	staged, e := parent.Lstat(stage)
	if e != nil {
		return fail(e)
	}
	held, e := a.root.Stat(".")
	if e != nil || !os.SameFile(staged, held) {
		return fail(ErrInvalid)
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	if e = unix.Renameat2(int(from.Fd()), stage, int(from.Fd()), name, unix.RENAME_NOREPLACE); e != nil {
		return fail(e)
	}
	a.runtimeDirectory = b.Local.Directory
	if e = a.point("source-install-published"); e != nil {
		return fail(e)
	}
	if e = from.Sync(); e != nil {
		return fail(e)
	}
	if e = a.guard(ctx); e != nil {
		return fail(e)
	}
	a.Fault = nil
	return a, nil
}
