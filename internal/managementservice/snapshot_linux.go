package managementservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/management"
)

// Snapshot requires the execution lease: it never stops a running service.
// The explicitly chosen private export directory must be disjoint from live
// state. A failed prefix stays under an unpredictable .partial name; only the
// fully synced file is linked to the requested new name without replacement.
func (s *Service) Snapshot(ctx context.Context, output string, maxBytes int64) (management.SnapshotReceipt, error) {
	var out management.SnapshotReceipt
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || maxBytes < 1 || maxBytes > management.MaxSnapshotBytes {
		return out, management.ErrInvalid
	}
	root, e := localfs.OpenRoot(filepath.Dir(output))
	if e != nil {
		return out, e
	}
	defer root.Close()
	info, e := root.Stat(".")
	if e != nil {
		return out, e
	}
	if info.Mode().Perm()&0077 != 0 {
		return out, management.ErrDenied
	}
	if e = localfs.Disjoint(ctx, s.root, root); e != nil {
		return out, e
	}
	name := filepath.Base(output)
	if _, e = localfs.Stat(root, name); !errors.Is(e, os.ErrNotExist) {
		return out, management.ErrConflict
	}
	e = s.lease.WithLock(ctx, func() error {
		profile, e := s.loadProfile(true)
		if e != nil {
			return e
		}
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return e
		}
		tmp := ".partial-snapshot-" + hex.EncodeToString(nonce[:])
		f, e := localfs.OpenFile(root, tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		receipt, e := s.registry.Snapshot(ctx, f, profile.Revision, profile.ProfileDigest, maxBytes)
		if e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		if e = s.snapshotPoint("management-snapshot-file-durable"); e != nil {
			return e
		}
		if e = s.guard(ctx); e != nil {
			return e
		}
		// Link fails if another writer won the requested name. Never replace an
		// accepted export, symlink, or unrelated existing file.
		if e = root.Link(tmp, name); e != nil {
			return e
		}
		dir, e := root.Open(".")
		if e != nil {
			return e
		}
		defer dir.Close()
		if e = dir.Sync(); e != nil {
			return e
		}
		if e = s.snapshotPoint("management-snapshot-name-durable"); e != nil {
			return e
		}
		if e = root.Remove(tmp); e != nil {
			return e
		}
		if e = dir.Sync(); e != nil {
			return e
		}
		out = receipt
		return nil
	})
	if e != nil {
		return management.SnapshotReceipt{}, e
	}
	return out, nil
}

func (s *Service) snapshotPoint(name string) error {
	if s.SnapshotFault != nil {
		return s.SnapshotFault(name)
	}
	return nil
}
