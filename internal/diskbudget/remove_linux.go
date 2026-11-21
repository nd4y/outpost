package diskbudget

import (
	"context"
	"errors"
	"os"
	"path"
)

// Remove debits only measured allocated blocks after an owned regular file is
// unlinked and its parent is fsynced. It never recurses or removes unknown files.
// The global write lease prevents writers/reconciliation racing this debit.
// A crash or uncertain failure leaves conservative over-accounting; normal
// startup reconciliation recovers it. Per-write overhead stays until a scan,
// because an earlier scan may already have discarded that overhead charge.
func (b *Budget) Remove(ctx context.Context, name string, expectedBytes int64) error {
	if !validPath(name) || expectedBytes < 1 || expectedBytes > 64<<20 {
		return ErrInvalid
	}
	return b.exclusive(ctx, func() error {
		return b.store.WithLock(ctx, func() error {
			s, e := b.load()
			if e != nil {
				return e
			}
			i, e := b.root.Lstat(name)
			if errors.Is(e, os.ErrNotExist) {
				return nil
			}
			if e != nil {
				return e
			}
			if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() != expectedBytes {
				return ErrInvalid
			}
			blocks, e := allocated(i)
			if e != nil {
				return e
			}
			class := category(name)
			if s.Used[class] < blocks {
				return ErrInvalid
			}
			if e = b.root.Remove(name); e != nil {
				return e
			}
			d, e := b.root.Open(path.Dir(name))
			if e != nil {
				return e
			}
			e = errors.Join(d.Sync(), d.Close())
			if e != nil {
				return e
			}
			s.Used[class] -= blocks
			return b.save(s)
		})
	})
}
