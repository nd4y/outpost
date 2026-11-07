package filekit

import (
	"context"
	"github.com/nd4y/outpost/internal/localfs"
	"os"
	"syscall"
)

func (s *Store) checkObjectContext(ctx context.Context, ref Object) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !validID(ref.ID) || ref.Bytes < 1 || ref.Bytes > MaxObject {
		return ErrInvalid
	}
	if s.backend != nil {
		return s.backend.Check(ctx, ref)
	}
	f, e := localfs.OpenFile(s.root, objectPath(ref.ID), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() != int64(ref.Bytes) {
		return ErrInvalid
	}
	return nil
}
