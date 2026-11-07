package generation

import (
	"context"
	"github.com/nd4y/outpost/internal/localfs"
	"os"
	"syscall"
)

// CheckObject checks a scoped COMPLETE object's presence and length. It is a
// reuse hint, not a content scrub or a new durability receipt. Complete and
// VerifyComplete still hash every object before accepting a generation.
func (r *Replica) CheckObject(ctx context.Context, id string, ref Object) error {
	return r.locked(ctx, func(s *state) error {
		item, ok := s.Generations[id]
		if !ok || !item.Complete {
			return ErrIncomplete
		}
		_, refs, e := r.get(s, id, false)
		if e != nil {
			return e
		}
		if expected, ok := refs[ref.ID]; !ok || expected != ref {
			return ErrInvalid
		}
		f, e := localfs.OpenFile(r.root, "objects/"+ref.ID, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		i, e := f.Stat()
		if e != nil {
			return e
		}
		if !i.Mode().IsRegular() || i.Size() != int64(ref.Bytes) {
			return ErrIncomplete
		}
		return ctx.Err()
	})
}
