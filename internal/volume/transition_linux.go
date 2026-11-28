package volume

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

const MoveFormat = "outpost-volume-transition-1"

type MoveRequest struct {
	Format    string      `json:"format"`
	Operation string      `json:"operation"`
	Current   Binding     `json:"current"`
	Directory string      `json:"directory"`
	NextRoot  string      `json:"nextRoot"`
	Probe     Observation `json:"probe"`
}

type SignedMove struct {
	Request   MoveRequest `json:"request"`
	Signature []byte      `json:"signature"`
}

type moveState struct {
	Request    MoveRequest `json:"request"`
	Signature  []byte      `json:"signature"`
	Next       Binding     `json:"next"`
	NewMarker  string      `json:"newMarker"`
	Tombstone  string      `json:"tombstone"`
	OldRetired bool        `json:"oldRetired"`
}

func (r MoveRequest) checked() error {
	if r.Format != MoveFormat || !storage.ID(r.Operation) || r.Current.Format != FencedFormat ||
		r.Current.Epoch == 0 || r.Current.Epoch == ^uint64(0) || r.Probe.ReadOnly {
		return ErrUnavailable
	}
	relative, e := workerRelative(r.Current.Root, r.Directory)
	if e != nil {
		return e
	}
	if _, e = workerRelative(r.NextRoot, filepath.Join(r.NextRoot, relative)); e != nil ||
		r.NextRoot == r.Current.Root || !bindingIdentity(r.Current).independent(identity(r.Probe)) {
		return ErrUnavailable
	}
	return nil
}

func SignMove(r MoveRequest, key ed25519.PrivateKey) ([]byte, error) {
	if e := r.checked(); e != nil {
		return nil, e
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
		return nil, ErrUnavailable
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	return json.Marshal(SignedMove{Request: r, Signature: ed25519.Sign(key, raw)})
}

func VerifyMove(raw []byte, owner ed25519.PublicKey) (SignedMove, error) {
	var signed SignedMove
	if len(owner) != ed25519.PublicKeySize || storage.Decode(raw, &signed, 4096) != nil || signed.Request.checked() != nil {
		return SignedMove{}, ErrUnavailable
	}
	request, e := json.Marshal(signed.Request)
	if e != nil || !ed25519.Verify(owner, request, signed.Signature) {
		return SignedMove{}, ErrUnavailable
	}
	return signed, nil
}

// EnrollFenced is an explicit first enrollment on an empty private data root.
// An interrupted exact enrollment can be resumed without selecting a new root
// or sentinel. It never upgrades an old volume in place.
func EnrollFenced(ctx context.Context, path, directory string, expected Observation, node, authorityPath string,
	owner ed25519.PublicKey) (Binding, error) {
	var zero Binding
	if len(owner) != ed25519.PublicKeySize || !storage.ID(node) {
		return zero, ErrUnavailable
	}
	relative, e := workerRelative(path, directory)
	if e != nil {
		return zero, e
	}
	a, e := openAuthority(ctx, authorityPath, true)
	if e != nil {
		return zero, e
	}
	defer a.close()
	if !a.id.independent(identity(expected)) {
		return zero, ErrUnavailable
	}
	root, obs, e := openMoveRoot(ctx, path, identity(expected))
	if e != nil {
		return zero, e
	}
	defer root.Close()
	st, e := a.read(owner)
	if errors.Is(e, os.ErrNotExist) {
		d, e := root.Open(".")
		if e != nil {
			return zero, e
		}
		entries, end := d.ReadDir(1)
		d.Close()
		if len(entries) != 0 || end != io.EOF || obs != expected {
			return zero, ErrUnavailable
		}
		raw, e := newMarker(FencedFormat, node, 1)
		if e != nil {
			return zero, e
		}
		st = authorityState{Authority: a.id, Owner: owner, Relative: relative,
			Active: bindingFor(path, node, 1, obs, raw), Enrollment: string(raw)}
		if e = a.save(ctx, st); e != nil {
			return zero, e
		}
	} else if e != nil {
		return zero, e
	}
	if st.Active.Root != path || st.Active.Scope != node || st.Active.Epoch != 1 ||
		st.Relative != relative || bindingIdentity(st.Active) != identity(expected) || st.Move != nil {
		return zero, ErrUnavailable
	}
	if st.Enrollment == "" {
		raw, e := sentinel(root, FencedFormat)
		if e != nil || storage.Hash(raw) != st.Active.SentinelDigest {
			return zero, ErrUnavailable
		}
		return st.Active, nil
	}
	if storage.Hash([]byte(st.Enrollment)) != st.Active.SentinelDigest {
		return zero, ErrUnavailable
	}
	if e = installMarker(ctx, root, "", "", st.Enrollment, FencedFormat); e != nil {
		return zero, e
	}
	st.Enrollment = ""
	if e = a.save(ctx, st); e != nil {
		return zero, e
	}
	return st.Active, nil
}

func installMarker(ctx context.Context, root *os.Root, oldFormat, oldDigest, next, nextFormat string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if raw, e := sentinel(root, nextFormat); e == nil && string(raw) == next {
		d, e := root.Open(".")
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	}
	raw, e := sentinel(root, oldFormat)
	if oldDigest != "" && (e != nil || storage.Hash(raw) != oldDigest) ||
		oldDigest == "" && !errors.Is(e, os.ErrNotExist) {
		return ErrUnavailable
	}
	if oldDigest != "" {
		s, e := statefile.OpenAt(root, ".", 2048, false)
		if e != nil {
			return e
		}
		defer s.Close()
		if e = s.Write(Sentinel, []byte(next)); e != nil {
			return e
		}
	} else if e = createMarker(root, next); e != nil {
		return e
	}
	raw, e = sentinel(root, nextFormat)
	if e != nil || string(raw) != next {
		return ErrUnavailable
	}
	return nil
}

func createMarker(root *os.Root, marker string) error {
	name := ".volume-stage-" + rand.Text()
	out, e := localfs.OpenFile(root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(name)
	_, e = out.WriteString(marker)
	if e == nil {
		e = out.Sync()
	}
	if e = errors.Join(e, out.Close()); e != nil {
		return e
	}
	dir, e := root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	fd := int(dir.Fd())
	if e = unix.Renameat2(fd, name, fd, Sentinel, unix.RENAME_NOREPLACE); e != nil {
		return e
	}
	return dir.Sync()
}

// MoveFenced transfers write admission to a distinct prepared volume on this
// host. The protected host authority is the single activation point.
func MoveFenced(ctx context.Context, current Binding, directory, authorityPath string, owner ed25519.PublicKey,
	permit []byte) (Binding, error) {
	return moveFenced(ctx, current, directory, authorityPath, owner, permit, nil)
}

func moveFenced(ctx context.Context, current Binding, directory, authorityPath string, owner ed25519.PublicKey,
	permit []byte, fault func(string) error) (Binding, error) {
	var zero Binding
	signed, e := VerifyMove(permit, owner)
	req := signed.Request
	if e != nil || req.Current != current || req.Directory != directory {
		return zero, ErrUnavailable
	}
	target, expected, operation := req.NextRoot, req.Probe, req.Operation
	relative, _ := workerRelative(current.Root, directory)
	a, e := openAuthority(ctx, authorityPath, true)
	if e != nil {
		return zero, e
	}
	defer a.close()
	st, e := a.read(owner)
	if e != nil || st.Enrollment != "" || st.Relative != relative || !a.id.independent(identity(expected)) {
		return zero, ErrUnavailable
	}
	if st.Active != current {
		if st.Move == nil && st.Last != nil && st.Last.Request == req && st.Last.Next == st.Active &&
			bytes.Equal(st.Last.Signature, signed.Signature) {
			if e = st.Active.check(ctx, filepath.Join(target, st.Relative), false, FencedFormat); e == nil {
				return st.Active, nil
			}
		}
		return zero, ErrUnavailable
	}
	old, _, e := openMoveRoot(ctx, current.Root, bindingIdentity(current))
	if e != nil {
		return zero, e
	}
	defer old.Close()
	fresh, observed, e := openMoveRoot(ctx, target, identity(expected))
	if e != nil {
		return zero, e
	}
	defer fresh.Close()
	verified := false
	if st.Move == nil {
		if observed != expected || st.Last != nil && st.Last.Request.Operation == operation {
			return zero, ErrUnavailable
		}
		if _, e = fresh.Lstat(Sentinel); !errors.Is(e, os.ErrNotExist) {
			return zero, ErrUnavailable
		}
		if _, e = sentinel(old, FencedFormat); e != nil {
			return zero, e
		}
		if e = current.check(ctx, directory, false, FencedFormat); e != nil {
			return zero, e
		}
		if e = verifyWorkerCopy(ctx, old, fresh, relative); e != nil {
			return zero, e
		}
		verified = true
		raw, e := newMarker(FencedFormat, current.Scope, current.Epoch+1)
		if e != nil {
			return zero, e
		}
		tombstone, e := newMarker(retiredFormat, current.Scope, current.Epoch)
		if e != nil {
			return zero, e
		}
		st.Move = &moveState{Request: req, Signature: signed.Signature,
			Next:      bindingFor(target, current.Scope, current.Epoch+1, observed, raw),
			NewMarker: string(raw), Tombstone: string(tombstone)}
		if e = a.save(ctx, st); e != nil {
			return zero, e
		}
	} else if st.Move.Request != req || !bytes.Equal(st.Move.Signature, signed.Signature) {
		return zero, ErrUnavailable
	}
	return finishVolumeMove(ctx, a, st, old, fresh, verified, fault)
}

func verifyWorkerCopy(ctx context.Context, old, fresh *os.Root, relative string) error {
	first, e := localfs.OpenAt(old, relative, false)
	if e != nil {
		return e
	}
	defer first.Close()
	next, e := localfs.OpenAt(fresh, relative, false)
	if e != nil {
		return e
	}
	defer next.Close()
	return compareCopy(ctx, first, next)
}

func finishVolumeMove(ctx context.Context, a *authority, st authorityState, old, fresh *os.Root, verified bool, fault func(string) error) (Binding, error) {
	var zero Binding
	move := st.Move
	if e := a.checkPath(ctx); e != nil {
		return zero, e
	}
	if move.Next.Format != FencedFormat || move.Next.Scope != st.Active.Scope ||
		move.Next.Epoch != st.Active.Epoch+1 || move.Next.Root != move.Request.NextRoot ||
		bindingIdentity(move.Next) != identity(move.Request.Probe) ||
		storage.Hash([]byte(move.NewMarker)) != move.Next.SentinelDigest {
		return zero, ErrUnavailable
	}
	if !verified {
		if e := verifyWorkerCopy(ctx, old, fresh, st.Relative); e != nil {
			return zero, e
		}
	}
	if e := recheckMoveRoot(ctx, old, st.Active); e != nil {
		return zero, e
	}
	if e := recheckMoveRoot(ctx, fresh, move.Next); e != nil {
		return zero, e
	}
	if !move.OldRetired {
		if e := installMarker(ctx, old, FencedFormat, st.Active.SentinelDigest, move.Tombstone, retiredFormat); e != nil {
			return zero, e
		}
		if fault != nil {
			if e := fault("retirement-fsynced"); e != nil {
				return zero, e
			}
		}
		move.OldRetired = true
		if e := a.save(ctx, st); e != nil {
			return zero, e
		}
	}
	retired, e := sentinel(old, retiredFormat)
	if e != nil || string(retired) != move.Tombstone {
		return zero, ErrUnavailable
	}
	if e = recheckMoveRoot(ctx, fresh, move.Next); e != nil {
		return zero, e
	}
	if e = installMarker(ctx, fresh, "", "", move.NewMarker, FencedFormat); e != nil {
		return zero, e
	}
	if e = move.Next.check(ctx, filepath.Join(move.Next.Root, st.Relative), false, FencedFormat); e != nil {
		return zero, e
	}
	st.Active, st.Last, st.Move = move.Next, move, nil
	if e = a.save(ctx, st); e != nil {
		return zero, e
	}
	return st.Active, nil
}

func recheckMoveRoot(ctx context.Context, held *os.Root, binding Binding) error {
	r, observed, e := openMoveRoot(ctx, binding.Root, bindingIdentity(binding))
	if e != nil {
		return e
	}
	defer r.Close()
	i, e := r.Stat(".")
	if e != nil {
		return e
	}
	j, e := held.Stat(".")
	if e != nil || !os.SameFile(i, j) {
		return ErrUnavailable
	}
	old, e := InspectRoot(ctx, held)
	if e != nil || old != observed {
		return ErrUnavailable
	}
	return nil
}
