package volume

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

// FencedFormat is used only by a migration-capable worker installed with an
// independent host authority. Legacy volume readers refuse its marker.
const FencedFormat = "outpost-volume-2"

const retiredFormat = "outpost-volume-retired-2"
const authorityName = "worker-volume.json"
const authorityLimit = 32768

type diskIdentity struct {
	Filesystem int64    `json:"filesystem"`
	FSID       [2]int32 `json:"fsid"`
	Inode      uint64   `json:"inode"`
}

func identity(p Observation) diskIdentity {
	return diskIdentity{p.Filesystem, p.FSID, p.RootInode}
}

func (x diskIdentity) independent(y diskIdentity) bool {
	return x.FSID != y.FSID
}

type authorityState struct {
	Authority  diskIdentity      `json:"authority"`
	Owner      ed25519.PublicKey `json:"owner"`
	Relative   string            `json:"relative"`
	Active     Binding           `json:"active"`
	Enrollment string            `json:"enrollment,omitempty"`
	Move       *moveState        `json:"move,omitempty"`
	Last       *moveState        `json:"last,omitempty"`
}

type authority struct {
	root  *os.Root
	lock  *os.File
	store *statefile.Store
	id    diskIdentity
	path  string
}

func openAuthority(ctx context.Context, path string, exclusive bool) (*authority, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if path == "/" {
		return nil, ErrUnavailable
	}
	r, e := localfs.OpenRoot(path)
	if e != nil {
		return nil, errors.Join(ErrUnavailable, e)
	}
	f, e := r.Open(".")
	if e != nil {
		r.Close()
		return nil, e
	}
	a := &authority{root: r, lock: f, path: path}
	fail := func(e error) (*authority, error) {
		a.close()
		return nil, errors.Join(ErrUnavailable, e)
	}
	var stat unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &stat); e != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		return fail(e)
	}
	o, e := observe(f)
	if e != nil || exclusive && o.ReadOnly {
		return fail(e)
	}
	a.id = identity(o)
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	if e = unix.Flock(int(f.Fd()), mode|unix.LOCK_NB); e != nil {
		return fail(e)
	}
	a.store, e = statefile.OpenAt(r, ".", authorityLimit, false)
	if e != nil {
		return fail(e)
	}
	return a, nil
}

func (a *authority) close() {
	if a.store != nil {
		a.store.Close()
	}
	a.lock.Close()
	a.root.Close()
}

func (a *authority) checkPath(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	f, e := localfs.OpenDirectory(a.path)
	if e != nil {
		return errors.Join(ErrUnavailable, e)
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return errors.Join(ErrUnavailable, e)
	}
	j, e := a.lock.Stat()
	if e != nil || !os.SameFile(i, j) {
		return ErrUnavailable
	}
	return nil
}

func (a *authority) read(owner ed25519.PublicKey) (authorityState, error) {
	var st authorityState
	raw, e := a.store.Read(authorityName)
	if e != nil {
		return st, e
	}
	if storage.Decode(raw, &st, authorityLimit) != nil || st.Authority != a.id ||
		len(owner) != ed25519.PublicKeySize || !bytes.Equal(st.Owner, owner) ||
		st.Active.Format != FencedFormat || !a.id.independent(bindingIdentity(st.Active)) ||
		st.Relative == "" || st.Relative == "." {
		return authorityState{}, ErrUnavailable
	}
	return st, nil
}

func (a *authority) save(ctx context.Context, st authorityState) error {
	if e := a.checkPath(ctx); e != nil {
		return e
	}
	raw, e := json.Marshal(st)
	if e != nil {
		return e
	}
	return a.store.Write(authorityName, raw)
}

func bindingIdentity(b Binding) diskIdentity {
	return diskIdentity{b.Filesystem, b.FSID, b.RootInode}
}

func bindingFor(path, node string, epoch uint64, o Observation, raw []byte) Binding {
	return Binding{Format: FencedFormat, Scope: node, Epoch: epoch, Root: path, Filesystem: o.Filesystem,
		FSID: o.FSID, RootInode: o.RootInode, SentinelDigest: storage.Hash(raw)}
}

func workerRelative(root, directory string) (string, error) {
	if !filepath.IsAbs(root) || root == "/" || filepath.Clean(root) != root ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", ErrUnavailable
	}
	relative, e := filepath.Rel(root, directory)
	if e != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", ErrUnavailable
	}
	return relative, nil
}

// OpenFenced admits every worker process under a shared lock on the pinned
// host authority, then returns the guard and a cleanup held for its lifetime.
func OpenFenced(ctx context.Context, binding Binding, directory, path string, owner ed25519.PublicKey,
	initialize bool) (*os.Root, func(context.Context) error, func(), error) {
	a, e := openAuthority(ctx, path, false)
	if e != nil {
		return nil, nil, nil, e
	}
	fail := func(e error) (*os.Root, func(context.Context) error, func(), error) {
		a.close()
		return nil, nil, nil, errors.Join(ErrUnavailable, e)
	}
	st, e := a.read(owner)
	if e != nil || st.Enrollment != "" || st.Move != nil || st.Active != binding ||
		directory != filepath.Join(binding.Root, st.Relative) {
		return fail(e)
	}
	root, e := binding.open(ctx, directory, initialize, FencedFormat)
	if e != nil {
		return fail(e)
	}
	check := func(ctx context.Context) error {
		if e := a.checkPath(ctx); e != nil {
			return e
		}
		return binding.checkHandle(ctx, directory, root, FencedFormat)
	}
	return root, check, func() { root.Close(); a.close() }, nil
}

// openMoveRoot accepts only a held, owner-private volume root. Its observed
// current mount cannot silently switch to an underlying filesystem.
func openMoveRoot(ctx context.Context, path string, expected diskIdentity) (*os.Root, Observation, error) {
	var zero Observation
	if e := ctx.Err(); e != nil {
		return nil, zero, e
	}
	r, e := localfs.OpenRoot(path)
	if e != nil {
		return nil, zero, errors.Join(ErrUnavailable, e)
	}
	f, e := r.Open(".")
	if e != nil {
		r.Close()
		return nil, zero, e
	}
	defer f.Close()
	o, e := observe(f)
	var stat unix.Stat_t
	if e != nil || o.ReadOnly || identity(o) != expected || unix.Fstat(int(f.Fd()), &stat) != nil ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 {
		r.Close()
		return nil, zero, ErrUnavailable
	}
	return r, o, nil
}

func newMarker(format, node string, epoch uint64) ([]byte, error) {
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	return json.Marshal(marker{Format: format, Scope: node, Epoch: epoch, Nonce: hex.EncodeToString(nonce[:])})
}
