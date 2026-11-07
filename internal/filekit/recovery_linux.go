package filekit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func dependencies(e Envelope, d Descriptor) (map[string]Object, error) {
	objects := map[string]Object{}
	add := func(ref Object) error {
		if old, ok := objects[ref.ID]; ok && old != ref {
			return ErrInvalid
		}
		objects[ref.ID] = ref
		return nil
	}
	for _, p := range e.Parts {
		if err := add(p); err != nil {
			return nil, err
		}
	}
	for _, b := range d.Blocks {
		if err := add(b.Object); err != nil {
			return nil, err
		}
	}
	return objects, nil
}

// Export copies the selected kit BEFORE loss of any shared state. Its payload
// files are separate inodes, not links into the original object store.
func (s *Store) Export(ctx context.Context, version, dest string) error {
	unlock, err := s.lock(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()
	if !filepath.IsAbs(dest) || filepath.Clean(dest) != dest {
		return ErrInvalid
	}
	sourceRoot, err := filepath.EvalSymlinks(s.root.Name())
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dest))
	if err != nil {
		return err
	}
	dest = filepath.Join(parent, filepath.Base(dest))
	rel, err := filepath.Rel(sourceRoot, dest)
	if err != nil || rel == "." || !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return ErrInvalid
	}
	e, d, err := s.LoadVersion(version)
	if err != nil {
		return err
	}
	refs, err := dependencies(e, d)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dest, 0700); err != nil {
		return err
	}
	kit, err := OpenStore(dest, s.Owner, true)
	if err != nil {
		return err
	}
	defer kit.Close()
	for _, ref := range refs {
		if err = ctx.Err(); err != nil {
			return err
		}
		b, err := s.readObject(ref)
		if err != nil {
			return err
		}
		if _, err = kit.putObject(b, refIsMetadata(e, ref.ID)); err != nil {
			return err
		}
	}
	if err = kit.syncDir("objects"); err != nil {
		return err
	}
	if err = kit.writeEnvelope("kit.json", e); err != nil {
		return err
	}
	// The recovery entrypoint uses only kit.json and its listed objects.
	return kit.syncDir(".")
}
func refIsMetadata(e Envelope, id string) bool {
	for _, p := range e.Parts {
		if p.ID == id {
			return true
		}
	}
	return false
}

// ReadTo authenticates every complete object, chunk and ordered plaintext
// stream. Callers must not publish the sink until this method returns success.
func (s *Store) readTo(ctx context.Context, d Descriptor, w io.Writer) error {
	h := sha256.New()
	sink := io.MultiWriter(w, h)
	var total int64
	lastID := ""
	var pack []byte
	for _, b := range d.Blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if b.Object.ID != lastID {
			var err error
			pack, err = s.readObject(b.Object)
			if err != nil {
				return err
			}
			lastID = b.Object.ID
		}
		if len(pack) != b.Object.Bytes {
			return ErrInvalid
		}
		plain, err := s.Owner.open(d.File, "chunk/"+b.Hash, pack[b.Offset:b.Offset+b.CipherBytes])
		if err != nil {
			return err
		}
		if len(plain) != b.Bytes || digest(plain) != b.Hash {
			return ErrInvalid
		}
		n, err := sink.Write(plain)
		if err != nil {
			return err
		}
		if n != len(plain) {
			return io.ErrShortWrite
		}
		total += int64(n)
	}
	if total != d.Size || hex.EncodeToString(h.Sum(nil)) != d.SHA256 {
		return ErrInvalid
	}
	return nil
}

// Restore publishes a NEW directory atomically only after bytes, all metadata
// and hard-link aliases are verified. An error never publishes a partial file.
// The caller supplies the expected opaque version from its trusted receipt.
func (s *Store) Restore(ctx context.Context, version, dest string) (Descriptor, error) {
	_, d, err := s.load("kit.json", version)
	if err != nil {
		return d, err
	}
	return s.restoreDescriptor(ctx, d, dest)
}

// VerifyKit authenticates and decrypts an independent kit without publishing
// restored files or requiring permission to apply its recorded numeric IDs.
// It proves readable content/metadata, not successful attribute restoration.
func (s *Store) VerifyKit(ctx context.Context, version string) (Descriptor, error) {
	_, d, e := s.load("kit.json", version)
	if e != nil {
		return d, e
	}
	return d, s.verifyDescriptor(ctx, d)
}
func (s *Store) VerifyVersion(ctx context.Context, version string) (Descriptor, error) {
	unlock, e := s.lock(ctx, false)
	if e != nil {
		return Descriptor{}, e
	}
	defer unlock()
	_, d, e := s.LoadVersion(version)
	if e != nil {
		return d, e
	}
	return d, s.verifyDescriptor(ctx, d)
}
func (s *Store) verifyDescriptor(ctx context.Context, d Descriptor) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := validateDescriptor(d); e != nil {
		return e
	}
	if d.Kind != "" {
		return nil
	}
	return s.readTo(ctx, d, io.Discard)
}

// RestoreVersion is a convenience for a healthy store, not the independent
// recovery proof. A shared process lock protects it from maintenance/GC.
func (s *Store) RestoreVersion(ctx context.Context, version, dest string) (Descriptor, error) {
	unlock, err := s.lock(ctx, false)
	if err != nil {
		return Descriptor{}, err
	}
	defer unlock()
	_, d, err := s.LoadVersion(version)
	if err != nil {
		return d, err
	}
	return s.restoreDescriptor(ctx, d, dest)
}

func (s *Store) restoreDescriptor(ctx context.Context, d Descriptor, dest string) (Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return d, err
	}
	if !filepath.IsAbs(dest) || filepath.Clean(dest) != dest || path.Base(dest) == "/" {
		return d, ErrInvalid
	}
	parent, err := os.OpenRoot(path.Dir(dest))
	if err != nil {
		return d, err
	}
	defer parent.Close()
	name := path.Base(dest)
	if _, err = parent.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = os.ErrExist
		}
		return d, err
	}
	tmp := ".outpost-restore-" + randomID()
	if err = parent.Mkdir(tmp, 0700); err != nil {
		return d, err
	}
	finished := false
	defer func() {
		if !finished {
			_ = parent.RemoveAll(tmp)
		}
	}()
	out, err := parent.OpenRoot(tmp)
	if err != nil {
		return d, err
	}
	defer out.Close()
	for _, n := range d.Names {
		if err = out.MkdirAll(path.Dir(n), 0700); err != nil {
			return d, err
		}
	}
	if d.Kind != "" {
		err = restoreSpecial(out, d)
	} else {
		err = s.restoreRegular(ctx, out, d)
	}
	if err != nil {
		return d, err
	}
	// Persist all created directory entries from leaves to the staging root.
	for _, n := range d.Names {
		for dir := path.Dir(n); ; dir = path.Dir(dir) {
			f, e := out.Open(dir)
			if e != nil {
				return d, e
			}
			e = f.Sync()
			f.Close()
			if e != nil {
				return d, e
			}
			if dir == "." {
				break
			}
		}
	}
	if err = s.checkpoint("restore-verified"); err != nil {
		return d, err
	}
	if _, err = parent.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = os.ErrExist
		}
		return d, err
	}
	p, err := parent.Open(".")
	if err != nil {
		return d, err
	}
	defer p.Close()
	if err = unix.Renameat2(int(p.Fd()), tmp, int(p.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return d, err
	}
	finished = true
	if err = p.Sync(); err != nil {
		return d, err
	}
	return d, nil
}
func (s *Store) restoreRegular(ctx context.Context, out *os.Root, d Descriptor) error {
	f, err := out.OpenFile(d.Names[0], os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	err = s.readTo(ctx, d, f)
	if err == nil {
		err = applyMetadata(f, d.Metadata)
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	for _, n := range d.Names[1:] {
		if err = out.Link(d.Names[0], n); err != nil {
			return err
		}
	}
	return nil
}
