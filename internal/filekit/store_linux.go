package filekit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"time"
)

func OpenStore(dir string, owner Owner, create bool) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, ErrInvalid
	}
	if err := owner.validate(); err != nil {
		return nil, err
	}
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{root: r, Owner: owner}
	if create {
		if err = s.initialize(); err != nil {
			r.Close()
			return nil, err
		}
		for _, name := range []string{"objects", "versions", ".txn"} {
			if err = r.MkdirAll(name, 0700); err != nil {
				r.Close()
				return nil, err
			}
		}
		if err = s.syncDir("."); err != nil {
			r.Close()
			return nil, err
		}
	}
	return s, nil
}
func (s *Store) Close() error { return s.root.Close() }

type storeMarker struct {
	Format string `json:"format"`
	Domain string `json:"domain"`
}

func (s *Store) authorize() error {
	b, err := s.readFile("store.json", 4096)
	if err != nil {
		return err
	}
	var m storeMarker
	if err = decode(b, &m); err != nil {
		return err
	}
	if m.Format != Format || m.Domain != s.Owner.Domain {
		return ErrInvalid
	}
	return nil
}
func (s *Store) initialize() error {
	if err := s.authorize(); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := s.root.Open(".")
	if err != nil {
		return err
	}
	entries, e := f.ReadDir(1)
	f.Close()
	if len(entries) != 0 || e != io.EOF {
		return errors.New("refuse unowned nonempty destination")
	}
	b, err := json.Marshal(storeMarker{Format, s.Owner.Domain})
	if err != nil {
		return err
	}
	f, err = s.root.OpenFile("store.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return s.syncDir(".")
}

func (s *Store) lock(ctx context.Context, exclusive bool) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.authorize(); err != nil {
		return nil, err
	}
	f, err := s.root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	for {
		err = syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func objectPath(id string) string { return "objects/" + id[:2] + "/" + id }
func (s *Store) syncDir(name string) error {
	f, err := s.root.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *Store) readFile(name string, limit int) ([]byte, error) {
	// Untrusted kit entries must not block open on a FIFO or follow a link.
	f, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > int64(limit) {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != st.Size() {
		return nil, ErrInvalid
	}
	return b, nil
}
func (s *Store) readObject(ref Object) ([]byte, error) {
	if !validID(ref.ID) || ref.Bytes <= 0 || ref.Bytes > MaxObject {
		return nil, ErrInvalid
	}
	b, err := s.readFile(objectPath(ref.ID), ref.Bytes)
	if err != nil {
		return nil, err
	}
	s.Stats.VerifiedReadBytes += int64(len(b))
	if len(b) != ref.Bytes || digest(b) != ref.ID {
		return nil, fmt.Errorf("object integrity failure: %w", ErrInvalid)
	}
	return b, nil
}

func (s *Store) putObject(b []byte, metadata bool) (Object, error) {
	ref := Object{ID: digest(b), Bytes: len(b)}
	if len(b) == 0 || len(b) > MaxObject {
		return ref, ErrInvalid
	}
	name := objectPath(ref.ID)
	if existing, err := s.readFile(name, MaxObject); err == nil {
		if !bytes.Equal(existing, b) {
			return ref, ErrInvalid
		}
		return ref, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ref, err
	}
	dir := path.Dir(name)
	if err := s.root.MkdirAll(dir, 0700); err != nil {
		return ref, err
	}
	// Persist newly created fanout directories before publishing references.
	if err := s.syncDir("objects"); err != nil {
		return ref, err
	}
	tmp := ".txn/" + randomID()
	f, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ref, err
	}
	defer s.root.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = s.checkpoint("object-written")
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = s.checkpoint("object-synced")
	}
	closeErr := f.Close()
	if err != nil {
		return ref, err
	}
	if closeErr != nil {
		return ref, closeErr
	}
	if err = s.root.Link(tmp, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return ref, err
		}
		existing, e := s.readObject(ref)
		if e != nil || !bytes.Equal(existing, b) {
			return ref, ErrInvalid
		}
		return ref, nil
	}
	if err = s.checkpoint("object-linked"); err != nil {
		return ref, err
	}
	if err = s.syncDir(dir); err != nil {
		return ref, err
	}
	if err = s.checkpoint("object-durable"); err != nil {
		return ref, err
	}
	s.Stats.NewObjects++
	if metadata {
		s.Stats.NewMetadataBytes += int64(len(b))
	} else {
		s.Stats.NewPayloadBytes += int64(len(b))
	}
	return ref, nil
}

func (s *Store) writeEnvelope(name string, e Envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > MaxRoot {
		return ErrInvalid
	}
	tmp := ".txn/" + randomID()
	f, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer s.root.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = s.checkpoint("descriptor-written")
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = s.checkpoint("descriptor-synced")
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = s.root.Rename(tmp, name); err != nil {
		return err
	}
	if err = s.checkpoint("descriptor-renamed"); err != nil {
		return err
	}
	if err = s.syncDir(path.Dir(name)); err != nil {
		return err
	}
	s.Stats.NewMetadataBytes += int64(len(b))
	return s.checkpoint("descriptor-durable")
}

func (s *Store) sealDescriptor(d Descriptor) (Envelope, error) {
	v, err := s.Owner.version(d)
	if err != nil {
		return Envelope{}, err
	}
	e := Envelope{Format: Format, Domain: d.Domain, File: d.File, Version: v}
	b, err := json.Marshal(d)
	if err != nil {
		return e, err
	}
	if len(b) > MaxDescriptor {
		return e, ErrInvalid
	}
	b, err = s.Owner.seal(d.File, "descriptor", b)
	if err != nil {
		return e, err
	}
	for len(b) > 0 {
		n := min(len(b), DescriptorPart)
		ref, err := s.putObject(b[:n], true)
		if err != nil {
			return e, err
		}
		e.Parts = append(e.Parts, ref)
		b = b[n:]
	}
	return s.Owner.sign(e)
}

func (s *Store) load(name, version string) (Envelope, Descriptor, error) {
	var e Envelope
	var d Descriptor
	if !validID(version) {
		return e, d, ErrInvalid
	}
	b, err := s.readFile(name, MaxRoot)
	if err != nil {
		return e, d, err
	}
	if err = decode(b, &e); err != nil {
		return e, d, err
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(canonical, b) {
		return e, d, ErrInvalid
	}
	if err = s.Owner.verifyEnvelope(e, version); err != nil {
		return e, d, err
	}
	var sealed []byte
	for _, p := range e.Parts {
		b, err = s.readObject(p)
		if err != nil {
			return e, d, err
		}
		sealed = append(sealed, b...)
	}
	b, err = s.Owner.open(e.File, "descriptor", sealed)
	if err != nil {
		return e, d, err
	}
	if len(b) > MaxDescriptor {
		return e, d, ErrInvalid
	}
	if err = decode(b, &d); err != nil {
		return e, d, err
	}
	if d.Domain != e.Domain || d.File != e.File {
		return e, d, ErrInvalid
	}
	canonical, err = json.Marshal(d)
	if err != nil || !bytes.Equal(canonical, b) {
		return e, d, ErrInvalid
	}
	v, err := s.Owner.version(d)
	if err != nil || v != version {
		return e, d, ErrInvalid
	}
	return e, d, nil
}

func (s *Store) LoadVersion(version string) (Envelope, Descriptor, error) {
	if !validID(version) {
		return Envelope{}, Descriptor{}, ErrInvalid
	}
	return s.load("versions/"+version+".json", version)
}

func ReadOwner(name string) (Owner, error) {
	var o Owner
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return o, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return o, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 4096 {
		return o, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return o, err
	}
	if err = decode(b, &o); err != nil {
		return o, err
	}
	return o, o.validate()
}
func WriteOwner(name string, o Owner) error {
	if err := o.validate(); err != nil {
		return err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	parent, err := os.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
