package filekit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"syscall"

	"github.com/restic/chunker"
)

type countedReader struct {
	r     io.Reader
	count *int64
}

func (r countedReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	*r.count += int64(n)
	return n, e
}

// Backup streams a stable regular file directly into the destination object
// store. No plaintext temporary file or second source repository is created.
// Previous is an authenticated per-file descriptor, never a global index.
func (s *Store) Backup(ctx context.Context, source string, opt BackupOptions) (Stats, error) {
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return Stats{}, err
	}
	defer unlock()
	s.Stats = Stats{}
	if opt.File == "" {
		opt.File = randomID()
	}
	if !validID(opt.File) || len(opt.Names) == 0 || len(opt.Names) > 256 {
		return s.Stats, ErrInvalid
	}
	names := map[string]bool{}
	for _, n := range opt.Names {
		if !safeName(n) || names[n] {
			return s.Stats, ErrInvalid
		}
		names[n] = true
	}
	for _, n := range opt.Names {
		for p := path.Dir(n); p != "."; p = path.Dir(p) {
			if names[p] {
				return s.Stats, ErrInvalid
			}
		}
	}
	reuse := map[string]Block{}
	if opt.Previous != "" {
		_, prev, e := s.LoadVersion(opt.Previous)
		if e != nil {
			return s.Stats, e
		}
		if prev.File != opt.File {
			return s.Stats, ErrInvalid
		}
		for _, b := range prev.Blocks {
			reuse[b.Hash] = b
		}
	}
	fd, err := syscall.Open(source, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return s.Stats, err
	}
	f := os.NewFile(uintptr(fd), source)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return s.Stats, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxFileBytes {
		return s.Stats, ErrInvalid
	}
	meta, err := captureMetadata(f)
	if err != nil {
		return s.Stats, err
	}
	d := Descriptor{Format: Format, Domain: s.Owner.Domain, File: opt.File, Names: append([]string(nil), opt.Names...), Metadata: meta}
	h := sha256.New()
	input := io.TeeReader(countedReader{contextReader{ctx, f}, &s.Stats.SourceBytes}, h)
	c := chunker.New(input, chunker.Pol(0x3da3358b4dc173), chunker.WithBoundaries(256<<10, MaxChunk), chunker.WithAverageBits(20))
	buf := make([]byte, MaxChunk)
	pack := make([]byte, 0, MaxObject)
	pending := map[string]Block{}
	positions := map[string][]int{}
	existing := map[string]bool{}
	flush := func() error {
		if len(pack) == 0 {
			return nil
		}
		ref, e := s.putObject(pack, false)
		if e != nil {
			return e
		}
		for hash, b := range pending {
			b.Object = ref
			reuse[hash] = b
			for _, i := range positions[hash] {
				d.Blocks[i] = b
			}
		}
		pack = pack[:0]
		clear(pending)
		clear(positions)
		return nil
	}
	for {
		chunk, e := c.Next(buf)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return s.Stats, e
		}
		if len(d.Blocks) >= MaxBlocks || d.Size+int64(len(chunk.Data)) > MaxFileBytes {
			return s.Stats, ErrInvalid
		}
		hash := digest(chunk.Data)
		d.Size += int64(len(chunk.Data))
		index := len(d.Blocks)
		if b, ok := reuse[hash]; ok {
			if b.Bytes != len(chunk.Data) {
				return s.Stats, ErrInvalid
			}
			if !existing[b.Object.ID] {
				st, e := s.root.Stat(objectPath(b.Object.ID))
				if e != nil {
					return s.Stats, e
				}
				if !st.Mode().IsRegular() || st.Size() != int64(b.Object.Bytes) {
					return s.Stats, ErrInvalid
				}
				existing[b.Object.ID] = true
			}
			d.Blocks = append(d.Blocks, b)
			continue
		}
		if b, ok := pending[hash]; ok {
			d.Blocks = append(d.Blocks, b)
			positions[hash] = append(positions[hash], index)
			continue
		}
		ciphertext, e := s.Owner.seal(opt.File, "chunk/"+hash, chunk.Data)
		if e != nil {
			return s.Stats, e
		}
		if len(pack)+len(ciphertext) > MaxObject {
			if e = flush(); e != nil {
				return s.Stats, e
			}
		}
		b := Block{Hash: hash, Bytes: len(chunk.Data), Offset: len(pack), CipherBytes: len(ciphertext)}
		pack = append(pack, ciphertext...)
		pending[hash] = b
		positions[hash] = []int{index}
		d.Blocks = append(d.Blocks, b)
	}
	if err = flush(); err != nil {
		return s.Stats, err
	}
	d.SHA256 = hex.EncodeToString(h.Sum(nil))
	after, err := f.Stat()
	if err != nil {
		return s.Stats, err
	}
	afterMeta, err := captureMetadata(f)
	if err != nil {
		return s.Stats, err
	}
	if after.Size() != st.Size() || after.Size() != d.Size || !sameMetadata(meta, afterMeta) {
		return s.Stats, errors.New("source changed during capture")
	}
	version, err := s.Owner.version(d)
	if err != nil {
		return s.Stats, err
	}
	s.Stats.Version = version
	s.Stats.File = opt.File
	s.Stats.Blocks = len(d.Blocks)
	s.Stats.PeakBufferBytes = MaxChunk + MaxObject + 2*MaxDescriptor
	if _, _, e := s.LoadVersion(version); e == nil {
		return s.Stats, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return s.Stats, e
	}
	e, err := s.sealDescriptor(d)
	if err != nil {
		return s.Stats, err
	}
	if err = s.writeEnvelope("versions/"+version+".json", e); err != nil {
		return s.Stats, err
	}
	return s.Stats, nil
}
