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
	"golang.org/x/sys/unix"
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
	fd, err := syscall.Open(source, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Stats{}, err
	}
	f := os.NewFile(uintptr(fd), source)
	defer f.Close()
	return s.BackupFile(ctx, f, opt)
}

// BackupFile reads a caller-owned regular file descriptor from offset zero.
// Source scanners must open it through a root-confined, no-symlink path and
// establish complete hardlink aliases before passing the approved names.
func (s *Store) BackupFile(ctx context.Context, f *os.File, opt BackupOptions) (Stats, error) {
	if f == nil {
		return Stats{}, ErrInvalid
	}
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return Stats{}, err
	}
	defer unlock()
	s.Stats = Stats{}
	if opt.Progress != "" && (!validID(opt.Progress) || !validID(opt.File) || s.backend == nil) {
		return s.Stats, ErrInvalid
	}
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
		_, prev, e := s.LoadVersionContext(ctx, opt.Previous)
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
	st, err := f.Stat()
	if err != nil {
		return s.Stats, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxFileBytes {
		return s.Stats, ErrInvalid
	}
	if opt.Expected != nil {
		var observed unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &observed); err != nil {
			return s.Stats, err
		}
		if identity(observed) != *opt.Expected {
			return s.Stats, ErrInvalid
		}
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return s.Stats, err
	}
	meta, err := captureMetadata(f)
	if err != nil {
		return s.Stats, err
	}
	var progress *captureProgress
	if opt.Progress != "" {
		var observed unix.Stat_t
		if err = unix.Fstat(int(f.Fd()), &observed); err != nil {
			return s.Stats, err
		}
		var accepted map[string]Block
		progress, accepted, err = s.openProgress(ctx, opt, identity(observed), meta)
		if err != nil {
			return s.Stats, err
		}
		defer progress.file.Close()
		for hash, block := range accepted {
			reuse[hash] = block
		}
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
		ref, e := s.putObjectContext(ctx, pack, false)
		if e != nil {
			return e
		}
		checkpoint := make([]Block, 0, len(pending))
		for hash, b := range pending {
			b.Object = ref
			reuse[hash] = b
			checkpoint = append(checkpoint, b)
			for _, i := range positions[hash] {
				d.Blocks[i] = b
			}
		}
		if progress != nil {
			if e = progress.append(ctx, checkpoint); e != nil {
				return e
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
				if e := s.checkObjectContext(ctx, b.Object); e != nil {
					return s.Stats, e
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
	if !sameInodeSnapshot(st, after) || after.Size() != d.Size || !sameMetadata(meta, afterMeta) {
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
	if _, _, e := s.LoadVersionContext(ctx, version); e == nil {
		return s.Stats, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return s.Stats, e
	}
	e, err := s.sealDescriptorContext(ctx, d)
	if err != nil {
		return s.Stats, err
	}
	if err = s.writeEnvelope("versions/"+version+".json", e); err != nil {
		return s.Stats, err
	}
	return s.Stats, nil
}
