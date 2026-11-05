// outpost-fixture creates synthetic, reproducible, incompressible G1 data.
// Its byte oracle is independent of the backup descriptor and encryption code.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const bufferSize = 4 << 20
const insertionBytes = int64(1 << 20)

// Independent seekable AES-CTR fixture stream; the seeds are public test data.
func fill(b []byte, offset int64, seed string) {
	key := sha256.Sum256([]byte("outpost-public-fixture/" + seed))
	block, _ := aes.NewCipher(key[:])
	iv := make([]byte, 16)
	binary.BigEndian.PutUint64(iv[8:], uint64(offset/16))
	stream := cipher.NewCTR(block, iv)
	if skip := int(offset % 16); skip > 0 {
		dummy := make([]byte, skip)
		stream.XORKeyStream(dummy, dummy)
	}
	clear(b)
	stream.XORKeyStream(b, b)
}
func overlay(b []byte, offset, start, length int64, seed string) {
	lo := max(offset, start)
	hi := min(offset+int64(len(b)), start+length)
	if hi > lo {
		fill(b[lo-offset:hi-offset], lo-start, seed)
	}
}
func baseData(b []byte, offset, size int64, phase string) {
	fill(b, offset, "baseline")
	if phase != "base" {
		overlay(b, offset, size/2, 8<<20, "contiguous-change")
	}
	if phase == "scattered" || phase == "inserted" {
		for i := int64(1); i <= 8; i++ {
			overlay(b, offset, size*i/9, 1<<20, fmt.Sprintf("scattered-%d", i))
		}
	}
}
func expected(b []byte, offset, size int64, phase string) {
	if phase != "inserted" {
		baseData(b, offset, size, phase)
		return
	}
	start := size - (64 << 20)
	end := offset + int64(len(b))
	if offset < start {
		n := min(end, start) - offset
		baseData(b[:n], offset, size, phase)
	}
	lo, hi := max(offset, start), min(end, start+insertionBytes)
	if hi > lo {
		fill(b[lo-offset:hi-offset], lo-start, "insertion")
	}
	if end > start+insertionBytes {
		lo = max(offset, start+insertionBytes)
		baseData(b[lo-offset:], lo-insertionBytes, size, phase)
	}
}
func stamp(phase string) time.Time {
	n := map[string]int64{"base": 0, "patched": 1, "scattered": 2, "inserted": 3}[phase]
	return time.Unix(1700000000+n, 123456789)
}
func acl() []byte {
	b := make([]byte, 44)
	binary.LittleEndian.PutUint32(b, 2)
	for i, e := range [][3]uint32{{1, 6, ^uint32(0)}, {2, 4, uint32(os.Getuid() + 1)}, {4, 4, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		p := b[4+i*8:]
		binary.LittleEndian.PutUint16(p, uint16(e[0]))
		binary.LittleEndian.PutUint16(p[2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(p[4:], e[2])
	}
	return b
}
func metadata(path, phase string) error {
	if e := os.Chmod(path, 0640); e != nil {
		return e
	}
	if e := syscall.Setxattr(path, "user.outpost-fixture", []byte("synthetic-private-attribute"), 0); e != nil {
		return e
	}
	if e := syscall.Setxattr(path, "system.posix_acl_access", acl(), 0); e != nil {
		return e
	}
	return os.Chtimes(path, stamp(phase), stamp(phase))
}
func attrs(path, phase string, st os.FileInfo) error {
	s := st.Sys().(*syscall.Stat_t)
	if st.Mode().Perm() != 0640 || st.ModTime().UnixNano() != stamp(phase).UnixNano() || s.Uid != uint32(os.Getuid()) || s.Gid != uint32(os.Getgid()) {
		return errors.New("metadata mismatch")
	}
	for key, want := range map[string][]byte{"user.outpost-fixture": []byte("synthetic-private-attribute"), "system.posix_acl_access": acl()} {
		got := make([]byte, 256)
		n, e := syscall.Getxattr(path, key, got)
		if e != nil {
			return e
		}
		if !bytes.Equal(got[:n], want) {
			return errors.New("xattr mismatch")
		}
	}
	return nil
}
func run() error {
	op := flag.String("op", "", "generate, mutate, verify")
	name := flag.String("file", "", "synthetic file path")
	phase := flag.String("phase", "base", "base, patched, scattered, inserted")
	size := flag.Int64("bytes", 100<<30, "baseline byte length")
	alias := flag.String("alias", "", "optional hard-link alias to verify")
	flag.Parse()
	if *size < 128<<20 || *size > 128<<30 {
		return errors.New("fixture size outside bounds")
	}
	if *phase != "base" && *phase != "patched" && *phase != "scattered" && *phase != "inserted" {
		return errors.New("unknown phase")
	}
	started := time.Now()
	buf := make([]byte, bufferSize)
	h := sha256.New()
	var count int64
	var compression float64
	switch *op {
	case "generate":
		if *phase != "base" {
			return errors.New("generate only creates baseline")
		}
		f, e := os.OpenFile(*name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		for offset := int64(0); offset < *size; offset += int64(len(buf)) {
			b := buf[:min(int64(len(buf)), *size-offset)]
			expected(b, offset, *size, "base")
			if offset == 0 {
				var compressed bytes.Buffer
				z, _ := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
				_, _ = z.Write(b)
				_ = z.Close()
				compression = float64(compressed.Len()) / float64(len(b))
				if compression < 0.99 {
					return errors.New("fixture compressible")
				}
			}
			n, e := f.Write(b)
			if e != nil {
				return e
			}
			if n != len(b) {
				return io.ErrShortWrite
			}
			h.Write(b)
			count += int64(n)
		}
		if e = metadata(*name, *phase); e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
	case "mutate":
		if *phase == "base" {
			return errors.New("mutation phase required")
		}
		f, e := os.OpenFile(*name, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			return e
		}
		if st.Size() != *size {
			return errors.New("unexpected pre-mutation length")
		}
		write := func(offset, length int64, seed string) error {
			for p := int64(0); p < length; p += int64(len(buf)) {
				b := buf[:min(int64(len(buf)), length-p)]
				fill(b, p, seed)
				n, e := f.WriteAt(b, offset+p)
				if e != nil {
					return e
				}
				if n != len(b) {
					return io.ErrShortWrite
				}
				count += int64(n)
			}
			return nil
		}
		if *phase == "patched" {
			e = write(*size/2, 8<<20, "contiguous-change")
		}
		if *phase == "scattered" {
			for i := int64(1); i <= 8; i++ {
				if e = write(*size*i/9, 1<<20, fmt.Sprintf("scattered-%d", i)); e != nil {
					break
				}
			}
		}
		if *phase == "inserted" {
			start := *size - (64 << 20)
			e = f.Truncate(*size + insertionBytes)
			if e != nil {
				return e
			}
			for end := *size; end > start; {
				n := min(int64(len(buf)), end-start)
				begin := end - n
				b := buf[:n]
				if _, e = f.ReadAt(b, begin); e != nil {
					return e
				}
				if _, e = f.WriteAt(b, begin+insertionBytes); e != nil {
					return e
				}
				count += n
				end = begin
			}
			e = write(start, insertionBytes, "insertion")
		}
		if e != nil {
			return e
		}
		if e = metadata(*name, *phase); e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
	case "verify":
		f, e := os.Open(*name)
		if e != nil {
			return e
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			return e
		}
		want := *size
		if *phase == "inserted" {
			want += insertionBytes
		}
		if st.Size() != want {
			return errors.New("length mismatch")
		}
		if e = attrs(*name, *phase, st); e != nil {
			return e
		}
		oracle := make([]byte, len(buf))
		for offset := int64(0); offset < want; offset += int64(len(buf)) {
			b := buf[:min(int64(len(buf)), want-offset)]
			if _, e = io.ReadFull(f, b); e != nil {
				return e
			}
			expected(oracle[:len(b)], offset, *size, *phase)
			if !bytes.Equal(b, oracle[:len(b)]) {
				return fmt.Errorf("byte oracle mismatch at %d", offset)
			}
			h.Write(b)
			count += int64(len(b))
		}
		if *alias != "" {
			other, e := os.Stat(*alias)
			if e != nil {
				return e
			}
			if !os.SameFile(st, other) {
				return errors.New("hard-link alias differs")
			}
		}
	default:
		return errors.New("unknown operation")
	}
	st, e := os.Stat(*name)
	if e != nil {
		return e
	}
	allocated := st.Sys().(*syscall.Stat_t).Blocks * 512
	if allocated < st.Size()*99/100 {
		return errors.New("fixture or output is sparse")
	}
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"operation": *op, "phase": *phase, "bytesProcessed": count, "fileBytes": st.Size(), "allocatedBytes": allocated, "sha256": hex.EncodeToString(h.Sum(nil)), "compressionRatio": compression, "elapsedSeconds": time.Since(started).Seconds(), "maxRSSKiB": usage.Maxrss, "attributesVerified": *op == "verify"})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
