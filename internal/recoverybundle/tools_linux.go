package recoverybundle

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
)

type toolManifest struct {
	Format        string            `json:"format"`
	Revision      string            `json:"revision"`
	SourceDigest  string            `json:"sourceDigest"`
	Source        map[string]string `json:"source"`
	GoVersion     string            `json:"goVersion"`
	GoOS          string            `json:"goos"`
	CGO           bool              `json:"cgo"`
	Architectures []string          `json:"architectures"`
	Files         map[string]File   `json:"files"`
}

type tools struct {
	root     *os.Root
	raw      []byte
	manifest toolManifest
	digest   string
}

func regular(root *os.Root, name string, max int64, private bool) (*os.File, error) {
	f, e := localfs.OpenFile(root, name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max || private && st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, ErrInvalid
	}
	return f, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}

func readSmall(ctx context.Context, root *os.Root, name string, max int, private bool) ([]byte, error) {
	f, e := regular(root, name, int64(max), private)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(contextReader{ctx, f}, int64(max)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > max {
		return nil, ErrCapacity
	}
	return raw, nil
}

func validateTools(raw []byte, expected, revision string) (toolManifest, error) {
	var m toolManifest
	if !storage.ID(expected) || storage.Hash(raw) != expected || document(raw, &m, MaxManifestBytes) != nil || m.Format != "outpost-distribution-1" || m.Revision != revision || !revisionPattern.MatchString(m.Revision) || m.GoOS != "linux" || m.CGO || !goVersionPattern.MatchString(m.GoVersion) || !storage.ID(m.SourceDigest) || len(m.Source) < 1 || len(m.Source) > 4096 || len(m.Architectures) < 1 || len(m.Architectures) > 2 {
		return m, ErrInvalid
	}
	for name, digest := range m.Source {
		if !sourceNamePattern.MatchString(name) || strings.HasPrefix(name, "/") || !storage.ID(digest) {
			return m, ErrInvalid
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return m, ErrInvalid
			}
		}
	}
	canonical, _ := json.Marshal(m.Source)
	if storage.Hash(canonical) != m.SourceDigest {
		return m, ErrInvalid
	}
	if strings.HasPrefix(m.Revision, "dev-") && m.Revision != "dev-"+m.SourceDigest {
		return m, ErrInvalid
	}
	allowed := map[string]bool{"Dockerfile": true, "compose.yaml": true, ".dockerignore": true, "licenses/LICENSE": true, "licenses/THIRD_PARTY_NOTICES.md": true, "licenses/GO_LICENSE": true}
	seen := map[string]bool{}
	for _, arch := range m.Architectures {
		if (arch != "amd64" && arch != "arm64") || seen[arch] {
			return m, ErrInvalid
		}
		seen[arch] = true
		for _, name := range []string{"linux_" + arch + "/outpost", "linux_" + arch + "/outpost-kit", "outpost-linux-" + arch + ".tar.gz"} {
			allowed[name] = true
		}
	}
	if len(m.Files) != len(allowed) {
		return m, ErrInvalid
	}
	for name, ref := range m.Files {
		if !allowed[name] || ref.Bytes < 1 || ref.Bytes > MaxToolBytes || !storage.ID(ref.SHA256) {
			return m, ErrInvalid
		}
	}
	return m, nil
}

func openTools(ctx context.Context, directory, expected, revision string) (*tools, error) {
	root, e := localfs.OpenRoot(directory)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*tools, error) { root.Close(); return nil, e }
	raw, e := readSmall(ctx, root, "manifest.json", MaxManifestBytes, false)
	if e != nil {
		return fail(e)
	}
	m, e := validateTools(raw, expected, revision)
	if e != nil {
		return fail(e)
	}
	for _, arch := range m.Architectures {
		name := "outpost-linux-" + arch + ".tar.gz"
		f, e := regular(root, name, MaxToolBytes, false)
		if e != nil {
			return fail(e)
		}
		e = verifyToolArchive(ctx, f, arch, m)
		e = errors.Join(e, f.Close())
		if e != nil {
			return fail(e)
		}
	}
	return &tools{root: root, raw: raw, manifest: m, digest: expected}, nil
}

// verifyToolArchive follows the selected distribution verifier's contract:
// exact files/checksums, Linux ELF64 architecture, and no dynamic interpreter.
// It never extracts or executes a supplied binary.
func verifyToolArchive(ctx context.Context, input io.Reader, arch string, m toolManifest) (err error) {
	defer func() {
		if e := ctx.Err(); e != nil {
			err = e
		}
	}()
	ref, ok := m.Files["outpost-linux-"+arch+".tar.gz"]
	if !ok {
		return ErrInvalid
	}
	compressed := sha256.New()
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: ref.Bytes + 1}
	buffered := bufio.NewReader(io.TeeReader(limited, compressed))
	z, e := gzip.NewReader(buffered)
	if e != nil {
		return ErrInvalid
	}
	defer z.Close()
	z.Multistream(false)
	t := tar.NewReader(z)
	seen := map[string]bool{}
	var expanded int64
	for {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrInvalid
		}
		name := h.Name
		key := name
		mode := int64(0644)
		isBinary := name == "outpost" || name == "outpost-kit"
		if isBinary {
			key = "linux_" + arch + "/" + name
			mode = 0755
		} else if name != "licenses/LICENSE" && name != "licenses/THIRD_PARTY_NOTICES.md" && name != "licenses/GO_LICENSE" {
			return ErrInvalid
		}
		item, ok := m.Files[key]
		if !ok || seen[name] || h.Typeflag != tar.TypeReg || h.Size != item.Bytes || h.Mode != mode || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Linkname != "" || h.ModTime.Unix() != 0 || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 {
			return ErrInvalid
		}
		seen[name] = true
		expanded += h.Size
		if expanded > 128<<20 {
			return ErrCapacity
		}
		hash := sha256.New()
		reader := contextReader{ctx, t}
		if isBinary {
			if e := copyELF(hash, reader, h.Size, arch); e != nil {
				return e
			}
		} else if n, e := io.Copy(hash, reader); e != nil || n != h.Size {
			return ErrInvalid
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
			return ErrInvalid
		}
	}
	if len(seen) != 5 {
		return ErrInvalid
	}
	// Python's USTAR output pads its record to a fixed block. Only bounded zero
	// padding may follow the tar terminator; consume it to verify gzip's CRC.
	padding, e := io.ReadAll(io.LimitReader(contextReader{ctx, z}, 10241))
	if e != nil || len(padding) > 10240 || !bytes.Equal(padding, make([]byte, len(padding))) {
		return ErrInvalid
	}
	if e = z.Close(); e != nil {
		return ErrInvalid
	}
	if _, e = buffered.ReadByte(); e != io.EOF {
		return ErrInvalid
	}
	if limited.N != 1 || hex.EncodeToString(compressed.Sum(nil)) != ref.SHA256 {
		return ErrInvalid
	}
	return nil
}

func copyELF(out io.Writer, in io.Reader, size int64, arch string) error {
	header := make([]byte, 64)
	if _, e := io.ReadFull(in, header); e != nil {
		return ErrInvalid
	}
	machine := uint16(62)
	if arch == "arm64" {
		machine = 183
	}
	if !bytes.Equal(header[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) || binary.LittleEndian.Uint16(header[18:20]) != machine {
		return ErrInvalid
	}
	offset := binary.LittleEndian.Uint64(header[32:40])
	width := binary.LittleEndian.Uint16(header[54:56])
	count := binary.LittleEndian.Uint16(header[56:58])
	if size < 64 || offset < 64 || offset > uint64(size) || width != 56 || count < 1 || count > 128 || uint64(width)*uint64(count) > uint64(size)-offset {
		return ErrInvalid
	}
	if _, e := out.Write(header); e != nil {
		return e
	}
	if _, e := io.CopyN(out, in, int64(offset)-64); e != nil {
		return ErrInvalid
	}
	programs := make([]byte, int(width)*int(count))
	if _, e := io.ReadFull(in, programs); e != nil {
		return ErrInvalid
	}
	for i := 0; i < int(count); i++ {
		if binary.LittleEndian.Uint32(programs[i*int(width):]) == 3 {
			return ErrInvalid
		}
	}
	if _, e := out.Write(programs); e != nil {
		return e
	}
	remaining := size - int64(offset) - int64(len(programs))
	if _, e := io.CopyN(out, in, remaining); e != nil {
		return ErrInvalid
	}
	var extra [1]byte
	if n, e := in.Read(extra[:]); n != 0 || e != io.EOF {
		return ErrInvalid
	}
	return nil
}
