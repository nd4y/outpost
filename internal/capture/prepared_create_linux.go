package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/source"
)

// PreparedClaim is supplied by the native producer after it completes its own
// consistent export. Outpost measures the closed bytes; it does not infer or
// certify application consistency from the directory or create an export.
type PreparedClaim struct {
	Sequence      uint64 `json:"sequence"`
	SnapshotUnix  int64  `json:"snapshotUnix"`
	CompletedUnix int64  `json:"completedUnix"`
	Root          string `json:"root"`
}

func CreatePreparedExport(ctx context.Context, parent *os.Root, b PreparedTrust, c PreparedClaim, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if b.validate() != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), b.Producer) || c.Sequence == 0 || c.SnapshotUnix < 1 || c.CompletedUnix < c.SnapshotUnix || c.CompletedUnix > now.Unix() || !preparedName(c.Root, true) {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	root, e := localfs.OpenAt(parent, c.Root, false)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	plan, e := source.Scan(ctx, root, source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: b.Profile}}, Domains: map[string]bool{b.Profile: true}, EntryLimit: source.MaxEntries})
	if e != nil {
		return nil, e
	}
	if plan.Excluded != 0 || plan.SourceBytes > b.MaxBytes {
		return nil, ErrInvalid
	}
	m := PreparedExport{Format: PreparedExportFormat, Profile: b.Profile, Origin: b.Origin, Method: b.Method, Sequence: c.Sequence, SnapshotUnix: c.SnapshotUnix, CompletedUnix: c.CompletedUnix, Root: c.Root}
	dirs := map[string]bool{".": true}
	for _, entry := range plan.Entries {
		if len(entry.Names) != 1 {
			return nil, ErrInvalid
		}
		switch entry.Identity.Kind() {
		case "directory":
		case "regular":
			if entry.Identity.Links != 1 || entry.Identity.Size < 0 {
				return nil, ErrInvalid
			}
			name := entry.Names[0]
			m.Files = append(m.Files, PreparedFile{Name: name, Bytes: entry.Identity.Size})
			if len(m.Files) > b.MaxFiles {
				return nil, ErrInvalid
			}
			for d := path.Dir(name); d != "."; d = path.Dir(d) {
				dirs[d] = true
			}
		default:
			return nil, ErrInvalid
		}
	}
	if len(m.Files) == 0 {
		return nil, ErrInvalid
	}
	for _, entry := range plan.Entries {
		if entry.Identity.Kind() == "directory" && !dirs[entry.Names[0]] {
			return nil, ErrInvalid
		}
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	for index, file := range m.Files {
		digest, e := preparedDigest(ctx, root, file.Name, file.Bytes)
		if e != nil {
			return nil, e
		}
		m.Files[index].SHA256 = digest
	}
	if e = plan.Recheck(ctx, root); e != nil {
		return nil, e
	}
	return SignPreparedExport(m, b, key, now)
}

func preparedDigest(ctx context.Context, root *os.Root, name string, size int64) (string, error) {
	if size < 0 || size > 1<<60 {
		return "", ErrInvalid
	}
	f, e := localfs.OpenFile(root, name, os.O_RDONLY, 0)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	n, e := io.CopyBuffer(h, &preparedReader{ctx: ctx, r: io.LimitReader(f, size+1)}, make([]byte, 64<<10))
	closeErr := f.Close()
	if e != nil {
		return "", e
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n != size {
		return "", ErrInvalid
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
