package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/source"
	"github.com/nd4y/outpost/internal/storage"
)

const PreparedExportFormat = "outpost-prepared-export-1"
const MaxPreparedExport = 1 << 20
const MaxPreparedFiles = 4096

// PreparedExport is private producer attestation, not a network capability or
// proof that arbitrary files are application-consistent. The configured native
// producer owns export consistency and publishes an immutable view before it
// signs this closed inventory. Consumers verify identity and bytes separately.
type PreparedExport struct {
	Format        string         `json:"format"`
	Profile       string         `json:"profile"`
	Origin        string         `json:"origin"`
	Method        string         `json:"method"`
	Sequence      uint64         `json:"sequence"`
	SnapshotUnix  int64          `json:"snapshotUnix"`
	CompletedUnix int64          `json:"completedUnix"`
	Root          string         `json:"root"`
	Files         []PreparedFile `json:"files"`
	SnapshotID    string         `json:"snapshotId,omitempty"`
	Signature     []byte         `json:"signature,omitempty"`
}
type PreparedFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// PreparedTrust is a local enrollment boundary. No field selects a command,
// executable, network endpoint or producer-owned cleanup action.
type PreparedTrust struct {
	Profile        string            `json:"profile"`
	Origin         string            `json:"origin"`
	Method         string            `json:"method"`
	Producer       ed25519.PublicKey `json:"producer"`
	MaxBytes       int64             `json:"maxBytes"`
	MaxFiles       int               `json:"maxFiles"`
	SnapshotOrigin string            `json:"snapshotOrigin,omitempty"`
}

func preparedName(s string, root bool) bool {
	if len(s) == 0 || len(s) > 4095 || !utf8.ValidString(s) || path.IsAbs(s) || path.Clean(s) != s || s == ".." || strings.HasPrefix(s, "../") || strings.ContainsAny(s, "\\\x00\r\n") || len(strings.Split(s, "/")) > 128 {
		return false
	}
	return root || s != "."
}
func (b PreparedTrust) validate() error {
	if !storage.ID(b.Profile) || !storage.ID(b.Origin) || len(b.Producer) != ed25519.PublicKeySize || b.MaxBytes < 1 || b.MaxBytes > 1<<60 || b.MaxFiles < 1 || b.MaxFiles > MaxPreparedFiles || len(b.Method) < 1 || len(b.Method) > 64 {
		return ErrInvalid
	}
	for _, c := range b.Method {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return ErrInvalid
		}
	}
	if b.SnapshotOrigin != "" && (b.Method != BtrfsSnapshotMethod || !btrfsUUID(b.SnapshotOrigin)) {
		return ErrInvalid
	}
	return nil
}

func (b PreparedTrust) Validate() error { return b.validate() }

func (b PreparedTrust) Consistency() string {
	if b.SnapshotOrigin != "" {
		return "filesystem"
	}
	return "application"
}

func (m PreparedExport) validate(b PreparedTrust, now time.Time) error {
	if b.validate() != nil || m.Format != PreparedExportFormat || m.Profile != b.Profile || m.Origin != b.Origin || m.Method != b.Method || m.Sequence == 0 || m.SnapshotUnix < 1 || m.CompletedUnix < m.SnapshotUnix || m.CompletedUnix > now.Unix() || !preparedName(m.Root, true) || len(m.Files) < 1 || len(m.Files) > b.MaxFiles {
		return ErrInvalid
	}
	if b.Consistency() == "filesystem" {
		if !btrfsUUID(m.SnapshotID) || m.SnapshotID == b.SnapshotOrigin {
			return ErrInvalid
		}
	} else if m.SnapshotID != "" {
		return ErrInvalid
	}
	var total int64
	previous := ""
	files := map[string]bool{}
	for _, f := range m.Files {
		if !preparedName(f.Name, false) || f.Name <= previous || f.Bytes < 0 || f.Bytes > b.MaxBytes-total || !storage.ID(f.SHA256) {
			return ErrInvalid
		}
		for parent := path.Dir(f.Name); parent != "."; parent = path.Dir(parent) {
			if files[parent] {
				return ErrInvalid
			}
		}
		files[f.Name] = true
		previous = f.Name
		total += f.Bytes
	}
	return nil
}

func SignPreparedExport(m PreparedExport, b PreparedTrust, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), b.Producer) || m.validate(b, now) != nil {
		return nil, ErrInvalid
	}
	m.Signature = nil
	raw, e := json.Marshal(m)
	if e != nil || len(raw) > MaxPreparedExport-128 {
		return nil, ErrInvalid
	}
	m.Signature = ed25519.Sign(key, append([]byte(PreparedExportFormat+"\x00"), raw...))
	raw, e = json.Marshal(m)
	if e != nil || len(raw) > MaxPreparedExport {
		return nil, ErrInvalid
	}
	return raw, nil
}
func VerifyPreparedExport(raw []byte, b PreparedTrust, now time.Time) (PreparedExport, error) {
	var m PreparedExport
	if storage.Decode(raw, &m, MaxPreparedExport) != nil || m.validate(b, now) != nil {
		return PreparedExport{}, ErrInvalid
	}
	canonical, _ := json.Marshal(m)
	if !bytes.Equal(raw, canonical) {
		return PreparedExport{}, ErrInvalid
	}
	sig := m.Signature
	m.Signature = nil
	unsigned, _ := json.Marshal(m)
	if !ed25519.Verify(b.Producer, append([]byte(PreparedExportFormat+"\x00"), unsigned...), sig) {
		return PreparedExport{}, ErrInvalid
	}
	m.Signature = sig
	return m, nil
}

// OpenPreparedExport checks the exact signed inventory within a held enrolled
// parent. It performs no writes, acquisition, native application commands or
// cleanup. The caller owns the returned root and must preserve/recheck plan
// identities through capture. A native producer must never mutate its export.
func OpenPreparedExport(ctx context.Context, parent *os.Root, raw []byte, b PreparedTrust, now time.Time) (*os.Root, source.Plan, error) {
	var empty source.Plan
	if e := ctx.Err(); e != nil {
		return nil, empty, e
	}
	m, e := VerifyPreparedExport(raw, b, now)
	if e != nil {
		return nil, empty, e
	}
	r, e := localfs.OpenAt(parent, m.Root, false)
	if e != nil {
		return nil, empty, e
	}
	accepted := false
	defer func() {
		if !accepted {
			r.Close()
		}
	}()
	if b.Consistency() == "filesystem" {
		proof, e := inspectBtrfsSnapshot(r)
		if e != nil || proof.id != m.SnapshotID || proof.parent != b.SnapshotOrigin || proof.created != m.SnapshotUnix {
			return nil, empty, ErrInvalid
		}
	}
	selection := source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: b.Profile}}, Domains: map[string]bool{b.Profile: true}, EntryLimit: source.MaxEntries}
	plan, e := source.Scan(ctx, r, selection)
	if e != nil {
		return nil, empty, e
	}
	files := map[string]PreparedFile{}
	dirs := map[string]bool{".": true}
	var total int64
	for _, f := range m.Files {
		files[f.Name] = f
		total += f.Bytes
		for d := path.Dir(f.Name); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	if plan.Excluded != 0 || plan.SourceBytes != total || total > b.MaxBytes {
		return nil, empty, ErrInvalid
	}
	seen := 0
	for _, entry := range plan.Entries {
		if e := ctx.Err(); e != nil {
			return nil, empty, e
		}
		if len(entry.Names) != 1 {
			return nil, empty, ErrInvalid
		}
		name := entry.Names[0]
		switch entry.Identity.Kind() {
		case "directory":
			if !dirs[name] {
				return nil, empty, ErrInvalid
			}
		case "regular":
			file, ok := files[name]
			if !ok || entry.Identity.Links != 1 || entry.Identity.Size != file.Bytes {
				return nil, empty, ErrInvalid
			}
			digest, e := preparedDigest(ctx, r, name, file.Bytes)
			if e != nil {
				return nil, empty, e
			}
			if digest != file.SHA256 {
				return nil, empty, ErrInvalid
			}
			seen++
		default:
			return nil, empty, ErrInvalid
		}
	}
	if seen != len(files) {
		return nil, empty, ErrInvalid
	}
	if e = plan.Recheck(ctx, r); e != nil {
		return nil, empty, e
	}
	accepted = true
	return r, plan, nil
}

type preparedReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *preparedReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
