// Package recoverybundle prepares owner-held recovery material and the exact
// selected offline tools. Packages contain plaintext recovery secrets and must
// never be placed in a replica or sent to a shared worker or external model.
package recoverybundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const Format = "outpost-owner-recovery-1"
const MaxPackageBytes int64 = 256 << 20
const MaxToolBytes int64 = 64 << 20
const MaxManifestBytes = 2 << 20

var ErrInvalid = errors.New("invalid owner recovery package")
var ErrConflict = errors.New("owner recovery package destination or identity conflict")
var ErrCapacity = errors.New("owner recovery package capacity exceeded")
var ErrDenied = errors.New("owner recovery package private boundary rejected")

var revisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|dev-[0-9a-f]{64})$`)
var sourceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
var goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)

type File struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Metadata struct {
	Format             string          `json:"format"`
	CreatedUnix        int64           `json:"createdUnix"`
	Domain             string          `json:"domain"`
	Repository         string          `json:"repository"`
	Epoch              uint64          `json:"epoch"`
	FileKitFormats     []string        `json:"fileKitFormats"`
	ToolRevision       string          `json:"toolRevision"`
	ToolManifestSHA256 string          `json:"toolManifestSHA256"`
	Architectures      []string        `json:"architectures"`
	CheckpointPresent  bool            `json:"checkpointPresent"`
	Files              map[string]File `json:"files"`
}

// Material is private, never a CLI result, report or log value. The caller must
// retain only RecoveryMaterial(), not any source signing key, in an archive.
type Material struct {
	Owner      filekit.Owner
	Trust      generation.Trust
	Checkpoint []byte
}

func (m Material) validate() error {
	owner, e := m.Owner.RecoveryMaterial()
	if e != nil || len(m.Owner.SigningKey) != 0 || owner.Domain != m.Trust.Domain || !storage.ID(m.Trust.Domain) || !storage.ID(m.Trust.Repository) || m.Trust.Epoch == 0 || len(m.Trust.Writer) != ed25519.PublicKeySize || len(m.Trust.Maintenance) != ed25519.PublicKeySize || bytes.Equal(m.Trust.Writer, m.Trust.Maintenance) {
		return ErrInvalid
	}
	if len(m.Checkpoint) != 0 {
		if _, e := capture.VerifyCheckpoint(m.Checkpoint, m.Trust); e != nil {
			return ErrInvalid
		}
	}
	return nil
}

type Receipt struct {
	Format             string   `json:"format"`
	SHA256             string   `json:"sha256"`
	Bytes              int64    `json:"bytes"`
	Domain             string   `json:"domain"`
	Repository         string   `json:"repository"`
	Epoch              uint64   `json:"epoch"`
	ToolRevision       string   `json:"toolRevision"`
	ToolManifestSHA256 string   `json:"toolManifestSHA256"`
	Architectures      []string `json:"architectures"`
	CheckpointPresent  bool     `json:"checkpointPresent"`
	Generation         string   `json:"generation,omitempty"`
	Sequence           uint64   `json:"sequence,omitempty"`
	VerifiedUnix       int64    `json:"verifiedUnix,omitempty"`
}

func receipt(meta Metadata, material Material) (Receipt, error) {
	out := Receipt{Format: Format, Domain: meta.Domain, Repository: meta.Repository, Epoch: meta.Epoch, ToolRevision: meta.ToolRevision, ToolManifestSHA256: meta.ToolManifestSHA256, Architectures: append([]string(nil), meta.Architectures...), CheckpointPresent: meta.CheckpointPresent}
	if meta.CheckpointPresent {
		c, e := capture.VerifyCheckpoint(material.Checkpoint, material.Trust)
		if e != nil {
			return Receipt{}, ErrInvalid
		}
		out.Generation, out.Sequence, out.VerifiedUnix = c.Generation, c.Sequence, c.Receipt.VerifiedAt
	}
	return out, nil
}

func names(files map[string]File) []string {
	out := make([]string, 0, len(files))
	for name := range files {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Distribution manifests are intentionally pretty-printed by the packager.
// Reject duplicate keys before typed decoding rather than interpreting the last
// occurrence differently from another independently retained verifier.
func document(raw []byte, out any, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return ErrInvalid
		}
		token, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				key, ok := k.(string)
				if e != nil || !ok || seen[key] || len(seen) >= 4096 {
					return ErrInvalid
				}
				seen[key] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			count := 0
			for d.More() {
				count++
				if count > 4096 {
					return ErrInvalid
				}
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if walk(0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
