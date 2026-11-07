// Package filekit implements the independently recoverable file-kit candidate.
// It is a Linux development format, not a production worker or migration API.
package filekit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/nd4y/outpost/internal/statefile"
	"io"
	"os"
)

const (
	Format               = "outpost-filekit-1"
	TypedFormat          = "outpost-filekit-2"
	MaxFileBytes   int64 = 128 << 30
	MaxChunk             = 4 << 20
	MaxObject            = 8 << 20
	DescriptorPart       = 4 << 20
	MaxDescriptor        = 64 << 20
	MaxBlocks            = 524288
	MaxRoot              = 128 << 10
)

type Owner struct {
	Format     string             `json:"format"`
	Domain     string             `json:"domain"`
	Master     []byte             `json:"master"`
	VerifyKey  ed25519.PublicKey  `json:"verifyKey"`
	SigningKey ed25519.PrivateKey `json:"signingKey,omitempty"`
}

// Metadata describes one regular inode and optional hard-link aliases. All
// names and attributes are encrypted inside the descriptor.
type Metadata struct {
	Mode    uint32            `json:"mode"`
	UID     uint32            `json:"uid"`
	GID     uint32            `json:"gid"`
	MtimeNS int64             `json:"mtimeNs"`
	Xattrs  map[string][]byte `json:"xattrs,omitempty"`
}

type Object struct {
	ID    string `json:"id"`
	Bytes int    `json:"bytes"`
}

type Block struct {
	Hash        string `json:"hash"`
	Bytes       int    `json:"bytes"`
	Object      Object `json:"object"`
	Offset      int    `json:"offset"`
	CipherBytes int    `json:"cipherBytes"`
}

type Descriptor struct {
	Format     string   `json:"format"`
	Domain     string   `json:"domain"`
	File       string   `json:"file"`
	Names      []string `json:"names"`
	Size       int64    `json:"size"`
	SHA256     string   `json:"sha256"`
	Metadata   Metadata `json:"metadata"`
	Blocks     []Block  `json:"blocks"`
	Kind       string   `json:"kind,omitempty"`
	LinkTarget string   `json:"linkTarget,omitempty"`
}

// Envelope is signed and contains every descriptor part. It reveals opaque
// identities and lengths, never source paths or plaintext chunk hashes.
type Envelope struct {
	Format    string   `json:"format"`
	Domain    string   `json:"domain"`
	File      string   `json:"file"`
	Version   string   `json:"version"`
	Parts     []Object `json:"parts"`
	Signature []byte   `json:"signature,omitempty"`
}

type Stats struct {
	Version           string `json:"version"`
	File              string `json:"file"`
	SourceBytes       int64  `json:"sourceBytes"`
	VerifiedReadBytes int64  `json:"verifiedReadBytes"`
	NewPayloadBytes   int64  `json:"newPayloadBytes"`
	NewMetadataBytes  int64  `json:"newMetadataBytes"`
	NewObjects        int    `json:"newObjects"`
	Blocks            int    `json:"blocks"`
	PeakBufferBytes   int64  `json:"peakBufferBytes"`
}

type BackupOptions struct {
	File     string
	Previous string
	Names    []string
	Expected *SourceIdentity
}

// Fault is an optional test hook. A caller may inject a failure or stop its own
// process at a durability boundary; normal callers leave it nil.
type Fault func(string) error

type Store struct {
	root    *os.Root
	Owner   Owner
	Fault   Fault
	Stats   Stats
	backend ObjectBackend
	Admit   statefile.Admission
}

// ObjectBackend receives ciphertext only. Write must reject conflicting bytes
// and acknowledge verified durable acceptance; false means an identical object
// was already accepted. Check proves presence/length, not a full content scrub.
// Implementations must honor context cancellation and bound their requests.
type ObjectBackend interface {
	Read(context.Context, Object) ([]byte, error)
	Write(context.Context, Object, []byte) (bool, error)
	Check(context.Context, Object) error
}

var ErrInvalid = errors.New("invalid or unsupported file kit")

var ErrRemoteMaintenance = errors.New("object maintenance is owned by the receiving replica")

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func (s *Store) checkpoint(name string) error {
	if s.Fault != nil {
		return s.Fault(name)
	}
	return nil
}
