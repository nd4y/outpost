package filekit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validID(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}

func NewOwner() (Owner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Owner{}, err
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return Owner{}, err
	}
	return Owner{Format: Format, Domain: randomID(), Master: key, VerifyKey: priv.Public().(ed25519.PublicKey), SigningKey: priv}, nil
}
func (o Owner) validate() error {
	if o.Format != Format || !validID(o.Domain) || len(o.Master) != 32 || len(o.VerifyKey) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	if len(o.SigningKey) != 0 && (len(o.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(o.SigningKey[:32]), o.SigningKey) || !bytes.Equal(o.SigningKey.Public().(ed25519.PublicKey), o.VerifyKey)) {
		return ErrInvalid
	}
	return nil
}
func (o Owner) key(file, kind string) ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	if !validID(file) {
		return nil, ErrInvalid
	}
	return hkdf.Key(sha256.New, o.Master, []byte(o.Domain), Format+"/"+file+"/"+kind, 32)
}
func (o Owner) aead(file, kind string) (cipher.AEAD, error) {
	k, err := o.key(file, kind)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(b)
}
func (o Owner) seal(file, kind string, plain []byte) ([]byte, error) {
	a, err := o.aead(file, kind)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nil, plain, []byte(Format+"/"+o.Domain+"/"+file+"/"+kind)), nil
}
func (o Owner) open(file, kind string, sealed []byte) ([]byte, error) {
	a, err := o.aead(file, kind)
	if err != nil {
		return nil, err
	}
	b, err := a.Open(nil, nil, sealed, []byte(Format+"/"+o.Domain+"/"+file+"/"+kind))
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	return b, nil
}

func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func safeName(s string) bool {
	if s == "" || len(s) > 4095 || !utf8.ValidString(s) || strings.ContainsAny(s, "\\\x00") || strings.HasPrefix(s, "/") || s == "." || s == ".." || strings.HasPrefix(s, "../") || path.Clean(s) != s {
		return false
	}
	for _, component := range strings.Split(s, "/") {
		if len(component) > 255 {
			return false
		}
	}
	return true
}

func validateDescriptor(d Descriptor) error {
	if d.Format != Format || !validID(d.Domain) || !validID(d.File) || !validID(d.SHA256) || d.Size < 0 || d.Size > MaxFileBytes || len(d.Names) == 0 || len(d.Names) > 256 || len(d.Blocks) > MaxBlocks {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, n := range d.Names {
		if !safeName(n) || seen[n] {
			return ErrInvalid
		}
		seen[n] = true
	}
	for _, n := range d.Names {
		for p := path.Dir(n); p != "."; p = path.Dir(p) {
			if seen[p] {
				return ErrInvalid
			}
		}
	}
	if err := validateMetadata(d.Metadata); err != nil {
		return err
	}
	var size int64
	for _, b := range d.Blocks {
		if !validID(b.Hash) || !validID(b.Object.ID) || b.Bytes <= 0 || b.Bytes > MaxChunk || b.CipherBytes != b.Bytes+28 || b.Object.Bytes <= 0 || b.Object.Bytes > MaxObject || b.Offset < 0 || b.Offset > b.Object.Bytes-b.CipherBytes {
			return ErrInvalid
		}
		size += int64(b.Bytes)
		if size > MaxFileBytes {
			return ErrInvalid
		}
	}
	if size != d.Size {
		return ErrInvalid
	}
	return nil
}

// Logical identity includes ordered plaintext content and attributes but not
// physical pack locations. Repacking cannot change the selected version.
func (o Owner) version(d Descriptor) (string, error) {
	if err := validateDescriptor(d); err != nil {
		return "", err
	}
	copyD := d
	copyD.Blocks = append([]Block(nil), d.Blocks...)
	for i := range copyD.Blocks {
		copyD.Blocks[i].Object = Object{}
		copyD.Blocks[i].Offset = 0
		copyD.Blocks[i].CipherBytes = 0
	}
	b, err := json.Marshal(copyD)
	if err != nil {
		return "", err
	}
	k, err := o.key(d.File, "version")
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, k)
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (o Owner) sign(e Envelope) (Envelope, error) {
	e.Signature = nil
	b, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	if err = o.validate(); err != nil {
		return e, err
	}
	if len(o.SigningKey) != ed25519.PrivateKeySize {
		return e, ErrInvalid
	}
	e.Signature = ed25519.Sign(o.SigningKey, b)
	return e, nil
}
func (o Owner) verifyEnvelope(e Envelope, expected string) error {
	if err := o.validate(); err != nil {
		return err
	}
	if e.Format != Format || e.Domain != o.Domain || !validID(e.File) || !validID(e.Version) || e.Version != expected || len(e.Parts) == 0 || len(e.Parts) > (MaxDescriptor+28+DescriptorPart-1)/DescriptorPart {
		return ErrInvalid
	}
	var n int
	for i, p := range e.Parts {
		if !validID(p.ID) || p.Bytes < 1 || p.Bytes > DescriptorPart || (i < len(e.Parts)-1 && p.Bytes != DescriptorPart) {
			return ErrInvalid
		}
		n += p.Bytes
	}
	if n > MaxDescriptor+28 {
		return ErrInvalid
	}
	sig := e.Signature
	e.Signature = nil
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if !ed25519.Verify(o.VerifyKey, b, sig) {
		return ErrInvalid
	}
	return nil
}
