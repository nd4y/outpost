package sourceagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

// The serial fixture uses a fresh random seed held outside its per-case roots.
// The controller provides the same read-only seed only to the four producers.
// Independent reader processes receive their normal recovery-only material.
func loadAsymmetricSerialEpoch(path string) (*fixtureEpoch, string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() != sha256.Size ||
		!ok || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
		return nil, "", errors.New("serial fixture seed requires one private, owned regular file")
	}
	seed, err := io.ReadAll(io.LimitReader(file, sha256.Size+1))
	if err != nil {
		return nil, "", err
	}
	defer clear(seed)
	if len(seed) != sha256.Size || bytes.Equal(seed, make([]byte, sha256.Size)) {
		return nil, "", errors.New("serial fixture requires a fresh 32-byte seed")
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, seed)
		mac.Write([]byte("outpost-test/asymmetric-serial/v1/" + label))
		return mac.Sum(nil)
	}
	signer := ed25519.NewKeyFromSeed(derive("file-signer"))
	writer := ed25519.NewKeyFromSeed(derive("generation-writer"))
	maintenance := ed25519.NewKeyFromSeed(derive("maintenance"))
	owner := filekit.Owner{Format: filekit.Format, Domain: storage.Hash(derive("domain")), Master: derive("file-master"),
		VerifyKey: signer.Public().(ed25519.PublicKey), SigningKey: signer}
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("asymmetric-scale-repo")), Epoch: 1,
		Writer: writer.Public().(ed25519.PublicKey), Maintenance: maintenance.Public().(ed25519.PublicKey)}
	public, err := json.Marshal(struct {
		Trust generation.Trust
		File  ed25519.PublicKey
	}{trust, owner.VerifyKey})
	if err != nil {
		return nil, "", err
	}
	return &fixtureEpoch{owner: owner, trust: trust, writer: writer}, storage.Hash(public), nil
}

func TestAsymmetricSerialFixtureEpochIsSharedAndPrivate(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed")
	makeSeed := func(path string, value byte, permissions os.FileMode) {
		t.Helper()
		must(t, os.WriteFile(path, bytes.Repeat([]byte{value}, sha256.Size), permissions))
	}
	makeSeed(seed, 1, 0400)
	first, firstID, err := loadAsymmetricSerialEpoch(seed)
	must(t, err)
	second, secondID, err := loadAsymmetricSerialEpoch(seed)
	must(t, err)
	if !storage.ID(firstID) || firstID != secondID || !bytes.Equal(first.owner.Master, second.owner.Master) ||
		!bytes.Equal(first.writer, second.writer) || !bytes.Equal(first.owner.SigningKey, second.owner.SigningKey) {
		t.Fatal("same serial seed did not preserve the cryptographic epoch")
	}
	other := filepath.Join(dir, "other")
	makeSeed(other, 2, 0400)
	third, thirdID, err := loadAsymmetricSerialEpoch(other)
	must(t, err)
	if firstID == thirdID || bytes.Equal(first.owner.Master, third.owner.Master) {
		t.Fatal("an independent synthetic run reused the serial epoch")
	}
	link := filepath.Join(dir, "linked")
	must(t, os.Symlink(seed, link))
	public := filepath.Join(dir, "public")
	makeSeed(public, 1, 0444)
	wrongSize := filepath.Join(dir, "short")
	must(t, os.WriteFile(wrongSize, []byte{1}, 0400))
	aliased := filepath.Join(dir, "hardlink")
	must(t, os.Link(seed, aliased))
	fifo := filepath.Join(dir, "fifo")
	must(t, unix.Mkfifo(fifo, 0400))
	for _, refused := range []string{link, public, wrongSize, aliased, seed, fifo} {
		if _, _, err := loadAsymmetricSerialEpoch(refused); err == nil {
			t.Fatal("unowned or unbounded seed accepted", filepath.Base(refused))
		}
	}
}
