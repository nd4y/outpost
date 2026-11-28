package filekit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNamesRespectLinuxFilesystemBounds(t *testing.T) {
	base, s, source, data := fixture(t, 64)
	for _, name := range []string{strings.Repeat("a", 256), "dir/" + strings.Repeat("я", 128), strings.Repeat("a/", 2047) + "aa"} {
		if _, err := s.Backup(context.Background(), source, BackupOptions{Names: []string{name}}); err == nil {
			t.Fatal("unrestorable name accepted")
		}
	}
	name := strings.Repeat("a", 255)
	v := mustBackup(t, s, source, BackupOptions{Names: []string{name}})
	mustRestore(t, s, v.Version, filepath.Join(base, "maximum-component"), data, false)
}

func TestSpecialSourceAndOwnerInputsRejectWithoutBlocking(t *testing.T) {
	base, s, source, _ := fixture(t, 64)
	fifo := filepath.Join(base, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{fifo, link, base} {
		done := make(chan error, 1)
		go func() {
			_, err := s.Backup(context.Background(), name, BackupOptions{Names: []string{"file"}})
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("special source accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("opening non-regular source blocked")
		}
	}
	done := make(chan error, 1)
	go func() { _, err := ReadOwner(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO owner accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("opening owner FIFO blocked")
	}
}

func forgedDescriptor(t *testing.T, s *Store, e Envelope, d Descriptor) {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	forgedDescriptorBytes(t, s, e, b)
}

func forgedDescriptorBytes(t *testing.T, s *Store, e Envelope, b []byte) {
	t.Helper()
	b, err := s.Owner.seal(e.File, "descriptor", b)
	if err != nil {
		t.Fatal(err)
	}
	e.Parts = nil
	for len(b) > 0 {
		n := min(len(b), DescriptorPart)
		p, err := s.putObject(b[:n], true)
		if err != nil {
			t.Fatal(err)
		}
		e.Parts = append(e.Parts, p)
		b = b[n:]
	}
	e, err = s.Owner.sign(e)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.writeEnvelope("kit.json", e); err != nil {
		t.Fatal(err)
	}
}

func assertRestoreUnpublished(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("failed recovery published output", err)
	}
	stages, err := filepath.Glob(filepath.Join(filepath.Dir(out), ".outpost-restore-*"))
	if err != nil || len(stages) != 0 {
		t.Fatal("failed recovery retained plaintext staging", stages, err)
	}
}

func TestTamperedKitNeverPublishesOutput(t *testing.T) {
	base, s, source, _ := fixture(t, 9<<20)
	ctx := context.Background()
	v := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
	cases := map[string]func(*testing.T, *Store, *Envelope, *Descriptor){
		"object-fifo": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			r := d.Blocks[0].Object
			if err := k.root.Remove(objectPath(r.ID)); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(k.root.Name(), objectPath(r.ID)), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"missing-descriptor-part": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			if err := k.root.Remove(objectPath(e.Parts[len(e.Parts)-1].ID)); err != nil {
				t.Fatal(err)
			}
		},
		"truncated-payload": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			r := d.Blocks[len(d.Blocks)-1].Object
			f, err := k.root.OpenFile(objectPath(r.ID), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err = f.Truncate(int64(r.Bytes - 1)); err != nil {
				t.Fatal(err)
			}
		},
		"extra-payload-byte": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			r := d.Blocks[0].Object
			f, err := k.root.OpenFile(objectPath(r.ID), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err = f.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
		},
		"corrupted-payload": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			r := d.Blocks[0].Object
			f, err := k.root.OpenFile(objectPath(r.ID), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			b := []byte{0}
			if _, err = f.ReadAt(b, 0); err != nil {
				t.Fatal(err)
			}
			b[0] ^= 1
			if _, err = f.WriteAt(b, 0); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-key": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			k.Owner.Master = append([]byte(nil), k.Owner.Master...)
			k.Owner.Master[0] ^= 1
		},
		"bad-signature": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			e.Signature[0] ^= 1
			if err := k.writeEnvelope("kit.json", *e); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-file-identity": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			e.File = randomID()
			signed, err := k.Owner.sign(*e)
			if err != nil {
				t.Fatal(err)
			}
			if err = k.writeEnvelope("kit.json", signed); err != nil {
				t.Fatal(err)
			}
		},
		"root-extra-data": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			f, err := k.root.OpenFile("kit.json", os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err = f.Write([]byte("\n{}")); err != nil {
				t.Fatal(err)
			}
		},
		"descriptor-extra-data": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			b, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			forgedDescriptorBytes(t, k, *e, append(b, []byte("\n{}")...))
		},
		"reordered-blocks": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			if len(d.Blocks) < 2 {
				t.Fatal("need multiple blocks")
			}
			d.Blocks[0], d.Blocks[len(d.Blocks)-1] = d.Blocks[len(d.Blocks)-1], d.Blocks[0]
			forgedDescriptor(t, k, *e, *d)
		},
		"traversal-descriptor": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			d.Names = []string{"../../escaped"}
			forgedDescriptor(t, k, *e, *d)
		},
		"overlong-metadata": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			d.Metadata.Xattrs = map[string][]byte{"user.too-large": make([]byte, 65537)}
			forgedDescriptor(t, k, *e, *d)
		},
		"missing-final-block": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			d.Blocks = d.Blocks[:len(d.Blocks)-1]
			forgedDescriptor(t, k, *e, *d)
		},
		"object-symlink-escape": func(t *testing.T, k *Store, e *Envelope, d *Descriptor) {
			r := d.Blocks[0].Object
			if err := k.root.Remove(objectPath(r.ID)); err != nil {
				t.Fatal(err)
			}
			if err := k.root.Symlink(source, objectPath(r.ID)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(base, "kit-"+name)
			if err := s.Export(ctx, v.Version, dir); err != nil {
				t.Fatal(err)
			}
			k, err := OpenStore(dir, s.Owner, false)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()
			e, d, err := k.load("kit.json", v.Version)
			if err != nil {
				t.Fatal(err)
			}
			change(t, k, &e, &d)
			out := filepath.Join(base, "out-"+name)
			if _, err = k.Restore(ctx, v.Version, out); err == nil {
				t.Fatal("tamper accepted")
			}
			assertRestoreUnpublished(t, out)
		})
	}
	if _, err := os.Stat(filepath.Join(base, "escaped")); !os.IsNotExist(err) {
		t.Fatal("path escaped", err)
	}
}

func TestMultipartDescriptorIsSelfContained(t *testing.T) {
	base, s, source, _ := fixture(t, 1)
	f, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := captureMetadata(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	file := randomID()
	plain := []byte{'q'}
	hash := digest(plain)
	ciphertext, err := s.Owner.seal(file, "chunk/"+hash, plain)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := s.putObject(ciphertext, false)
	if err != nil {
		t.Fatal(err)
	}
	const blocks = 60000
	d := Descriptor{Format: Format, Domain: s.Owner.Domain, File: file, Names: []string{"multipart"}, Size: blocks, SHA256: digest(bytes.Repeat(plain, blocks)), Metadata: meta}
	for range blocks {
		d.Blocks = append(d.Blocks, Block{Hash: hash, Bytes: 1, Object: ref, CipherBytes: len(ciphertext)})
	}
	e, err := s.sealDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Parts) < 3 || e.Parts[0].Bytes != DescriptorPart || e.Parts[1].Bytes != DescriptorPart {
		t.Fatal("two full-size descriptor parts and a final part required")
	}
	if e.Parts[0].ID == e.Parts[1].ID {
		t.Fatal("reordering must change descriptor ciphertext")
	}
	if err = s.writeEnvelope("versions/"+e.Version+".json", e); err != nil {
		t.Fatal(err)
	}
	kitDir := filepath.Join(base, "multipart-kit")
	if err = s.Export(context.Background(), e.Version, kitDir); err != nil {
		t.Fatal(err)
	}
	k, err := OpenStore(kitDir, s.Owner, false)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	mustRestore(t, k, e.Version, filepath.Join(base, "good"), bytes.Repeat(plain, blocks), true)
	for _, name := range []string{"missing-final-part", "reordered-full-size-parts"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(base, name+"-kit")
			if err := s.Export(context.Background(), e.Version, dir); err != nil {
				t.Fatal(err)
			}
			bad, err := OpenStore(dir, s.Owner, false)
			if err != nil {
				t.Fatal(err)
			}
			defer bad.Close()
			changed := e
			changed.Parts = append([]Object(nil), e.Parts...)
			if name == "missing-final-part" {
				if err := bad.root.Remove(objectPath(changed.Parts[len(changed.Parts)-1].ID)); err != nil {
					t.Fatal(err)
				}
			} else {
				changed.Parts[0], changed.Parts[1] = changed.Parts[1], changed.Parts[0]
				changed, err = s.Owner.sign(changed)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Owner.verifyEnvelope(changed, e.Version); err != nil {
					t.Fatal("reordered envelope must pass size/signature admission", err)
				}
				if err := bad.writeEnvelope("kit.json", changed); err != nil {
					t.Fatal(err)
				}
			}
			out := filepath.Join(base, name+"-output")
			if _, err := bad.Restore(context.Background(), e.Version, out); err == nil {
				t.Fatal("invalid multipart kit accepted")
			}
			assertRestoreUnpublished(t, out)
		})
	}
}

func TestCrossFileCiphertextAndVersionSubstitution(t *testing.T) {
	base, s, source, data := fixture(t, 64<<10)
	ctx := context.Background()
	a := mustBackup(t, s, source, BackupOptions{Names: []string{"first"}})
	b := mustBackup(t, s, source, BackupOptions{Names: []string{"second"}})
	if a.File == b.File || a.Version == b.Version {
		t.Fatal("identities not separated")
	}
	_, other, err := s.LoadVersion(b.Version)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "kit")
	if err = s.Export(ctx, a.Version, dir); err != nil {
		t.Fatal(err)
	}
	k, err := OpenStore(dir, s.Owner, false)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	e, d, err := k.load("kit.json", a.Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.Restore(ctx, b.Version, filepath.Join(base, "wrong-version")); err == nil {
		t.Fatal("substituted version accepted")
	}
	assertRestoreUnpublished(t, filepath.Join(base, "wrong-version"))
	otherCipher, err := s.readObject(other.Blocks[0].Object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.putObject(otherCipher, false); err != nil {
		t.Fatal(err)
	}
	if d.Blocks[0].Hash != other.Blocks[0].Hash || d.Size != int64(len(data)) {
		t.Fatal("cross-file fixture differs")
	}
	d.Blocks[0] = other.Blocks[0]
	forgedDescriptor(t, k, e, d)
	if _, err = k.Restore(ctx, a.Version, filepath.Join(base, "wrong-file")); err == nil {
		t.Fatal("other file ciphertext accepted")
	}
	assertRestoreUnpublished(t, filepath.Join(base, "wrong-file"))
}
