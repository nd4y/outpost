package filekit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func entryOK(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func TestTypedIndependentDirectoryAndSymlinkRecovery(t *testing.T) {
	base, s, _, _ := fixture(t, 1)
	ctx := context.Background()
	source := filepath.Join(base, "tree")
	entryOK(t, os.Mkdir(source, 0700))
	entryOK(t, os.Mkdir(filepath.Join(source, "private-directory"), 0750))
	entryOK(t, unix.Setxattr(filepath.Join(source, "private-directory"), "user.outpost-test", []byte("directory attribute"), 0))
	outside := filepath.Join(base, "outside-sensitive-target")
	entryOK(t, os.WriteFile(outside, []byte("must remain unchanged"), 0640))
	when := time.Unix(1700000000, 123456789)
	entryOK(t, os.Chtimes(outside, when, when))
	entryOK(t, os.Chtimes(filepath.Join(source, "private-directory"), when, when))
	entryOK(t, os.Symlink(outside, filepath.Join(source, "private-link")))
	times := []unix.Timespec{unix.NsecToTimespec(when.UnixNano()), unix.NsecToTimespec(when.UnixNano())}
	entryOK(t, unix.UtimesNanoAt(unix.AT_FDCWD, filepath.Join(source, "private-link"), times, unix.AT_SYMLINK_NOFOLLOW))
	root, e := os.OpenRoot(source)
	entryOK(t, e)
	defer root.Close()
	type saved struct {
		version, kind, name string
		meta                Metadata
		target              string
	}
	var all []saved
	for _, name := range []string{"private-directory", "private-link"} {
		result, e := s.BackupEntry(ctx, root, name, BackupOptions{Names: []string{"selected/" + name}})
		entryOK(t, e)
		envelope, d, e := s.LoadVersion(result.Version)
		entryOK(t, e)
		if envelope.Format != TypedFormat || d.Format != TypedFormat || result.SourceBytes != 0 {
			t.Fatal("type not versioned independently", envelope, d)
		}
		raw, e := json.Marshal(envelope)
		entryOK(t, e)
		if bytes.Contains(raw, []byte(name)) || bytes.Contains(raw, []byte(outside)) {
			t.Fatal("plain path in root")
		}
		for _, part := range envelope.Parts {
			b, e := s.readObject(part)
			entryOK(t, e)
			if bytes.Contains(b, []byte(name)) || bytes.Contains(b, []byte(outside)) {
				t.Fatal("plain path in object")
			}
		}
		all = append(all, saved{result.Version, d.Kind, d.Names[0], d.Metadata, d.LinkTarget})
	}
	_, e = s.Repack(ctx)
	entryOK(t, e)
	for i, item := range all {
		kit := filepath.Join(base, []string{"directory-kit", "symlink-kit"}[i])
		entryOK(t, s.Export(ctx, item.version, kit))
		owner := s.Owner
		owner.SigningKey = nil
		k, e := OpenStore(kit, owner, false)
		entryOK(t, e)
		out := filepath.Join(base, []string{"directory-restore", "symlink-restore"}[i])
		d, e := k.Restore(ctx, item.version, out)
		entryOK(t, e)
		entryOK(t, k.Close())
		info, e := os.Lstat(filepath.Join(out, item.name))
		entryOK(t, e)
		if d.Kind != item.kind || info.ModTime().UnixNano() != item.meta.MtimeNS {
			t.Fatal("type/time differs")
		}
		if item.kind == "directory" {
			if !info.IsDir() || info.Mode().Perm() != 0750 {
				t.Fatal("directory metadata differs")
			}
			f, e := os.Open(filepath.Join(out, item.name))
			entryOK(t, e)
			meta, e := captureMetadata(f)
			entryOK(t, e)
			f.Close()
			if !sameMetadata(meta, item.meta) {
				t.Fatal("directory attrs lost")
			}
		} else {
			target, e := os.Readlink(filepath.Join(out, item.name))
			entryOK(t, e)
			if target != item.target || info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("symlink followed or changed")
			}
		}
	}
	data, e := os.ReadFile(outside)
	entryOK(t, e)
	info, e := os.Stat(outside)
	entryOK(t, e)
	if string(data) != "must remain unchanged" || info.ModTime() != when || info.Mode().Perm() != 0640 {
		t.Fatal("outside target was modified")
	}
}
func TestRootedEntryRefusesSymlinkAncestorsAndSpecialFiles(t *testing.T) {
	base, s, _, _ := fixture(t, 1)
	source := filepath.Join(base, "root")
	entryOK(t, os.Mkdir(source, 0700))
	entryOK(t, os.Mkdir(filepath.Join(source, "real"), 0700))
	entryOK(t, os.WriteFile(filepath.Join(source, "real", "data"), []byte("data"), 0600))
	entryOK(t, os.Symlink("real", filepath.Join(source, "alias")))
	entryOK(t, unix.Mkfifo(filepath.Join(source, "pipe"), 0600))
	root, e := os.OpenRoot(source)
	entryOK(t, e)
	defer root.Close()
	for _, name := range []string{"alias/data", "pipe", "../source", "/source"} {
		if _, e = s.BackupEntry(context.Background(), root, name, BackupOptions{Names: []string{"entry"}}); e == nil {
			t.Fatalf("unsafe entry accepted: %s", name)
		}
	}
	result, e := s.BackupEntry(context.Background(), root, "real/data", BackupOptions{Names: []string{"entry"}})
	entryOK(t, e)
	envelope, d, e := s.LoadVersion(result.Version)
	entryOK(t, e)
	raw, e := json.Marshal(d)
	entryOK(t, e)
	if envelope.Format != Format || d.Kind != "" || bytes.Contains(raw, []byte(`"kind"`)) || bytes.Contains(raw, []byte(`"linkTarget"`)) {
		t.Fatal("old regular encoding changed")
	}
}
func TestBackupDetectsChangedCTimeWithRestoredSizeAndMTime(t *testing.T) {
	_, s, source, _ := fixture(t, 12<<20)
	before, e := os.Stat(source)
	entryOK(t, e)
	changed := false
	s.Fault = func(point string) error {
		if point == "object-durable" && !changed {
			changed = true
			f, e := os.OpenFile(source, os.O_WRONLY, 0)
			if e != nil {
				return e
			}
			_, e = f.WriteAt([]byte("altered"), 0)
			closeErr := f.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
			return os.Chtimes(source, before.ModTime(), before.ModTime())
		}
		return nil
	}
	if _, e = s.Backup(context.Background(), source, BackupOptions{Names: []string{"entry"}}); e == nil {
		t.Fatal("mutation hidden by restored mtime")
	}
	if !changed {
		t.Fatal("mutation hook not reached")
	}
	versions, e := s.versions()
	entryOK(t, e)
	if len(versions) != 0 {
		t.Fatal("changing regular file published")
	}
}
func TestTypedDescriptorRejectsSubstitutionAndUnsupportedType(t *testing.T) {
	_, s, _, _ := fixture(t, 1)
	d := Descriptor{Format: TypedFormat, Domain: s.Owner.Domain, File: randomID(), Names: []string{"dir"}, SHA256: digest(nil), Kind: "directory", Metadata: Metadata{Mode: 0750}}
	entryOK(t, validateDescriptor(d))
	bad := d
	bad.Format = Format
	if e := validateDescriptor(bad); !errors.Is(e, ErrInvalid) {
		t.Fatal("typed data accepted as v1")
	}
	bad = d
	bad.Kind = "device"
	if e := validateDescriptor(bad); e == nil {
		t.Fatal("device accepted")
	}
	bad = d
	bad.LinkTarget = "../target"
	if e := validateDescriptor(bad); e == nil {
		t.Fatal("directory link target accepted")
	}
	bad = d
	bad.Names = []string{"a", "b"}
	if e := validateDescriptor(bad); e == nil {
		t.Fatal("directory hardlink aliases accepted")
	}
	bad = d
	bad.Metadata.Xattrs = map[string][]byte{string([]byte{255}): []byte{1}}
	if e := validateDescriptor(bad); e == nil {
		t.Fatal("non UTF-8 attribute name silently normalized")
	}
}
