package filekit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T, size int) (string, *Store, string, []byte) {
	t.Helper()
	base := t.TempDir()
	t.Logf("fixture directory %s; TMPDIR=%s", base, os.Getenv("TMPDIR"))
	if required := os.Getenv("OUTPOST_TEST_ROOT"); required != "" {
		rel, err := filepath.Rel(required, base)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatal("fixture outside required test filesystem")
		}
	}
	owner, err := NewOwner()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(filepath.Join(base, "store"), owner, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	data := make([]byte, size)
	if _, err = rand.Read(data); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source")
	if err = os.WriteFile(source, data, 0640); err != nil {
		t.Fatal(err)
	}
	return base, s, source, data
}
func mustBackup(t *testing.T, s *Store, source string, opt BackupOptions) Stats {
	t.Helper()
	r, e := s.Backup(context.Background(), source, opt)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func mustRestore(t *testing.T, s *Store, version, out string, want []byte, independent bool) Descriptor {
	t.Helper()
	var d Descriptor
	var err error
	if independent {
		d, err = s.Restore(context.Background(), version, out)
	} else {
		d, err = s.RestoreVersion(context.Background(), version, out)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, d.Names[0]))
	if err != nil || !bytes.Equal(b, want) {
		t.Fatal("restored bytes differ", err)
	}
	return d
}
func aclFor(uid uint32) []byte {
	b := make([]byte, 44)
	binary.LittleEndian.PutUint32(b, 2)
	entries := [][3]uint32{{1, 6, ^uint32(0)}, {2, 4, uid}, {4, 4, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}}
	for i, e := range entries {
		p := b[4+i*8:]
		binary.LittleEndian.PutUint16(p, uint16(e[0]))
		binary.LittleEndian.PutUint16(p[2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(p[4:], e[2])
	}
	return b
}

func TestIndependentVersionsAndAttributes(t *testing.T) {
	base, s, source, old := fixture(t, 12<<20)
	ctx := context.Background()
	names := []string{"folder/секрет с пробелом.bin", "alias/link.bin"}
	if err := os.Link(source, filepath.Join(base, "source-hardlink")); err != nil {
		t.Fatal(err)
	}
	acl := aclFor(uint32(os.Getuid() + 1))
	if err := syscall.Setxattr(source, "system.posix_acl_access", acl, 0); err != nil {
		t.Fatal("ACL support required", err)
	}
	if err := syscall.Setxattr(source, "user.outpost-test", []byte("private attribute marker"), 0); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1710000000, 123456789)
	if err := os.Chtimes(source, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	v1 := mustBackup(t, s, source, BackupOptions{Names: names})
	if v1.SourceBytes != int64(len(old)) {
		t.Fatal(v1.SourceBytes)
	}
	newData := append([]byte(nil), old...)
	copy(newData[len(newData)/2:], bytes.Repeat([]byte{97}, 32<<10))
	if err := os.WriteFile(source, newData, 0640); err != nil {
		t.Fatal(err)
	}
	v2 := mustBackup(t, s, source, BackupOptions{Names: names, File: v1.File, Previous: v1.Version})
	if v2.Version == v1.Version || v2.NewPayloadBytes >= int64(len(old)) {
		t.Fatal("version or reuse failed")
	}
	repeat := mustBackup(t, s, source, BackupOptions{Names: names, File: v1.File, Previous: v2.Version})
	if repeat.Version != v2.Version || repeat.NewPayloadBytes != 0 || repeat.NewMetadataBytes != 0 {
		t.Fatal("unchanged data copied")
	}
	for _, v := range []string{v1.Version, v2.Version} {
		if err := s.Export(ctx, v, filepath.Join(base, "kit-"+v)); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if err := os.RemoveAll(filepath.Join(base, "store")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	reader := s.Owner
	reader.SigningKey = nil
	for i, v := range []string{v1.Version, v2.Version} {
		kitDir := filepath.Join(base, "kit-"+v)
		for _, name := range []string{"versions", ".txn", ".lock", "store.json"} {
			if err := os.RemoveAll(filepath.Join(kitDir, name)); err != nil {
				t.Fatal(err)
			}
		}
		kit, err := OpenStore(kitDir, reader, false)
		if err != nil {
			t.Fatal(err)
		}
		want := old
		if i == 1 {
			want = newData
		}
		out := filepath.Join(base, "out-"+v)
		d := mustRestore(t, kit, v, out, want, true)
		kit.Close()
		a, err := os.Stat(filepath.Join(out, names[0]))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.Stat(filepath.Join(out, names[1]))
		if err != nil || !os.SameFile(a, b) {
			t.Fatal("hard links not preserved", err)
		}
		if a.Mode().Perm() != 0640 || a.ModTime().UnixNano() != d.Metadata.MtimeNS {
			t.Fatal("attributes differ")
		}
		if i == 0 && a.ModTime().UnixNano() != stamp.UnixNano() {
			t.Fatal("nanoseconds lost")
		}
		got := make([]byte, 64)
		n, err := syscall.Getxattr(filepath.Join(out, names[0]), "system.posix_acl_access", got)
		if err != nil || !bytes.Equal(got[:n], acl) {
			t.Fatal("ACL differs", err)
		}
		n, err = syscall.Getxattr(filepath.Join(out, names[0]), "user.outpost-test", got)
		if err != nil || string(got[:n]) != "private attribute marker" {
			t.Fatal("xattr differs", err)
		}
	}
}

func TestRepackAndRetirePreserveKits(t *testing.T) {
	base, s, source, old := fixture(t, 20<<20)
	ctx := context.Background()
	v1 := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
	newData := append([]byte(nil), old...)
	copy(newData[5<<20:], bytes.Repeat([]byte{42}, 64<<10))
	if err := os.WriteFile(source, newData, 0600); err != nil {
		t.Fatal(err)
	}
	v2 := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}, File: v1.File, Previous: v1.Version})
	saved := filepath.Join(base, "saved")
	if err := s.Export(ctx, v1.Version, saved); err != nil {
		t.Fatal(err)
	}
	r, err := s.Repack(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.PayloadObjectsReplaced == 0 || r.GarbageObjectsRemoved == 0 {
		t.Fatal("no physical repack", r)
	}
	mustRestore(t, s, v1.Version, filepath.Join(base, "after-repack-old"), old, false)
	mustRestore(t, s, v2.Version, filepath.Join(base, "after-repack-new"), newData, false)
	if _, err = s.Retire(ctx, []string{v1.Version}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.LoadVersion(v1.Version); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retired version visible", err)
	}
	mustRestore(t, s, v2.Version, filepath.Join(base, "retained"), newData, false)
	kit, err := OpenStore(saved, s.Owner, false)
	if err != nil {
		t.Fatal(err)
	}
	defer kit.Close()
	mustRestore(t, kit, v1.Version, filepath.Join(base, "saved-old"), old, true)
}

func TestFailureDoesNotPublishOrOverwrite(t *testing.T) {
	base, s, source, data := fixture(t, 2<<20)
	ctx := context.Background()
	v := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
	if _, err := s.Backup(ctx, source, BackupOptions{File: v.File, Previous: v.Version, Names: []string{"../escape"}}); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := s.Export(ctx, v.Version, filepath.Join(base, "store", "nested")); err == nil {
		t.Fatal("recursive export accepted")
	}
	out := filepath.Join(base, "occupied")
	s.Fault = func(point string) error {
		if point == "restore-verified" {
			return os.Mkdir(out, 0700)
		}
		return nil
	}
	if _, err := s.RestoreVersion(ctx, v.Version, out); err == nil {
		t.Fatal("racing destination overwritten")
	}
	if st, err := os.Stat(out); err != nil || !st.IsDir() {
		t.Fatal("existing destination lost")
	}
	s.Fault = nil
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".outpost-restore-") {
			t.Fatal("partial restore left")
		}
	}
	data[0] ^= 1
	if err = os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	s.Fault = func(point string) error {
		if point == "descriptor-written" {
			return syscall.ENOSPC
		}
		return nil
	}
	if _, err = s.Backup(ctx, source, BackupOptions{File: v.File, Previous: v.Version, Names: []string{"file"}}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("injected full disk not propagated", err)
	}
	s.Fault = nil
	ids, err := s.versions()
	if err != nil || len(ids) != 1 || ids[0] != v.Version {
		t.Fatal("failed publication visible", err)
	}
	data[0] ^= 1
	mustRestore(t, s, v.Version, filepath.Join(base, "last-good"), data, false)
}

func TestReaderBlocksRetirement(t *testing.T) {
	base, s, source, data := fixture(t, 1<<20)
	ctx := context.Background()
	v := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
	reader, err := OpenStore(filepath.Join(base, "store"), s.Owner, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	reader.Fault = func(point string) error {
		if point == "restore-verified" {
			close(entered)
			<-release
		}
		return nil
	}
	go func() { _, e := reader.RestoreVersion(ctx, v.Version, filepath.Join(base, "read")); done <- e }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("reader did not reach checkpoint")
	}
	limited, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = s.Retire(limited, []string{v.Version})
	cancel()
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("maintenance bypassed reader", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(base, "read", "file"))
	if err != nil || !bytes.Equal(b, data) {
		t.Fatal("reader lost data", err)
	}
	if _, err = s.Retire(ctx, []string{v.Version}); err != nil {
		t.Fatal(err)
	}
}
