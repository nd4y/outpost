package filekit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
)

type objectSink struct {
	mu                      sync.Mutex
	objects                 map[string][]byte
	reads, writes, checks   int
	readBytes, writtenBytes int64
	blockRead               bool
	corrupt                 bool
	failWrite               bool
}

func (b *objectSink) Read(ctx context.Context, ref Object) ([]byte, error) {
	b.mu.Lock()
	block := b.blockRead
	b.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.objects[ref.ID]
	if !ok {
		return nil, os.ErrNotExist
	}
	b.reads++
	b.readBytes += int64(len(data))
	data = append([]byte(nil), data...)
	if b.corrupt && len(data) > 0 {
		data[0] ^= 1
	}
	return data, nil
}
func (b *objectSink) Write(ctx context.Context, ref Object, data []byte) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failWrite {
		return false, statefile.ErrCapacity
	}
	if digest(data) != ref.ID || len(data) != ref.Bytes {
		return false, ErrInvalid
	}
	if previous, ok := b.objects[ref.ID]; ok {
		if !bytes.Equal(previous, data) {
			return false, ErrInvalid
		}
		return false, nil
	}
	b.objects[ref.ID] = append([]byte(nil), data...)
	b.writes++
	b.writtenBytes += int64(len(data))
	return true, nil
}
func (b *objectSink) Check(ctx context.Context, ref Object) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.checks++
	data, ok := b.objects[ref.ID]
	if !ok {
		return os.ErrNotExist
	}
	if len(data) != ref.Bytes {
		return ErrInvalid
	}
	return nil
}
func TestStreamingCaptureKeepsOnlyMetadataAndRestoresBothDeltaVersions(t *testing.T) {
	base, local, source, old := fixture(t, 12<<20)
	ctx := context.Background()
	sink := &objectSink{objects: map[string][]byte{}}
	cache := filepath.Join(base, "source-cache")
	s, e := OpenStreamingStore(cache, local.Owner, true, sink)
	entryOK(t, e)
	first, e := s.Backup(ctx, source, BackupOptions{Names: []string{"dataset/private-name"}})
	entryOK(t, e)
	if first.SourceBytes != int64(len(old)) || first.NewPayloadBytes < int64(len(old)) {
		t.Fatal("source/transfer accounting", first)
	}
	entries, e := os.ReadDir(filepath.Join(cache, "objects"))
	entryOK(t, e)
	if len(entries) != 0 {
		t.Fatal("full ciphertext copied to source")
	}
	var localBytes int64
	entryOK(t, filepath.WalkDir(cache, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			info, e := d.Info()
			if e != nil {
				return e
			}
			localBytes += info.Size()
		}
		return nil
	}))
	if localBytes > 65536 {
		t.Fatalf("unbounded metadata cache for one file: %d", localBytes)
	}
	if bad, e := OpenStore(cache, local.Owner, false); e == nil {
		bad.Close()
		t.Fatal("source cache accepted as full local copy")
	}
	for _, data := range sink.objects {
		if bytes.Contains(data, []byte("dataset/private-name")) {
			t.Fatal("plaintext name sent to backend")
		}
	}
	changed := append([]byte(nil), old...)
	copy(changed[6<<20:], bytes.Repeat([]byte{99}, 4096))
	entryOK(t, os.WriteFile(source, changed, 0640))
	sink.readBytes = 0
	second, e := s.Backup(ctx, source, BackupOptions{File: first.File, Previous: first.Version, Names: []string{"dataset/private-name"}})
	entryOK(t, e)
	if second.Version == first.Version || second.NewPayloadBytes <= 0 || second.NewPayloadBytes >= first.NewPayloadBytes || sink.checks == 0 {
		t.Fatal("delta did not reuse remote objects", first, second)
	}
	if sink.readBytes > 1<<20 {
		t.Fatalf("capture read old payload through source: %d", sink.readBytes)
	}
	entryOK(t, s.Close())
	s, e = OpenStreamingStore(cache, local.Owner, false, sink)
	entryOK(t, e)
	defer s.Close()
	mustRestore(t, s, first.Version, filepath.Join(base, "old-restore"), old, false)
	mustRestore(t, s, second.Version, filepath.Join(base, "new-restore"), changed, false)
	if _, e = s.GC(ctx); !errors.Is(e, ErrRemoteMaintenance) {
		t.Fatal("cache may collect receiver data", e)
	}
	if _, e = s.Retire(ctx, []string{first.Version}); !errors.Is(e, ErrRemoteMaintenance) {
		t.Fatal("cache may retire protected receiver roots", e)
	}
	if _, e = s.Repack(ctx); !errors.Is(e, ErrRemoteMaintenance) {
		t.Fatal("cache may repack receiver data", e)
	}
	_, _, e = s.LoadVersion(first.Version)
	entryOK(t, e)
}
func TestStreamingReadCancellationCorruptionAndAdmissionPreservePriorVersion(t *testing.T) {
	base, local, source, old := fixture(t, 2<<20)
	sink := &objectSink{objects: map[string][]byte{}}
	s, e := OpenStreamingStore(filepath.Join(base, "cache"), local.Owner, true, sink)
	entryOK(t, e)
	defer s.Close()
	ctx := context.Background()
	first, e := s.Backup(ctx, source, BackupOptions{Names: []string{"file"}})
	entryOK(t, e)
	sink.blockRead = true
	bounded, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e = s.Backup(bounded, source, BackupOptions{File: first.File, Previous: first.Version, Names: []string{"file"}})
	if !errors.Is(e, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("backend ignored operation cancellation", e)
	}
	sink.blockRead = false
	sink.corrupt = true
	if _, e = s.VerifyVersion(ctx, first.Version); e == nil {
		t.Fatal("corrupt backend accepted")
	}
	sink.corrupt = false
	modified := append([]byte(nil), old...)
	modified[0] ^= 1
	entryOK(t, os.WriteFile(source, modified, 0640))
	sink.failWrite = true
	if _, e = s.Backup(ctx, source, BackupOptions{File: first.File, Previous: first.Version, Names: []string{"file"}}); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("capacity not surfaced", e)
	}
	sink.failWrite = false
	s.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if _, e = s.Backup(ctx, source, BackupOptions{File: first.File, Previous: first.Version, Names: []string{"file"}}); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("local cache quota bypassed", e)
	}
	versions, e := s.versions()
	entryOK(t, e)
	if len(versions) != 1 || versions[0] != first.Version {
		t.Fatal("failed capture replaced old root")
	}
	s.Admit = nil
	mustRestore(t, s, first.Version, filepath.Join(base, "preserved"), old, false)
}
