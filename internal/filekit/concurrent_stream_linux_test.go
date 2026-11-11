package filekit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type reorderedSink struct {
	*objectSink
	payloads           atomic.Int32
	laterAcceptedBytes atomic.Int64
	release            chan struct{}
	once               sync.Once
	releaseOnThird     bool
}

func (b *reorderedSink) ParallelWrites() int { return 2 }
func (b *reorderedSink) releaseFirst()       { b.once.Do(func() { close(b.release) }) }
func (b *reorderedSink) Write(ctx context.Context, ref Object, data []byte) (bool, error) {
	if ref.Bytes < 256<<10 {
		return b.objectSink.Write(ctx, ref, data)
	}
	index := b.payloads.Add(1)
	if index == 1 {
		select {
		case <-b.release:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	if index == 3 && b.releaseOnThird {
		b.releaseFirst()
	}
	created, err := b.objectSink.Write(ctx, ref, data)
	if index > 1 && created && err == nil {
		b.laterAcceptedBytes.Add(int64(ref.Bytes))
	}
	return created, err
}

func TestConcurrentStreamingReusesCompletedSlotBeforeOldestWrite(t *testing.T) {
	base, local, input, want := fixture(t, 24<<20)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	sink := &reorderedSink{objectSink: &objectSink{objects: map[string][]byte{}}, release: make(chan struct{}), releaseOnThird: true}
	t.Cleanup(sink.releaseFirst)
	s, err := OpenStreamingStore(filepath.Join(base, "concurrent-cache"), local.Owner, true, sink)
	entryOK(t, err)
	defer s.Close()
	stats, err := s.Backup(ctx, input, BackupOptions{File: randomID(), Progress: randomID(), Names: []string{"payload"}})
	entryOK(t, err)
	if sink.payloads.Load() < 3 || stats.SourceBytes != int64(len(want)) {
		t.Fatal("write window did not advance with one older write still pending")
	}
	mustRestore(t, s, stats.Version, filepath.Join(base, "restored"), want, false)
}

func TestConcurrentStreamingCheckpointsLaterAcceptanceBeforeCancellation(t *testing.T) {
	base, local, input, want := fixture(t, 24<<20)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	sink := &reorderedSink{objectSink: &objectSink{objects: map[string][]byte{}}, release: make(chan struct{})}
	t.Cleanup(sink.releaseFirst)
	cache := filepath.Join(base, "concurrent-resume-cache")
	s, err := OpenStreamingStore(cache, local.Owner, true, sink)
	entryOK(t, err)
	stopped := errors.New("stop after a later durable acceptance")
	s.Fault = func(point string) error {
		if point == "capture-progress-durable" {
			return stopped
		}
		return nil
	}
	opt := BackupOptions{File: randomID(), Progress: randomID(), Names: []string{"payload"}}
	if _, err = s.Backup(ctx, input, opt); !errors.Is(err, stopped) {
		t.Fatalf("later acceptance was not checkpointed independently: %v", err)
	}
	accepted := sink.laterAcceptedBytes.Load()
	if accepted < 256<<10 || accepted > MaxObject {
		t.Fatal("unexpected later accepted payload", accepted)
	}
	entries, err := os.ReadDir(filepath.Join(cache, "versions"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("descriptor published while the first write was unconfirmed")
	}
	entryOK(t, s.Close())
	s, err = OpenStreamingStore(cache, local.Owner, false, sink)
	entryOK(t, err)
	defer s.Close()
	stats, err := s.Backup(ctx, input, opt)
	entryOK(t, err)
	if stats.SourceBytes != int64(len(want)) || stats.NewPayloadBytes+accepted > int64(len(want))+(64<<10) {
		t.Fatal("confirmed later pack was resent or source reads hidden", stats, accepted)
	}
	mustRestore(t, s, stats.Version, filepath.Join(base, "resumed-restored"), want, false)
}
