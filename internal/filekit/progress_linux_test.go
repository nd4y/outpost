package filekit

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/statefile"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestEncryptedCaptureProgressResumesAcceptedPacksAndTornTail(t *testing.T) {
	base, local, input, want := fixture(t, 16<<20)
	ctx := context.Background()
	sink := &objectSink{objects: map[string][]byte{}}
	cache := filepath.Join(base, "resume-cache")
	s, e := OpenStreamingStore(cache, local.Owner, true, sink)
	entryOK(t, e)
	opt := BackupOptions{File: randomID(), Progress: randomID(), Names: []string{"confidential-progress-name"}}
	s.Fault = func(name string) error {
		if name == "capture-progress-durable" {
			return errors.New("interrupted capture")
		}
		return nil
	}
	if _, e = s.Backup(ctx, input, opt); e == nil {
		t.Fatal("fault absent")
	}
	accepted := sink.writtenBytes
	if accepted < 4<<20 || accepted > MaxObject {
		t.Fatal("unexpected accepted pack", accepted)
	}
	entryOK(t, s.Close())
	logPath := filepath.Join(cache, progressName(opt.Progress, opt.File))
	raw, e := os.ReadFile(logPath)
	entryOK(t, e)
	if len(raw) > maxProgressRecord+4 || bytes.Contains(raw, []byte(opt.Names[0])) || bytes.Contains(raw, []byte(digest(want[:256<<10]))) {
		t.Fatal("resume metadata exposed or unbounded")
	}
	f, e := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	entryOK(t, e)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], 200)
	_, e = f.Write(append(size[:], []byte("partial ciphertext")...))
	entryOK(t, e)
	entryOK(t, f.Close())
	s, e = OpenStreamingStore(cache, local.Owner, false, sink)
	entryOK(t, e)
	defer s.Close()
	stats, e := s.Backup(ctx, input, opt)
	entryOK(t, e)
	if stats.SourceBytes != int64(len(want)) || stats.NewPayloadBytes+accepted > int64(len(want))+4096 {
		t.Fatal("accepted data resent or source reads hidden", stats, accepted)
	}
	mustRestore(t, s, stats.Version, filepath.Join(base, "resumed"), want, false)
	entryOK(t, s.DiscardCaptureProgress(ctx, opt.Progress, opt.File))
	entryOK(t, s.DiscardCaptureProgress(ctx, opt.Progress, opt.File))
	if _, e = os.Stat(logPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("progress retained", e)
	}
	mustRestore(t, s, stats.Version, filepath.Join(base, "after-discard"), want, false)
}

func TestCaptureProgressRejectsTamperingRebindingAndLocalGCMode(t *testing.T) {
	base, local, input, _ := fixture(t, 12<<20)
	ctx := context.Background()
	sink := &objectSink{objects: map[string][]byte{}}
	cache := filepath.Join(base, "progress-private")
	s, e := OpenStreamingStore(cache, local.Owner, true, sink)
	entryOK(t, e)
	defer s.Close()
	opt := BackupOptions{File: randomID(), Progress: randomID(), Names: []string{"data"}}
	s.Fault = func(name string) error {
		if name == "capture-progress-durable" {
			return errors.New("stop")
		}
		return nil
	}
	if _, e = s.Backup(ctx, input, opt); e == nil {
		t.Fatal("fault absent")
	}
	s.Fault = nil
	path := filepath.Join(cache, progressName(opt.Progress, opt.File))
	raw, e := os.ReadFile(path)
	entryOK(t, e)
	corrupt := bytes.Clone(raw)
	corrupt[len(corrupt)-1] ^= 1
	entryOK(t, os.WriteFile(path, corrupt, 0600))
	before := sink.writes
	if _, e = s.Backup(ctx, input, opt); e == nil {
		t.Fatal("authenticated corruption resumed")
	}
	entryOK(t, os.WriteFile(path, raw, 0600))
	changed := opt
	changed.Names = []string{"other"}
	if _, e = s.Backup(ctx, input, changed); e == nil {
		t.Fatal("progress rebound to different capture options")
	}
	if sink.writes != before {
		t.Fatal("invalid progress sent payload")
	}
	if _, e = local.Backup(ctx, input, opt); !errors.Is(e, ErrInvalid) {
		t.Fatal("local GC store accepted unrooted partial objects", e)
	}
	if e = local.DiscardCaptureProgress(ctx, opt.Progress, opt.File); !errors.Is(e, ErrInvalid) {
		t.Fatal("local mode cleanup allowed", e)
	}
	missing := opt
	missing.File = ""
	if _, e = s.Backup(ctx, input, missing); !errors.Is(e, ErrInvalid) {
		t.Fatal("unstable file identity accepted", e)
	}
}

type durableSink struct{ store *statefile.Store }

func (s durableSink) Read(ctx context.Context, o Object) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	b, e := s.store.Read(o.ID)
	if e == nil && (len(b) != o.Bytes || digest(b) != o.ID) {
		return nil, ErrInvalid
	}
	return b, e
}
func (s durableSink) Check(ctx context.Context, o Object) error { _, e := s.Read(ctx, o); return e }
func (s durableSink) Write(ctx context.Context, o Object, b []byte) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	if len(b) != o.Bytes || digest(b) != o.ID {
		return false, ErrInvalid
	}
	old, e := s.store.Read(o.ID)
	if e == nil {
		if !bytes.Equal(old, b) {
			return false, ErrInvalid
		}
		return false, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	return true, s.store.Write(o.ID, b)
}

type progressCrashFixture struct {
	Owner              Owner
	Options            BackupOptions
	Input, Cache, Sink string
}

func TestProgressCrashChild(t *testing.T) {
	if os.Getenv("OUTPOST_PROGRESS_CHILD") != "1" {
		return
	}
	raw, e := os.ReadFile(os.Getenv("OUTPOST_PROGRESS_FIXTURE"))
	entryOK(t, e)
	var f progressCrashFixture
	entryOK(t, json.Unmarshal(raw, &f))
	dest, e := statefile.Open(f.Sink, MaxObject, false)
	entryOK(t, e)
	defer dest.Close()
	s, e := OpenStreamingStore(f.Cache, f.Owner, false, durableSink{dest})
	entryOK(t, e)
	defer s.Close()
	s.Fault = func(name string) error {
		if name == "capture-progress-durable" {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	_, e = s.Backup(context.Background(), f.Input, f.Options)
	entryOK(t, e)
	t.Fatal("kill absent")
}
func TestCaptureProgressSIGKILLReusesDurablyAcceptedPack(t *testing.T) {
	base, local, input, want := fixture(t, 16<<20)
	ctx := context.Background()
	f := progressCrashFixture{Owner: local.Owner, Options: BackupOptions{File: randomID(), Progress: randomID(), Names: []string{"data"}}, Input: input, Cache: filepath.Join(base, "source-cache"), Sink: filepath.Join(base, "durable-sink")}
	dest, e := statefile.Open(f.Sink, MaxObject, true)
	entryOK(t, e)
	defer dest.Close()
	s, e := OpenStreamingStore(f.Cache, f.Owner, true, durableSink{dest})
	entryOK(t, e)
	entryOK(t, s.Close())
	raw, e := json.Marshal(f)
	entryOK(t, e)
	fixturePath := filepath.Join(base, "progress-child.json")
	entryOK(t, os.WriteFile(fixturePath, raw, 0600))
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestProgressCrashChild$", "-test.v")
	command.Env = append(os.Environ(), "OUTPOST_PROGRESS_CHILD=1", "OUTPOST_PROGRESS_FIXTURE="+fixturePath)
	output, e := command.CombinedOutput()
	exit, ok := e.(*exec.ExitError)
	if !ok || bounded.Err() != nil {
		t.Fatalf("not bounded SIGKILL: %v %s", e, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || status.Signal() != syscall.SIGKILL {
		t.Fatalf("not SIGKILL: %v %s", e, output)
	}
	entries, e := os.ReadDir(f.Sink)
	entryOK(t, e)
	var accepted int64
	for _, entry := range entries {
		if validID(entry.Name()) {
			i, e := entry.Info()
			entryOK(t, e)
			accepted += i.Size()
		}
	}
	if accepted < 4<<20 || accepted > MaxObject {
		t.Fatal("no accepted pack", accepted)
	}
	s, e = OpenStreamingStore(f.Cache, f.Owner, false, durableSink{dest})
	entryOK(t, e)
	defer s.Close()
	stats, e := s.Backup(ctx, f.Input, f.Options)
	entryOK(t, e)
	if stats.NewPayloadBytes+accepted > int64(len(want))+4096 {
		t.Fatal("accepted pack resent after SIGKILL", stats, accepted)
	}
	mustRestore(t, s, stats.Version, filepath.Join(base, "after-kill"), want, false)
}
