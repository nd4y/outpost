package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
	"golang.org/x/sys/unix"
)

func nativeTestProfile(t *testing.T, source, staging string) (BtrfsProducerProfile, ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	base := teststore.Root(t)
	id := storage.Hash([]byte(t.Name()))
	owner, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	origin := storage.Hash([]byte("native-test-origin"))
	src, err := ProbeTree(ctx, source, origin)
	must(t, err)
	dst, err := ProbeTree(ctx, staging, origin)
	must(t, err)
	observed, err := volume.Probe(ctx, base)
	must(t, err)
	binding, err := volume.Enroll(ctx, base, observed, id, 1)
	must(t, err)
	state := filepath.Join(base, "producer")
	must(t, os.Mkdir(state, 0700))
	return BtrfsProducerProfile{Format: BtrfsProducerFormat, Source: src, Staging: dst, StateVolume: binding,
		StateDirectory: state, Trust: PreparedTrust{Profile: id, Origin: origin, Producer: owner, Method: BtrfsSnapshotMethod,
			SnapshotOrigin: "11111111111111111111111111111111", MaxBytes: 1 << 20, MaxFiles: 10}, MaxRetained: 2}, key
}

func TestNativeBtrfsProducerRejectsOrdinaryTreeBeforeState(t *testing.T) {
	base := teststore.Root(t)
	source, staging := filepath.Join(base, "source"), filepath.Join(base, "staging")
	must(t, os.Mkdir(source, 0700))
	must(t, os.Mkdir(staging, 0700))
	profile, key := nativeTestProfile(t, source, staging)
	if profile.Source.Observed.Filesystem == unix.BTRFS_SUPER_MAGIC {
		t.Skip("requires a non-Btrfs fixture")
	}
	request := BtrfsProducerRequest{Profile: profile, Operation: storage.Hash([]byte("ordinary-source")), Sequence: 1}
	if _, err := ProduceBtrfsExport(context.Background(), request, key); !errors.Is(err, ErrInvalid) {
		t.Fatal("ordinary tree was admitted as a Btrfs source", err)
	}
	for _, path := range []string{staging, profile.StateDirectory} {
		entries, err := os.ReadDir(path)
		must(t, err)
		if len(entries) != 0 {
			t.Fatal("unsupported source caused a write")
		}
	}
}

func TestNativeBtrfsSnapshotCapacityChecksRetainedAndFreeFloor(t *testing.T) {
	staging, err := localfs.OpenRoot(teststore.Root(t))
	must(t, err)
	defer staging.Close()
	fd, err := staging.Open(".")
	must(t, err)
	defer fd.Close()

	profile := BtrfsProducerProfile{MaxRetained: 2}
	first := nativeSnapshotPrefix + storage.Hash([]byte("retained-first"))
	second := nativeSnapshotPrefix + storage.Hash([]byte("retained-second"))
	must(t, staging.Mkdir(first, 0700))
	count, err := checkNativeSnapshotCapacity(staging, fd, profile)
	must(t, err)
	if count != 1 {
		t.Fatalf("retained count = %d, want 1", count)
	}
	blocked := profile
	blocked.MinFreeBytes = ^uint64(0)
	if _, err := checkNativeSnapshotCapacity(staging, fd, blocked); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("volume below requested reserve admitted", err)
	}
	must(t, staging.Mkdir(second, 0700))
	if _, err := checkNativeSnapshotCapacity(staging, fd, profile); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("staging at the retained limit admitted", err)
	}
	for _, name := range []string{first, second} {
		_, err = staging.Stat(name)
		must(t, err)
	}
}

func TestNativeBtrfsSharedStagingSerializesIndependentJournals(t *testing.T) {
	base := teststore.Root(t)
	stagingPath := filepath.Join(base, "staging")
	must(t, os.Mkdir(stagingPath, 0700))
	openProducer := func(name string) (*statefile.Store, *os.File) {
		t.Helper()
		journalPath := filepath.Join(base, name)
		must(t, os.Mkdir(journalPath, 0700))
		journal, err := statefile.Open(journalPath, 4096, false)
		must(t, err)
		t.Cleanup(func() { must(t, journal.Close()) })
		root, err := localfs.OpenRoot(stagingPath)
		must(t, err)
		t.Cleanup(func() { must(t, root.Close()) })
		fd, err := root.Open(".")
		must(t, err)
		t.Cleanup(func() { must(t, fd.Close()) })
		return journal, fd
	}
	firstJournal, firstFD := openProducer("first-journal")
	secondJournal, secondFD := openProducer("second-journal")
	staging, err := localfs.OpenRoot(stagingPath)
	must(t, err)
	defer staging.Close()

	ctx := t.Context()
	profile := BtrfsProducerProfile{MaxRetained: 1}
	n := nativeSnapshotPrefix + storage.Hash([]byte("first-created"))
	must(t, firstJournal.WithLock(ctx, func() error {
		return withNativeStagingLock(ctx, firstFD, func() error {
			journalWait, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			journalEntered := false
			err := secondJournal.WithLock(journalWait, func() error {
				journalEntered = true
				wait, cancel := context.WithTimeout(journalWait, 40*time.Millisecond)
				defer cancel()
				return withNativeStagingLock(wait, secondFD, func() error {
					t.Fatal("independent journal bypassed the shared staging lock")
					return nil
				})
			})
			if !journalEntered || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("wait cancelled in wrong boundary: journal entered = %v, error = %v", journalEntered, err)
			}
			// The first allocation becomes visible before releasing the lock.
			return staging.Mkdir(n, 0700)
		})
	}))

	retry, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = secondJournal.WithLock(retry, func() error {
		return withNativeStagingLock(retry, secondFD, func() error {
			_, err := checkNativeSnapshotCapacity(staging, secondFD, profile)
			return err
		})
	})
	if !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("second producer did not observe the allocated slot after unlock", err)
	}
	entries, err := readNativeDirectory(staging, 2)
	must(t, err)
	if len(entries) != 1 || entries[0].Name() != n {
		t.Fatalf("staging lock created an unexpected entry: %v", entries)
	}
}

func TestNativeBtrfsProducerReusesExactKernelSnapshot(t *testing.T) {
	root := os.Getenv("OUTPOST_BTRFS_ROOT")
	if root == "" {
		t.Skip("isolated Btrfs fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	base, err := os.MkdirTemp(root, "outpost-native-producer-")
	must(t, err)
	parent, err := os.Open(base)
	must(t, err)
	defer parent.Close()
	// BTRFS_IOC_SUBVOL_CREATE_V2, using the same UAPI structure as snapshot creation.
	var args [4096]byte
	copy(args[56:], "source")
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, parent.Fd(), 0x50009418, uintptr(unsafe.Pointer(&args[0]))); e != 0 {
		t.Fatal(e)
	}
	source, staging := filepath.Join(base, "source"), filepath.Join(base, "staging")
	must(t, os.Mkdir(staging, 0700))
	path := filepath.Join(source, "sample")
	original := []byte("original fixture data")
	must(t, os.WriteFile(path, original, 0600))
	sourceFD, err := os.Open(source)
	must(t, err)
	defer sourceFD.Close()
	stageFD, err := os.Open(staging)
	must(t, err)
	defer stageFD.Close()
	stageRoot, err := localfs.OpenRoot(staging)
	must(t, err)
	defer stageRoot.Close()
	profile, key := nativeTestProfile(t, source, staging)
	origin, err := btrfsOriginUUID(sourceFD)
	must(t, err)
	wrong := BtrfsProducerRequest{Profile: profile, Operation: storage.Hash([]byte("wrong-origin")), Sequence: 1}
	if _, err = ProduceBtrfsExport(ctx, wrong, key); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong source UUID was admitted", err)
	}
	profile.Trust.SnapshotOrigin = origin
	request := BtrfsProducerRequest{Profile: profile, Operation: storage.Hash([]byte("first-native")), Sequence: 1}
	name := nativeSnapshotPrefix + request.Operation
	must(t, os.Mkdir(filepath.Join(staging, name), 0700))
	if _, err = ProduceBtrfsExport(ctx, request, key); !errors.Is(err, ErrInvalid) {
		t.Fatal("unrecorded directory was adopted", err)
	}
	must(t, os.Remove(filepath.Join(staging, name)))
	produce := func() []byte {
		t.Helper()
		raw, err := ProduceBtrfsExport(ctx, request, key)
		must(t, err)
		return raw
	}
	if executable := os.Getenv("OUTPOST_BTRFS_CLI"); executable != "" {
		private := teststore.Root(t)
		input, authority, output := filepath.Join(private, "request.json"), filepath.Join(private, "key.json"), filepath.Join(private, "manifest.json")
		raw, err := json.Marshal(request)
		must(t, err)
		must(t, os.WriteFile(input, raw, 0600))
		raw, err = json.Marshal(map[string]any{"privateKey": key})
		must(t, err)
		must(t, os.WriteFile(authority, raw, 0600))
		produce = func() []byte {
			t.Helper()
			receipt, err := exec.CommandContext(ctx, executable, "source-native-btrfs-export", "--input", input, "--key", authority, "--output", output).CombinedOutput()
			if err != nil {
				t.Fatalf("native producer CLI: %v: %s", err, receipt)
			}
			var envelope struct {
				Result struct {
					Operation         string
					ProducerOperation string
				}
			}
			must(t, json.Unmarshal(receipt, &envelope))
			manifest, err := os.ReadFile(output)
			must(t, err)
			if envelope.Result.Operation != storage.Hash(manifest) || envelope.Result.ProducerOperation != request.Operation ||
				bytes.Contains(receipt, []byte(staging)) {
				t.Fatal("wrong or unredacted native producer receipt")
			}
			return manifest
		}
	}
	first := produce()
	manifest, err := VerifyPreparedExport(first, profile.Trust, time.Now())
	must(t, err)
	if manifest.Root != name || manifest.Sequence != 1 || len(manifest.Files) != 1 ||
		manifest.Files[0].SHA256 != storage.Hash(original) {
		t.Fatal("native manifest differs from the captured source")
	}
	file, err := os.OpenFile(filepath.Join(staging, name, "sample"), os.O_WRONLY, 0)
	if file != nil {
		file.Close()
	}
	if !errors.Is(err, unix.EROFS) {
		t.Fatal("snapshot allowed a write", err)
	}
	must(t, os.WriteFile(path, []byte("later live bytes"), 0600))
	repeated := produce()
	if !bytes.Equal(first, repeated) {
		t.Fatal("same operation changed its signed snapshot or manifest")
	}
	view, _, err := OpenPreparedExport(ctx, stageRoot, repeated, profile.Trust, time.Now())
	must(t, err)
	got, err := view.ReadFile("sample")
	must(t, errors.Join(err, view.Close()))
	if !bytes.Equal(got, original) {
		t.Fatal("live changes leaked into the acquired snapshot")
	}
	second := BtrfsProducerRequest{Profile: profile, Operation: storage.Hash([]byte("second-native")), Sequence: 2}
	secondName := nativeSnapshotPrefix + second.Operation
	raw, err := json.Marshal(profile)
	must(t, err)
	journal, err := statefile.Open(profile.StateDirectory, MaxPreparedExport+8192, false)
	must(t, err)
	must(t, journal.WithLock(ctx, func() error {
		return saveNativeRecord(journal, btrfsProducerRecord{Format: btrfsProducerRecordFormat, Binding: storage.Hash(raw),
			Operation: second.Operation, Sequence: 2, Started: time.Now().Unix()}, key)
	}))
	must(t, journal.Close())
	// A prefix entry can fill the retained capacity between journal admission
	// and the first or retried ioctl. It must not cause a new snapshot.
	placeholder := nativeSnapshotPrefix + storage.Hash([]byte("staging-filled-after-admission"))
	must(t, stageRoot.Mkdir(placeholder, 0700))
	if _, err = ProduceBtrfsExport(ctx, second, key); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("pending operation bypassed the retained snapshot limit", err)
	}
	if _, err = stageRoot.Lstat(secondName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capacity refusal published a snapshot", err)
	}
	must(t, stageRoot.Remove(placeholder))
	must(t, createNativeSnapshot(sourceFD, stageFD, secondName))
	secondRoot, err := localfs.OpenAt(stageRoot, secondName, false)
	must(t, err)
	proof, err := inspectBtrfsSnapshot(secondRoot)
	must(t, errors.Join(err, secondRoot.Close()))
	secondRaw, err := ProduceBtrfsExport(ctx, second, key)
	must(t, err)
	secondManifest, err := VerifyPreparedExport(secondRaw, profile.Trust, time.Now())
	must(t, err)
	if secondManifest.SnapshotID != proof.id || secondManifest.SnapshotID == manifest.SnapshotID {
		t.Fatal("native snapshot with lost reply was replaced")
	}
	third := BtrfsProducerRequest{Profile: profile, Operation: storage.Hash([]byte("over-retention")), Sequence: 3}
	if _, err = ProduceBtrfsExport(ctx, third, key); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("producer exceeded the retained snapshot limit", err)
	}
	atLimit, err := ProduceBtrfsExport(ctx, second, key)
	must(t, err)
	if !bytes.Equal(atLimit, secondRaw) {
		t.Fatal("retained limit prevented replay of the existing exact snapshot")
	}
	count, err := countNativeSnapshots(stageRoot)
	must(t, err)
	if count != 2 {
		t.Fatal("unexpected number of physical snapshots", count)
	}
	if os.Getenv("OUTPOST_BTRFS_TEST_RELEASE") == "1" {
		exerciseNativeRemoval(t, ctx, profile, key, first, secondRaw, original)
	}
}
