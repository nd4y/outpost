package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
	"golang.org/x/sys/unix"
)

const BtrfsProducerFormat = "outpost-btrfs-producer-1"
const btrfsProducerRecordFormat = "outpost-btrfs-producer-record-1"
const btrfsProducerRecordName = "snapshot.json"
const nativeSnapshotPrefix = "outpost-native-"

type BtrfsProducerProfile struct {
	Format         string         `json:"format"`
	Source         TreeBinding    `json:"source"`
	Staging        TreeBinding    `json:"staging"`
	StateVolume    volume.Binding `json:"stateVolume"`
	StateDirectory string         `json:"stateDirectory"`
	Trust          PreparedTrust  `json:"trust"`
	MaxRetained    int            `json:"maxRetained"`
}

type BtrfsProducerRequest struct {
	Profile   BtrfsProducerProfile `json:"profile"`
	Operation string               `json:"operationId"`
	Sequence  uint64               `json:"sequence"`
}

type btrfsProducerRecord struct {
	Format    string          `json:"format"`
	Binding   string          `json:"binding"`
	Operation string          `json:"operationId"`
	Sequence  uint64          `json:"sequence"`
	Started   int64           `json:"startedUnix"`
	Snapshot  string          `json:"snapshot,omitempty"`
	Manifest  json.RawMessage `json:"manifest,omitempty"`
	Signature []byte          `json:"signature,omitempty"`
}

func checkNativeTree(ctx context.Context, root *os.Root, tree TreeBinding) error {
	current, err := volume.InspectRoot(ctx, root)
	if err != nil {
		return err
	}
	expected := tree.Observed
	if tree.Format != TreeFormat || !storage.ID(tree.Origin) || !filepath.IsAbs(tree.Path) ||
		filepath.Clean(tree.Path) != tree.Path || current.Filesystem != unix.BTRFS_SUPER_MAGIC ||
		current.Filesystem != expected.Filesystem || current.FSID != expected.FSID ||
		current.RootInode != expected.RootInode || current.ReadOnly != expected.ReadOnly {
		return ErrInvalid
	}
	pathRoot, err := localfs.OpenRoot(tree.Path)
	if err != nil {
		return err
	}
	defer pathRoot.Close()
	a, err := pathRoot.Stat(".")
	if err != nil {
		return err
	}
	b, err := root.Stat(".")
	if err != nil || !os.SameFile(a, b) {
		return ErrInvalid
	}
	return ctx.Err()
}

func btrfsFilesystemID(f *os.File) ([16]byte, error) {
	var id [16]byte
	var info [1024]byte
	const fsInfo = 0x8400941f
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), fsInfo, uintptr(unsafe.Pointer(&info[0]))); e != 0 {
		return id, e
	}
	copy(id[:], info[16:32])
	if id == [16]byte{} {
		return id, ErrInvalid
	}
	return id, nil
}

func btrfsOriginUUID(f *os.File) (string, error) {
	var inode unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &inode); e != nil || inode.Ino != 256 {
		return "", ErrInvalid
	}
	var info [504]byte
	const getSubvolInfo = 0x81f8943c
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), getSubvolInfo, uintptr(unsafe.Pointer(&info[0]))); e != 0 {
		return "", e
	}
	id := hex.EncodeToString(info[296:312])
	if !btrfsUUID(id) {
		return "", ErrInvalid
	}
	return id, nil
}

func createNativeSnapshot(source, destination *os.File, name string) error {
	const snapshotCreateV2 = 0x50009417
	const readOnly = 1 << 1
	// Linux btrfs_ioctl_vol_args_v2. The descriptor and flags use native
	// byte order. The name union begins after the four reserved u64 fields.
	var args [4096]byte
	binary.NativeEndian.PutUint64(args[:8], uint64(source.Fd()))
	binary.NativeEndian.PutUint64(args[16:24], readOnly)
	copy(args[56:], name)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, destination.Fd(), snapshotCreateV2, uintptr(unsafe.Pointer(&args[0]))); e != 0 {
		return e
	}
	return nil
}

func readNativeDirectory(root *os.Root, limit int) ([]os.DirEntry, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, statefile.ErrCapacity
	}
	return entries, nil
}

func countNativeSnapshots(root *os.Root) (int, error) {
	entries, err := readNativeDirectory(root, 4096)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), nativeSnapshotPrefix) {
			count++
		}
	}
	return count, nil
}

func loadNativeRecord(store *statefile.Store, binding string, pub ed25519.PublicKey, now int64) (btrfsProducerRecord, error) {
	var r btrfsProducerRecord
	raw, err := store.Read(btrfsProducerRecordName)
	if err != nil {
		return r, err
	}
	if storage.Decode(raw, &r, MaxPreparedExport+8192) != nil || r.Format != btrfsProducerRecordFormat ||
		r.Binding != binding || !storage.ID(r.Operation) || r.Sequence == 0 || r.Started < 1 || r.Started > now ||
		(r.Snapshot != "" && !btrfsUUID(r.Snapshot)) || (len(r.Manifest) > 0 && r.Snapshot == "") {
		return r, ErrInvalid
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return r, ErrInvalid
	}
	signature := r.Signature
	r.Signature = nil
	body, err := json.Marshal(r)
	if err != nil || !ed25519.Verify(pub, append([]byte(btrfsProducerRecordFormat+"\x00"), body...), signature) {
		return r, ErrInvalid
	}
	return r, nil
}

func saveNativeRecord(store *statefile.Store, r btrfsProducerRecord, key ed25519.PrivateKey) error {
	r.Signature = nil
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	r.Signature = ed25519.Sign(key, append([]byte(btrfsProducerRecordFormat+"\x00"), body...))
	body, err = json.Marshal(r)
	if err != nil {
		return err
	}
	return store.Write(btrfsProducerRecordName, body)
}

// ProduceBtrfsExport creates or reopens the exact snapshot of a locally admitted
// operation, then returns the existing signed prepared-export format.
func ProduceBtrfsExport(ctx context.Context, request BtrfsProducerRequest, key ed25519.PrivateKey) ([]byte, error) {
	p := request.Profile
	if p.Format != BtrfsProducerFormat || p.Trust.Validate() != nil || p.Trust.Method != BtrfsSnapshotMethod ||
		p.Trust.Consistency() != "filesystem" || p.Source.Origin != p.Trust.Origin || p.Staging.Origin != p.Trust.Origin ||
		p.Staging.Observed.ReadOnly || !storage.ID(request.Operation) || request.Sequence == 0 ||
		p.MaxRetained < 1 || p.MaxRetained > 16 || p.StateVolume.Scope != p.Trust.Profile ||
		len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) ||
		!bytes.Equal(key.Public().(ed25519.PublicKey), p.Trust.Producer) {
		return nil, ErrInvalid
	}
	source, err := localfs.OpenRoot(p.Source.Path)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	staging, err := localfs.OpenRoot(p.Staging.Path)
	if err != nil {
		return nil, err
	}
	defer staging.Close()
	stateRoot, err := p.StateVolume.Open(ctx, p.StateDirectory, false)
	if err != nil {
		return nil, err
	}
	defer stateRoot.Close()
	for _, roots := range [][2]*os.Root{{source, staging}, {source, stateRoot}, {staging, stateRoot}} {
		if err = localfs.Disjoint(ctx, roots[0], roots[1]); err != nil {
			return nil, err
		}
	}
	guard := func() error {
		if err := checkNativeTree(ctx, source, p.Source); err != nil {
			return err
		}
		if err := checkNativeTree(ctx, staging, p.Staging); err != nil {
			return err
		}
		return p.StateVolume.CheckHandle(ctx, p.StateDirectory, stateRoot)
	}
	if err = guard(); err != nil {
		return nil, err
	}
	src, err := source.Open(".")
	if err != nil {
		return nil, err
	}
	defer src.Close()
	dst, err := staging.Open(".")
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	sourceFS, err := btrfsFilesystemID(src)
	if err != nil {
		return nil, err
	}
	stagingFS, err := btrfsFilesystemID(dst)
	if err != nil || sourceFS != stagingFS {
		return nil, ErrInvalid
	}
	origin, err := btrfsOriginUUID(src)
	if err != nil || origin != p.Trust.SnapshotOrigin {
		return nil, ErrInvalid
	}
	store, err := statefile.OpenAt(stateRoot, ".", MaxPreparedExport+8192, false)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	profile, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	binding := storage.Hash(profile)
	name := nativeSnapshotPrefix + request.Operation
	var manifest []byte
	err = store.WithLock(ctx, func() error {
		write := func(r btrfsProducerRecord) error {
			if err := guard(); err != nil {
				return err
			}
			if _, err := readNativeDirectory(stateRoot, 8); err != nil {
				return err
			}
			return saveNativeRecord(store, r, key)
		}
		now := time.Now().Unix()
		r, err := loadNativeRecord(store, binding, p.Trust.Producer, now)
		if errors.Is(err, os.ErrNotExist) || err == nil && r.Operation != request.Operation {
			if err == nil && (len(r.Manifest) == 0 || r.Sequence == ^uint64(0) || request.Sequence != r.Sequence+1) {
				return ErrInvalid
			}
			if _, err = staging.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return ErrInvalid
			}
			count, err := countNativeSnapshots(staging)
			if err != nil {
				return err
			}
			if count >= p.MaxRetained {
				return statefile.ErrCapacity
			}
			if r.Operation == "" && (count != 0 || request.Sequence != 1) {
				return ErrInvalid
			}
			r = btrfsProducerRecord{Format: btrfsProducerRecordFormat, Binding: binding, Operation: request.Operation, Sequence: request.Sequence, Started: now}
			if err = write(r); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if r.Sequence != request.Sequence {
			return ErrInvalid
		}
		if _, err = staging.Lstat(name); errors.Is(err, os.ErrNotExist) && r.Snapshot == "" {
			if err = guard(); err != nil {
				return err
			}
			if err = createNativeSnapshot(src, dst, name); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		snapshot, err := localfs.OpenAt(staging, name, false)
		if err != nil {
			return err
		}
		proof, err := inspectBtrfsSnapshot(snapshot)
		snapshot.Close()
		if err != nil || proof.parent != origin || proof.created < r.Started ||
			(r.Snapshot != "" && r.Snapshot != proof.id) {
			return ErrInvalid
		}
		if len(r.Manifest) != 0 {
			m, err := VerifyPreparedExport(r.Manifest, p.Trust, time.Now())
			if err != nil || m.Root != name || m.Sequence != request.Sequence || m.SnapshotID != proof.id || m.SnapshotUnix != proof.created {
				return ErrInvalid
			}
			manifest = bytes.Clone(r.Manifest)
			return guard()
		}
		if r.Snapshot == "" {
			if err = dst.Sync(); err != nil {
				return err
			}
			r.Snapshot = proof.id
			if err = write(r); err != nil {
				return err
			}
		}
		completed := time.Now()
		r.Manifest, err = CreatePreparedExport(ctx, staging, p.Trust, PreparedClaim{
			Sequence: r.Sequence, Root: name, SnapshotUnix: proof.created, CompletedUnix: completed.Unix(),
		}, key, completed)
		if err != nil {
			return err
		}
		if err = write(r); err != nil {
			return err
		}
		manifest = bytes.Clone(r.Manifest)
		return guard()
	})
	return manifest, err
}
