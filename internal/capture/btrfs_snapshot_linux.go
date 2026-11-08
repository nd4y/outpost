package capture

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"unsafe"

	"github.com/nd4y/outpost/internal/localfs"
	"golang.org/x/sys/unix"
)

const BtrfsSnapshotMethod = "btrfs-readonly-snapshot-v1"

type btrfsSnapshot struct {
	id, parent string
	created    int64
}

func btrfsUUID(text string) bool {
	raw, err := hex.DecodeString(text)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == text &&
		text != "00000000000000000000000000000000"
}

func inspectBtrfsSnapshot(root *os.Root) (btrfsSnapshot, error) {
	var result btrfsSnapshot
	f, err := localfs.OpenFile(root, ".", os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return result, err
	}
	defer f.Close()
	var inode unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(f.Fd()), &inode) != nil || inode.Ino != 256 ||
		unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.BTRFS_SUPER_MAGIC {
		return result, ErrInvalid
	}

	// Linux btrfs.h UAPI on amd64 and arm64. SUBVOL_GETFLAGS uses the
	// public subvolume flag encoding, distinct from the root item flags
	// returned by GET_SUBVOL_INFO.
	const (
		subvolGetFlags = 0x80089419
		getSubvolInfo  = 0x81f8943c
		subvolReadOnly = 1 << 1
	)
	var flags uint64
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), subvolGetFlags, uintptr(unsafe.Pointer(&flags))); e != 0 || flags&subvolReadOnly == 0 {
		return result, ErrInvalid
	}
	var info [504]byte
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), getSubvolInfo, uintptr(unsafe.Pointer(&info[0]))); e != 0 {
		return result, ErrInvalid
	}
	// generation, uuid, parent_uuid, otransid and otime.sec from
	// struct btrfs_ioctl_get_subvol_info_args.
	generation := binary.NativeEndian.Uint64(info[280:288])
	original := binary.NativeEndian.Uint64(info[352:360])
	created := binary.NativeEndian.Uint64(info[392:400])
	result = btrfsSnapshot{hex.EncodeToString(info[296:312]), hex.EncodeToString(info[312:328]), int64(created)}
	if !btrfsUUID(result.id) || !btrfsUUID(result.parent) || generation == 0 || generation != original || created == 0 || created > 1<<40 {
		return btrfsSnapshot{}, ErrInvalid
	}
	return result, nil
}
