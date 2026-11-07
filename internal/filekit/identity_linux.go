package filekit

import (
	"golang.org/x/sys/unix"
	"os"
)

// SourceIdentity is a local scan checkpoint. It is never sent to ordinary nodes.
// Atime is intentionally absent because reading the source can update it.
type SourceIdentity struct {
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	Links    uint64 `json:"links"`
	Mode     uint32 `json:"mode"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Size     int64  `json:"size"`
	MtimeSec int64  `json:"mtimeSec"`
	MtimeNS  int64  `json:"mtimeNs"`
	CtimeSec int64  `json:"ctimeSec"`
	CtimeNS  int64  `json:"ctimeNs"`
}

func identity(s unix.Stat_t) SourceIdentity {
	return SourceIdentity{s.Dev, s.Ino, uint64(s.Nlink), s.Mode, s.Uid, s.Gid, s.Size, s.Mtim.Sec, s.Mtim.Nsec, s.Ctim.Sec, s.Ctim.Nsec}
}
func (i SourceIdentity) Kind() string {
	switch i.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "regular"
	case unix.S_IFDIR:
		return "directory"
	case unix.S_IFLNK:
		return "symlink"
	default:
		return "unsupported"
	}
}
func InspectEntry(root *os.Root, relative string) (SourceIdentity, error) {
	p, n, e := rootedParent(root, relative)
	if e != nil {
		return SourceIdentity{}, e
	}
	defer p.Close()
	var st unix.Stat_t
	e = unix.Fstatat(int(p.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW)
	return identity(st), e
}
