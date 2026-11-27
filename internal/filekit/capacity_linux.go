package filekit

import (
	"os"

	"github.com/nd4y/outpost/internal/statefile"
	"golang.org/x/sys/unix"
)

type RepackOptions struct {
	MinFreeBytes uint64
}

type allocationSpace struct {
	unit      uint64
	available uint64
}

type allocationPeak struct {
	unit   uint64
	blocks uint64
}

func readAllocationSpace(directory *os.File) (allocationSpace, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &st); err != nil {
		return allocationSpace{}, err
	}
	unit := st.Frsize
	if unit == 0 {
		unit = st.Bsize
	}
	if unit <= 0 || st.Bavail > st.Blocks {
		return allocationSpace{}, ErrInvalid
	}
	return allocationSpace{unit: uint64(unit), available: st.Bavail}, nil
}

func allocationBlocksForBytes(bytes, unit uint64) uint64 {
	if bytes == 0 {
		return 0
	}
	return (bytes-1)/unit + 1
}

func (p *allocationPeak) add(size int) error {
	// Charge rounded file data and a block of namespace overhead. A pack
	// stages a single inode and links it into place without copying it.
	return p.addBlocks(allocationBlocksForBytes(uint64(size), p.unit) + 1)
}

func (p *allocationPeak) addBlocks(blocks uint64) error {
	if p.blocks > ^uint64(0)-blocks {
		return statefile.ErrCapacity
	}
	p.blocks += blocks
	return nil
}

func (p *allocationPeak) addRepackVersion(envelope Envelope, descriptor Descriptor) error {
	size := 0
	for _, part := range envelope.Parts {
		size += part.Bytes
	}
	// Repack changes only the pack ID and the decimal offset and pack size.
	// IDs keep their encoded length; each integer has at most seven digits.
	const locationGrowth = 2 * (7 - 1)
	size = min(MaxDescriptor+28, size+locationGrowth*len(descriptor.Blocks))
	for size > 0 {
		part := min(size, DescriptorPart)
		if err := p.add(part); err != nil {
			return err
		}
		size -= part
	}
	// Charge each new root in full. Previously allocated roots are already
	// included in the observed usage and may overlap atomic replacements.
	return p.add(MaxRoot)
}

func (p allocationPeak) admit(space allocationSpace, reserve uint64) error {
	if space.unit != p.unit {
		return ErrInvalid
	}
	floor := allocationBlocksForBytes(reserve, space.unit)
	if space.available < floor || space.available-floor < p.blocks {
		return statefile.ErrCapacity
	}
	return nil
}
