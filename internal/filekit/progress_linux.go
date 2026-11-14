package filekit

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"sort"
	"strconv"
	"syscall"

	"github.com/nd4y/outpost/internal/statefile"
)

const ProgressFormat = "outpost-capture-progress-1"
const maxProgress = 64 << 20
const maxProgressRecord = 64 << 10

type progressRecord struct {
	Format   string  `json:"format"`
	Sequence uint64  `json:"sequence"`
	Previous string  `json:"previous"`
	Blocks   []Block `json:"blocks"`
}
type captureProgress struct {
	store                                        *Store
	file                                         *os.File
	name, identity, operation, binding, previous string
	sequence                                     uint64
	end                                          int64
	blocks                                       int
}

func progressName(operation, file string) string {
	return "progress/" + digest([]byte(operation+"/"+file))
}
func (p *captureProgress) kind() string {
	return "capture-progress/" + p.operation + "/" + p.binding + "/" + strconv.FormatUint(p.sequence, 10)
}
func validProgressBlock(b Block) bool {
	return validID(b.Hash) && validID(b.Object.ID) && b.Bytes > 0 && b.Bytes <= MaxChunk && b.CipherBytes == b.Bytes+28 && b.Object.Bytes > 0 && b.Object.Bytes <= MaxObject && b.Offset >= 0 && b.Offset <= b.Object.Bytes-b.CipherBytes
}
func (s *Store) openProgress(ctx context.Context, opt BackupOptions, source SourceIdentity, meta Metadata) (*captureProgress, map[string]Block, error) {
	if s.backend == nil || !validID(opt.Progress) || !validID(opt.File) {
		return nil, nil, ErrInvalid
	}
	binding, e := json.Marshal(struct {
		Identity SourceIdentity
		Metadata Metadata
		Names    []string
		Previous string
	}{source, meta, opt.Names, opt.Previous})
	if e != nil {
		return nil, nil, e
	}
	if e = s.root.Mkdir("progress", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return nil, nil, e
	}
	i, e := s.root.Lstat("progress")
	if e != nil {
		return nil, nil, e
	}
	if !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return nil, nil, ErrInvalid
	}
	if e = s.syncDir("."); e != nil {
		return nil, nil, e
	}
	p := &captureProgress{store: s, name: progressName(opt.Progress, opt.File), identity: opt.File, operation: opt.Progress, binding: digest(binding)}
	if _, e = s.root.Lstat(p.name); errors.Is(e, os.ErrNotExist) {
		e = statefile.Guard(s.Admit, p.name, 1, func() error {
			f, e := localfs.OpenFile(s.root, p.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			e = errors.Join(f.Sync(), f.Close())
			if e != nil {
				return e
			}
			return s.syncDir("progress")
		})
		if e != nil {
			return nil, nil, e
		}
	} else if e != nil {
		return nil, nil, e
	}
	p.file, e = localfs.OpenFile(s.root, p.name, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, nil, e
	}
	fail := func(e error) (*captureProgress, map[string]Block, error) { p.file.Close(); return nil, nil, e }
	i, e = p.file.Stat()
	if e != nil {
		return fail(e)
	}
	stat, ok := i.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > maxProgress {
		return fail(ErrInvalid)
	}
	reuse := map[string]Block{}
	for p.end < i.Size() {
		if e = ctx.Err(); e != nil {
			return fail(e)
		}
		var size [4]byte
		_, e = p.file.ReadAt(size[:], p.end)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return fail(e)
		}
		length := int64(binary.BigEndian.Uint32(size[:]))
		if length < 28 || length > maxProgressRecord {
			return fail(ErrInvalid)
		}
		if length > i.Size()-p.end-4 {
			break
		}
		sealed := make([]byte, length)
		if _, e = p.file.ReadAt(sealed, p.end+4); e != nil {
			return fail(e)
		}
		plain, e := s.Owner.open(opt.File, p.kind(), sealed)
		if e != nil {
			return fail(e)
		}
		var record progressRecord
		if decode(plain, &record) != nil || record.Format != ProgressFormat || record.Sequence != p.sequence || record.Previous != p.previous || len(record.Blocks) == 0 || len(record.Blocks) > 64 || p.blocks+len(record.Blocks) > MaxBlocks {
			return fail(ErrInvalid)
		}
		var object Object
		for _, block := range record.Blocks {
			if !validProgressBlock(block) {
				return fail(ErrInvalid)
			}
			if object.ID == "" {
				object = block.Object
			} else if object != block.Object {
				return fail(ErrInvalid)
			}
			if old, ok := reuse[block.Hash]; ok && old != block {
				return fail(ErrInvalid)
			}
			reuse[block.Hash] = block
		}
		p.blocks += len(record.Blocks)
		p.sequence++
		p.previous = digest(sealed)
		p.end += 4 + length
	}
	// A torn final append contains no accepted progress. Dropping only its tail
	// can resend at most that uncheckpointed pack, never invent accepted bytes.
	if p.end < i.Size() {
		if e = p.file.Truncate(p.end); e != nil {
			return fail(e)
		}
	}
	if e = p.file.Sync(); e != nil {
		return fail(e)
	}
	if e = s.syncDir("progress"); e != nil {
		return fail(e)
	}
	return p, reuse, nil
}
func (p *captureProgress) append(ctx context.Context, blocks []Block) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if len(blocks) == 0 || len(blocks) > 64 || p.blocks+len(blocks) > MaxBlocks {
		return ErrInvalid
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].Hash < blocks[j].Hash })
	for _, b := range blocks {
		if !validProgressBlock(b) || b.Object != blocks[0].Object {
			return ErrInvalid
		}
	}
	plain, e := json.Marshal(progressRecord{Format: ProgressFormat, Sequence: p.sequence, Previous: p.previous, Blocks: blocks})
	if e != nil {
		return e
	}
	sealed, e := p.store.Owner.seal(p.identity, p.kind(), plain)
	if e != nil {
		return e
	}
	if len(sealed) > maxProgressRecord || p.end+4+int64(len(sealed)) > maxProgress {
		return statefile.ErrCapacity
	}
	frame := make([]byte, 4+len(sealed))
	binary.BigEndian.PutUint32(frame, uint32(len(sealed)))
	copy(frame[4:], sealed)
	e = statefile.Guard(p.store.Admit, p.name, int(p.end)+len(frame), func() error {
		n, e := p.file.WriteAt(frame, p.end)
		if e != nil {
			return e
		}
		if n != len(frame) {
			return io.ErrShortWrite
		}
		return p.file.Sync()
	})
	if e != nil {
		return e
	}
	p.end += int64(len(frame))
	p.blocks += len(blocks)
	p.sequence++
	p.previous = digest(sealed)
	return p.store.checkpoint("capture-progress-durable")
}

func (s *Store) reusePreviousProgress(ctx context.Context, opt BackupOptions, observed SourceIdentity, meta Metadata, reuse, current map[string]Block) error {
	opt.Progress = opt.PreviousProgress
	if _, err := s.root.Lstat(progressName(opt.Progress, opt.File)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	old, accepted, err := s.openProgress(ctx, opt, observed, meta)
	if err != nil {
		return err
	}
	if err = old.file.Close(); err != nil {
		return err
	}
	checked := make(map[string]bool)
	for hash, block := range accepted {
		if _, ok := current[hash]; ok {
			continue
		}
		if _, ok := checked[block.Object.ID]; !ok {
			err = s.checkObjectContext(ctx, block.Object)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			checked[block.Object.ID] = err == nil
		}
		if checked[block.Object.ID] {
			reuse[hash] = block
		}
	}
	return nil
}

// DiscardCaptureProgress is a source-journal transition after durable receipt
// and provider release. It removes local resume metadata only, never payload.
// Remote maintenance is still owned by the receiving replica.
func (s *Store) DiscardCaptureProgress(ctx context.Context, operation, file string) error {
	if s.backend == nil || !validID(operation) || !validID(file) {
		return ErrInvalid
	}
	unlock, e := s.lock(ctx, true)
	if e != nil {
		return e
	}
	defer unlock()
	name := progressName(operation, file)
	i, e := s.root.Lstat(name)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > maxProgress {
		return ErrInvalid
	}
	if e = s.root.Remove(name); e != nil {
		return e
	}
	return s.syncDir("progress")
}
