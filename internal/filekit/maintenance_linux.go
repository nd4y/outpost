package filekit

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"
)

type MaintenanceStats struct {
	Stats                  Stats `json:"io"`
	OldPayloadObjects      int   `json:"oldPayloadObjects"`
	NewPayloadObjects      int   `json:"newPayloadObjects"`
	PayloadObjectsReplaced int   `json:"payloadObjectsReplaced"`
	GarbageObjectsRemoved  int   `json:"garbageObjectsRemoved"`
	RetiredVersions        int   `json:"retiredVersions"`
}

func (s *Store) versions() ([]string, error) {
	f, err := s.root.Open("versions")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(4097)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 4096 {
		return nil, ErrInvalid
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		n := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(n, ".json") || !validID(strings.TrimSuffix(n, ".json")) {
			return nil, ErrInvalid
		}
		ids = append(ids, strings.TrimSuffix(n, ".json"))
	}
	sort.Strings(ids)
	return ids, nil
}

func (s *Store) objectInventory() (map[string]int64, error) {
	f, err := s.root.Open("objects")
	if err != nil {
		return nil, err
	}
	dirs, err := f.ReadDir(257)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(dirs) > 256 {
		return nil, ErrInvalid
	}
	objects := map[string]int64{}
	for _, dir := range dirs {
		if !dir.IsDir() || len(dir.Name()) != 2 || !validID(dir.Name()+strings.Repeat("0", 62)) {
			return nil, ErrInvalid
		}
		f, err = s.root.Open("objects/" + dir.Name())
		if err != nil {
			return nil, err
		}
		entries, err := f.ReadDir(MaxBlocks*2 + 1)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || !validID(e.Name()) || !strings.HasPrefix(e.Name(), dir.Name()) {
				return nil, ErrInvalid
			}
			info, err := e.Info()
			if err != nil {
				return nil, err
			}
			if info.Size() < 1 || info.Size() > MaxObject {
				return nil, ErrInvalid
			}
			objects[e.Name()] = info.Size()
			if len(objects) > MaxBlocks*2 {
				return nil, ErrInvalid
			}
		}
	}
	return objects, nil
}

// gcLocked verifies every current descriptor and refuses unknown or missing
// references. Independent exported kits own separate physical dependencies.
func (s *Store) gcLocked(ctx context.Context) (int, error) {
	versions, err := s.versions()
	if err != nil {
		return 0, err
	}
	keep := map[string]Object{}
	for _, id := range versions {
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		e, d, err := s.LoadVersionContext(ctx, id)
		if err != nil {
			return 0, err
		}
		refs, err := dependencies(e, d)
		if err != nil {
			return 0, err
		}
		for k, v := range refs {
			if old, ok := keep[k]; ok && old != v {
				return 0, ErrInvalid
			}
			keep[k] = v
		}
		if len(keep) > MaxBlocks*2 {
			return 0, ErrInvalid
		}
	}
	objects, err := s.objectInventory()
	if err != nil {
		return 0, err
	}
	for id, ref := range keep {
		if objects[id] != int64(ref.Bytes) {
			return 0, ErrInvalid
		}
	}
	removed := 0
	dirty := map[string]bool{}
	for id := range objects {
		if _, ok := keep[id]; ok {
			continue
		}
		if err = ctx.Err(); err != nil {
			return removed, err
		}
		if err = s.root.Remove(objectPath(id)); err != nil {
			return removed, err
		}
		removed++
		dirty["objects/"+id[:2]] = true
		if err = s.checkpoint("gc-object-removed"); err != nil {
			return removed, err
		}
	}
	for dir := range dirty {
		if err = s.syncDir(dir); err != nil {
			return removed, err
		}
	}
	return removed, s.checkpoint("gc-durable")
}

func (s *Store) GC(ctx context.Context) (int, error) {
	if s.backend != nil {
		return 0, ErrRemoteMaintenance
	}
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return 0, err
	}
	defer unlock()
	return s.gcLocked(ctx)
}

func (s *Store) Retire(ctx context.Context, ids []string) (MaintenanceStats, error) {
	var result MaintenanceStats
	if s.backend != nil {
		return result, ErrRemoteMaintenance
	}
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return result, err
	}
	defer unlock()
	s.Stats = Stats{}
	if len(ids) > 4096 {
		return result, ErrInvalid
	}
	seen := map[string]bool{}
	// Validate the complete retained inventory before changing any descriptor.
	versions, err := s.versions()
	if err != nil {
		return result, err
	}
	for _, id := range versions {
		if _, _, err = s.LoadVersionContext(ctx, id); err != nil {
			return result, err
		}
	}
	for _, id := range ids {
		if !validID(id) || seen[id] {
			return result, ErrInvalid
		}
		seen[id] = true
		if _, _, err = s.LoadVersionContext(ctx, id); err != nil {
			return result, err
		}
	}
	for _, id := range ids {
		if err = s.root.Remove("versions/" + id + ".json"); err != nil {
			return result, err
		}
		if err = s.syncDir("versions"); err != nil {
			return result, err
		}
		result.RetiredVersions++
		if err = s.checkpoint("retire-unpublished"); err != nil {
			return result, err
		}
	}
	result.GarbageObjectsRemoved, err = s.gcLocked(ctx)
	result.Stats = s.Stats
	return result, err
}

// Repack reads each old pack once per file and concatenates existing AEAD
// records into new bounded objects. All retained logical versions keep their
// identities. Old objects are collected only after all roots are durable.
func (s *Store) Repack(ctx context.Context) (MaintenanceStats, error) {
	var result MaintenanceStats
	if s.backend != nil {
		return result, ErrRemoteMaintenance
	}
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return result, err
	}
	defer unlock()
	s.Stats = Stats{}
	versions, err := s.versions()
	if err != nil {
		return result, err
	}
	byFile := map[string][]string{}
	oldPayload := map[string]bool{}
	for _, id := range versions {
		_, d, e := s.LoadVersionContext(ctx, id)
		if e != nil {
			return result, e
		}
		byFile[d.File] = append(byFile[d.File], id)
		for _, b := range d.Blocks {
			oldPayload[b.Object.ID] = true
		}
		if len(oldPayload) > MaxBlocks*2 {
			return result, ErrInvalid
		}
	}
	result.OldPayloadObjects = len(oldPayload)
	newPayload := map[string]bool{}
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		unique := map[string]Block{}
		for _, id := range byFile[file] {
			_, d, e := s.LoadVersionContext(ctx, id)
			if e != nil {
				return result, e
			}
			for _, b := range d.Blocks {
				if old, ok := unique[b.Hash]; ok && old.Bytes != b.Bytes {
					return result, ErrInvalid
				}
				unique[b.Hash] = b
			}
			if len(unique) > MaxBlocks {
				return result, ErrInvalid
			}
		}
		group := map[string][]Block{}
		for _, b := range unique {
			group[b.Object.ID] = append(group[b.Object.ID], b)
		}
		objectIDs := make([]string, 0, len(group))
		for id := range group {
			objectIDs = append(objectIDs, id)
		}
		sort.Strings(objectIDs)
		pack := make([]byte, 0, 6<<20)
		var pending []Block
		flush := func() error {
			if len(pack) == 0 {
				return nil
			}
			ref, e := s.putObjectContext(ctx, pack, false)
			if e != nil {
				return e
			}
			newPayload[ref.ID] = true
			for _, b := range pending {
				b.Object = ref
				unique[b.Hash] = b
			}
			pack = pack[:0]
			pending = pending[:0]
			return nil
		}
		for _, id := range objectIDs {
			if err = ctx.Err(); err != nil {
				return result, err
			}
			blocks := group[id]
			sort.Slice(blocks, func(i, j int) bool { return blocks[i].Offset > blocks[j].Offset })
			old, err := s.readObjectContext(ctx, blocks[0].Object)
			if err != nil {
				return result, err
			}
			for _, b := range blocks {
				if b.Object.Bytes != len(old) {
					return result, ErrInvalid
				}
				record := old[b.Offset : b.Offset+b.CipherBytes]
				if len(pack)+len(record) > 6<<20 {
					if err = flush(); err != nil {
						return result, err
					}
				}
				b.Offset = len(pack)
				pack = append(pack, record...)
				pending = append(pending, b)
			}
		}
		if err = flush(); err != nil {
			return result, err
		}
		for _, id := range byFile[file] {
			_, d, e := s.LoadVersionContext(ctx, id)
			if e != nil {
				return result, e
			}
			for i, b := range d.Blocks {
				d.Blocks[i] = unique[b.Hash]
			}
			eNew, e := s.sealDescriptorContext(ctx, d)
			if e != nil {
				return result, e
			}
			if eNew.Version != id {
				return result, ErrInvalid
			}
			if e = s.writeEnvelope("versions/"+id+".json", eNew); e != nil {
				return result, e
			}
			if e = s.checkpoint("repack-version-published"); e != nil {
				return result, e
			}
		}
	}
	for id := range oldPayload {
		if !newPayload[id] {
			result.PayloadObjectsReplaced++
		}
	}
	result.NewPayloadObjects = len(newPayload)
	result.GarbageObjectsRemoved, err = s.gcLocked(ctx)
	result.Stats = s.Stats
	return result, err
}

// RemoveAbandoned removes only unpublished staging files under the private
// transaction directory, never payload objects or committed descriptors.
func (s *Store) RemoveAbandoned(ctx context.Context) error {
	if s.backend != nil {
		return ErrRemoteMaintenance
	}
	unlock, err := s.lock(ctx, true)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := s.root.Open(".txn")
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		entries, e := f.ReadDir(128)
		for _, entry := range entries {
			if !entry.Type().IsRegular() || !validID(entry.Name()) {
				return ErrInvalid
			}
			if err = s.root.Remove(".txn/" + entry.Name()); err != nil {
				return err
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
		if err = ctx.Err(); err != nil {
			return err
		}
	}
	return s.syncDir(".txn")
}
