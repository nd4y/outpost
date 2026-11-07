package generation

import (
	"bytes"
	"container/list"
	"encoding/json"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"sync"
	"syscall"
)

// Catalogs are immutable and addressed by their signed bytes. The bounded
// process-wide cache is an acceleration only: Open, publication, maintenance,
// export and scrub read actual files. It is not evidence of disk integrity.
const catalogCacheBytes = 64 << 20

type catalogStamp struct {
	Dev, Ino     uint64
	Size         int64
	Mtime, Ctime syscall.Timespec
}
type cachedCatalog struct {
	key     string
	stamp   catalogStamp
	catalog Catalog
	refs    map[string]Object
	cost    int
}

var catalogCache = struct {
	sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
	bytes   int
}{entries: map[string]*list.Element{}, lru: list.New()}

func stampOf(i os.FileInfo) (catalogStamp, error) {
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() {
		return catalogStamp{}, ErrInvalid
	}
	return catalogStamp{s.Dev, s.Ino, s.Size, s.Mtim, s.Ctim}, nil
}
func (r *Replica) catalogFile(id string, item entry) (*os.File, catalogStamp, error) {
	if !validID(id) {
		return nil, catalogStamp{}, ErrInvalid
	}
	f, e := localfs.OpenFile(r.root, "catalogs/"+id, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, catalogStamp{}, e
	}
	i, e := f.Stat()
	var stamp catalogStamp
	if e == nil {
		stamp, e = stampOf(i)
	}
	if e == nil && (stamp.Size != int64(item.Bytes) || item.Bytes < 1 || item.Bytes > MaxCatalog) {
		e = ErrInvalid
	}
	if e != nil {
		f.Close()
		return nil, stamp, e
	}
	return f, stamp, nil
}
func (r *Replica) readCatalog(f *os.File, stamp catalogStamp, id string, item entry) ([]byte, Catalog, map[string]Object, error) {
	b, e := io.ReadAll(io.LimitReader(f, int64(item.Bytes)+1))
	if e != nil {
		return nil, Catalog{}, nil, e
	}
	i, e := f.Stat()
	if e != nil {
		return nil, Catalog{}, nil, e
	}
	after, e := stampOf(i)
	if e != nil || after != stamp || len(b) != item.Bytes || Hash(b) != id {
		return nil, Catalog{}, nil, ErrInvalid
	}
	c, e := VerifyCatalog(b, r.trust)
	if e != nil {
		return nil, c, nil, e
	}
	if c.Sequence != item.Sequence {
		return nil, c, nil, ErrInvalid
	}
	refs, e := closure(c)
	return b, c, refs, e
}
func (r *Replica) catalogRaw(id string, item entry) ([]byte, error) {
	f, stamp, e := r.catalogFile(id, item)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, _, _, e := r.readCatalog(f, stamp, id, item)
	return b, e
}
func (r *Replica) catalogEntry(id string, item entry, fresh bool) (Catalog, map[string]Object, error) {
	f, stamp, e := r.catalogFile(id, item)
	if e != nil {
		return Catalog{}, nil, e
	}
	defer f.Close()
	trust, _ := json.Marshal(r.trust)
	key := r.root.Name() + "/" + id + "/" + Hash(trust)
	if !fresh {
		catalogCache.Lock()
		element := catalogCache.entries[key]
		if element != nil {
			cached := element.Value.(*cachedCatalog)
			if cached.stamp == stamp && cached.catalog.Sequence == item.Sequence {
				catalogCache.lru.MoveToFront(element)
				catalogCache.Unlock()
				return cached.catalog, cached.refs, nil
			}
		}
		catalogCache.Unlock()
	}
	b, c, refs, e := r.readCatalog(f, stamp, id, item)
	if e != nil {
		return c, nil, e
	}
	// This conservative estimate includes parsed strings, slices, maps and entry overhead.
	cost := len(b)*6 + 4096
	if cost <= catalogCacheBytes {
		catalogCache.Lock()
		defer catalogCache.Unlock()
		if old := catalogCache.entries[key]; old != nil {
			catalogCache.bytes -= old.Value.(*cachedCatalog).cost
			catalogCache.lru.Remove(old)
			delete(catalogCache.entries, key)
		}
		for catalogCache.bytes+cost > catalogCacheBytes {
			last := catalogCache.lru.Back()
			old := last.Value.(*cachedCatalog)
			catalogCache.bytes -= old.cost
			delete(catalogCache.entries, old.key)
			catalogCache.lru.Remove(last)
		}
		catalogCache.entries[key] = catalogCache.lru.PushFront(&cachedCatalog{key, stamp, c, refs, cost})
		catalogCache.bytes += cost
	}
	return c, refs, nil
}
func (r *Replica) putCatalog(id string, raw []byte) error {
	old, e := read(r.root, "catalogs/"+id, MaxCatalog)
	if e == nil {
		if !bytes.Equal(old, raw) {
			return ErrConflict
		}
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	if e = r.write("catalogs/"+id, raw); e != nil {
		return e
	}
	return r.point("catalog-durable")
}
