package generation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
)

var ctx = context.Background()

func ok(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func temp(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if required := os.Getenv("OUTPOST_TEST_ROOT"); required != "" {
		rel, e := filepath.Rel(required, base)
		if e != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatal("test outside admitted HDD")
		}
	}
	return base
}
func trust(t *testing.T) (Trust, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	maintenance, deleteKey, e := ed25519.GenerateKey(rand.Reader)
	ok(t, e)
	return Trust{Hash([]byte("domain")), Hash([]byte("repository")), 1, pub, maintenance}, key, deleteKey
}
func openTest(t *testing.T, base string, trust Trust) *Replica {
	t.Helper()
	ok(t, os.Mkdir(base, 0700))
	r, e := Open(base, trust, true)
	ok(t, e)
	t.Cleanup(func() { r.Close() })
	return r
}
func synthetic(t *testing.T, trust Trust, key ed25519.PrivateKey, seq uint64, marker string) ([]byte, map[string][]byte) {
	t.Helper()
	payload := []byte("ciphertext " + marker)
	root := []byte("opaque signed kit " + marker)
	c := Catalog{Format: Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch, Sequence: seq, SnapshotUnix: 1, Policy: 1, KitFormat: KitFormat,
		Kits: []Kit{{File: Hash([]byte("file")), Version: Hash([]byte("version " + marker)), Root: Object{Hash(root), len(root)}, Objects: []Object{{Hash(payload), len(payload)}}}}}
	if seq > 1 {
		c.Parent = Hash([]byte("trusted prior checkpoint"))
	}
	b, e := SignCatalog(c, key)
	ok(t, e)
	return b, map[string][]byte{Hash(root): root, Hash(payload): payload}
}
func fetch(objects map[string][]byte) func(Object) ([]byte, error) {
	return func(ref Object) ([]byte, error) {
		b, ok := objects[ref.ID]
		if !ok {
			return nil, os.ErrNotExist
		}
		return b, nil
	}
}
func permit(t *testing.T, r *Replica, key ed25519.PrivateKey, retire ...string) []byte {
	t.Helper()
	status, e := r.Status(ctx)
	ok(t, e)
	sort.Strings(retire)
	id := make([]byte, 32)
	_, e = rand.Read(id)
	ok(t, e)
	b, e := SignPermit(Permit{Format: Format, Domain: r.trust.Domain, Repository: r.trust.Repository, Epoch: r.trust.Epoch, Revision: status.Revision, Operation: Hash(id), Retire: retire}, key)
	ok(t, e)
	return b
}
func TestCatalogAuthenticationAndBounds(t *testing.T) {
	trust, key, maintenance := trust(t)
	raw, _ := synthetic(t, trust, key, 1, "first")
	_, e := VerifyCatalog(raw, trust)
	ok(t, e)
	for name, b := range map[string][]byte{
		"whitespace": append(append([]byte(nil), raw...), '\n'),
		"duplicate":  bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1),
		"unknown":    bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":1,"unknown":true`), 1),
		"changed":    bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":2`), 1),
		"oversize":   bytes.Repeat([]byte(" "), MaxCatalog+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := VerifyCatalog(b, trust); e == nil {
				t.Fatal("untrusted catalog accepted")
			}
		})
	}
	for _, mutate := range []func(*Catalog){
		func(c *Catalog) { c.Kits[0].Objects[0].Bytes = 0 },
		func(c *Catalog) { c.Kits[0].Objects[0].Bytes = MaxObject + 1 },
		func(c *Catalog) { c.Kits[0].Objects = append(c.Kits[0].Objects, c.Kits[0].Objects[0]) },
		func(c *Catalog) { c.Kits[0].Objects[0] = c.Kits[0].Root },
		func(c *Catalog) { c.Kits[0].Root.ID = "../escape" },
		func(c *Catalog) { c.Kits = append(c.Kits, c.Kits[0]) },
	} {
		var c Catalog
		ok(t, json.Unmarshal(raw, &c))
		mutate(&c)
		if _, e := SignCatalog(c, key); e == nil {
			t.Fatal("invalid closure signed")
		}
	}
	for _, mutate := range []func(*Trust){func(t *Trust) { t.Epoch++ }, func(t *Trust) { t.Repository = Hash([]byte("other")) }, func(t *Trust) { t.Writer = t.Maintenance }, func(t *Trust) { t.Maintenance = nil }} {
		bad := trust
		mutate(&bad)
		if _, e := VerifyCatalog(raw, bad); e == nil {
			t.Fatal("wrong trust accepted")
		}
	}
	p, e := SignPermit(Permit{Format: Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Operation: Hash([]byte("op"))}, maintenance)
	ok(t, e)
	bad := trust
	bad.Maintenance = nil
	if _, e = verifyPermit(p, bad); e == nil {
		t.Fatal("malformed trust accepted")
	}
}

func TestReceiveRestartConflictAndPendingPin(t *testing.T) {
	base := temp(t)
	trust, key, maintenance := trust(t)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	first, objects := synthetic(t, trust, key, 1, "one")
	one, e := r.Receive(ctx, first, fetch(objects))
	ok(t, e)
	newRaw, newObjects := synthetic(t, trust, key, 181, "new")
	calls := 0
	newID, e := r.Receive(ctx, newRaw, func(o Object) ([]byte, error) {
		calls++
		if calls == 2 {
			return nil, ioFailure
		}
		return newObjects[o.ID], nil
	})
	if !errors.Is(e, ioFailure) {
		t.Fatal(e)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != one || len(status.Receiving) != 1 {
		t.Fatal(status)
	}
	_, e = r.Maintain(ctx, permit(t, r, maintenance))
	ok(t, e)
	ok(t, r.Close())
	r, e = Open(filepath.Join(base, "replica"), trust, false)
	ok(t, e)
	defer r.Close()
	calls = 0
	id, e := r.Receive(ctx, newRaw, func(o Object) ([]byte, error) { calls++; return newObjects[o.ID], nil })
	ok(t, e)
	if id != newID || calls != 1 {
		t.Fatal("restart lost accepted object or resumed wrong checkpoint", calls)
	}
	status, e = r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != newID || status.HighestSequence != 181 {
		t.Fatal(status)
	}
	stale, _ := synthetic(t, trust, key, 180, "stale")
	if _, e = r.Begin(ctx, stale); !errors.Is(e, ErrRollback) {
		t.Fatal(e)
	}
	conflict, _ := synthetic(t, trust, key, 181, "fork")
	if _, e = r.Begin(ctx, conflict); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	// Exact previous delivery is idempotent but cannot move latest backwards.
	_, e = r.Receive(ctx, first, func(Object) ([]byte, error) { t.Fatal("duplicate fetched payload"); return nil, nil })
	ok(t, e)
	status, e = r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != newID {
		t.Fatal("rollback")
	}
	// A new incomplete generation cannot revoke the last complete generation.
	third, _ := synthetic(t, trust, key, 182, "pending")
	_, e = r.Begin(ctx, third)
	ok(t, e)
	if _, e = r.Maintain(ctx, permit(t, r, maintenance, newID)); !errors.Is(e, ErrProtected) {
		t.Fatal(e)
	}
}

var ioFailure = errors.New("injected connection cut")

func TestMaintenanceAuthorityPinsAndReplay(t *testing.T) {
	base := temp(t)
	trust, key, maintenance := trust(t)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	a, objects := synthetic(t, trust, key, 1, "one")
	one, e := r.Receive(ctx, a, fetch(objects))
	ok(t, e)
	b, newObjects := synthetic(t, trust, key, 2, "two")
	two, e := r.Receive(ctx, b, fetch(newObjects))
	ok(t, e)
	for _, kind := range []string{"generation", "kit", "restore"} {
		pin := Hash([]byte(kind))
		ok(t, r.Pin(ctx, pin, one, kind))
		if _, e = r.Maintain(ctx, permit(t, r, maintenance, one)); !errors.Is(e, ErrProtected) {
			t.Fatal(kind, e)
		}
		ok(t, r.ReleasePin(ctx, pin))
	}
	if _, e = r.Maintain(ctx, permit(t, r, key, one)); e == nil {
		t.Fatal("writer deleted history")
	}
	stale := permit(t, r, maintenance, one)
	pin := Hash([]byte("new pin"))
	ok(t, r.Pin(ctx, pin, two, "restore"))
	if _, e = r.Maintain(ctx, stale); !errors.Is(e, ErrRollback) {
		t.Fatal(e)
	}
	p := permit(t, r, maintenance, one)
	r.Fault = func(point string) error {
		if point == "retirement-durable" {
			return ioFailure
		}
		return nil
	}
	if _, e = r.Maintain(ctx, p); !errors.Is(e, ioFailure) {
		t.Fatal(e)
	}
	r.Fault = nil
	removed, e := r.Maintain(ctx, p)
	ok(t, e)
	if removed == 0 {
		t.Fatal("no actual garbage collected")
	}
	removed, e = r.Maintain(ctx, p)
	ok(t, e)
	if removed != 0 {
		t.Fatal("replay repeated deletion")
	}
	var changed Permit
	ok(t, json.Unmarshal(p, &changed))
	status, e := r.Status(ctx)
	ok(t, e)
	changed.Revision = status.Revision
	changed.Retire = []string{two}
	reused, e := SignPermit(changed, maintenance)
	ok(t, e)
	if _, e = r.Maintain(ctx, reused); !errors.Is(e, ErrConflict) {
		t.Fatal("operation id reused", e)
	}
	if _, e = r.Maintain(ctx, permit(t, r, maintenance, two)); !errors.Is(e, ErrProtected) {
		t.Fatal(e)
	}
	if _, e = r.Catalog(ctx, one); !errors.Is(e, ErrIncomplete) {
		t.Fatal(e)
	}
}

func TestIncompleteAndCorruptNeverPublishOrGC(t *testing.T) {
	base := temp(t)
	trust, key, maintenance := trust(t)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	raw, objects := synthetic(t, trust, key, 1, "one")
	id, e := r.Begin(ctx, raw)
	ok(t, e)
	if e = r.Complete(ctx, id); !errors.Is(e, ErrIncomplete) {
		t.Fatal(e)
	}
	for key, b := range objects {
		bad := append([]byte(nil), b...)
		bad[0] ^= 1
		if e = r.Put(ctx, id, key, bad); e == nil {
			t.Fatal("corrupt transfer accepted")
		}
	}
	r.Fault = func(point string) error {
		if point == "before-complete" {
			return ioFailure
		}
		return nil
	}
	_, e = r.Receive(ctx, raw, fetch(objects))
	if !errors.Is(e, ioFailure) {
		t.Fatal(e)
	}
	status, e := r.Status(ctx)
	ok(t, e)
	if status.LatestComplete != "" {
		t.Fatal("partial published")
	}
	r.Fault = nil
	ok(t, r.Complete(ctx, id))
	var catalog Catalog
	ok(t, json.Unmarshal(raw, &catalog))
	ref := catalog.Kits[0].Objects[0]
	ok(t, os.WriteFile(filepath.Join(base, "replica", "objects", ref.ID), bytes.Repeat([]byte{0}, ref.Bytes), 0600))
	before, e := os.ReadDir(filepath.Join(base, "replica", "objects"))
	ok(t, e)
	if _, e = r.Maintain(ctx, permit(t, r, maintenance)); !errors.Is(e, ErrIncomplete) {
		t.Fatal(e)
	}
	after, e := os.ReadDir(filepath.Join(base, "replica", "objects"))
	ok(t, e)
	if len(before) != len(after) {
		t.Fatal("GC deleted before verification")
	}
	if e = r.ExportKit(ctx, id, catalog.Kits[0].Version, filepath.Join(base, "output")); e == nil {
		t.Fatal("corrupt kit exported")
	}
	if _, e = os.Stat(filepath.Join(base, "output")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("partial output published")
	}
	ok(t, os.Remove(filepath.Join(base, "replica", "objects", ref.ID)))
	ok(t, syscall.Mkfifo(filepath.Join(base, "replica", "objects", ref.ID), 0600))
	start := time.Now()
	if e = r.Complete(ctx, id); e == nil {
		t.Fatal("FIFO accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("FIFO blocked")
	}
}

func TestSealedReplicaSurvivesSourceRepackAndAbsence(t *testing.T) {
	base := temp(t)
	owner, e := filekit.NewOwner()
	ok(t, e)
	source, e := filekit.OpenStore(filepath.Join(base, "source-store"), owner, true)
	ok(t, e)
	defer source.Close()
	path := filepath.Join(base, "input")
	old := make([]byte, 2<<20)
	_, e = rand.Read(old)
	ok(t, e)
	ok(t, os.WriteFile(path, old, 0640))
	first, e := source.Backup(ctx, path, filekit.BackupOptions{Names: []string{"private/name.bin", "alias.bin"}})
	ok(t, e)
	trust, key, maintenance := trust(t)
	trust.Domain = owner.Domain
	a := openTest(t, filepath.Join(base, "holder-a"), trust)
	b := openTest(t, filepath.Join(base, "holder-b"), trust)
	c := Catalog{Format: Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1, KitFormat: KitFormat}
	one, e := Seal(ctx, source, []string{first.Version}, a, c, key)
	ok(t, e)
	raw, e := a.Catalog(ctx, one)
	ok(t, e)
	_, e = b.Receive(ctx, raw, func(o Object) ([]byte, error) { return a.ReadObject(ctx, one, o) })
	ok(t, e)
	pin := Hash([]byte("offline-file-kit"))
	ok(t, b.Pin(ctx, pin, one, "kit"))
	precreated := filepath.Join(base, "saved-old-kit")
	ok(t, b.ExportKit(ctx, one, first.Version, precreated))
	newData := append([]byte(nil), old...)
	copy(newData[1<<20:], bytes.Repeat([]byte{17}, 8192))
	ok(t, os.WriteFile(path, newData, 0640))
	second, e := source.Backup(ctx, path, filekit.BackupOptions{Names: []string{"private/name.bin", "alias.bin"}, File: first.File, Previous: first.Version})
	ok(t, e)
	repacked, e := source.Repack(ctx)
	ok(t, e)
	if repacked.PayloadObjectsReplaced == 0 {
		t.Fatal("repack did not change actual objects")
	}
	_, e = source.Retire(ctx, []string{first.Version})
	ok(t, e)
	c.Sequence = 181
	c.Parent = one
	c.SnapshotUnix = 2
	newID, e := Seal(ctx, source, []string{second.Version}, a, c, key)
	ok(t, e)
	newCatalog, e := a.Catalog(ctx, newID)
	ok(t, e)
	_, e = b.Receive(ctx, newCatalog, func(o Object) ([]byte, error) { return a.ReadObject(ctx, newID, o) })
	ok(t, e)
	// Only B and the owner's recovery material survive. A never supplies the
	// missed intermediate catalogs; old B's physical closure stays pinned.
	ok(t, a.Close())
	ok(t, source.Close())
	ok(t, os.RemoveAll(filepath.Join(base, "holder-a")))
	ok(t, os.RemoveAll(filepath.Join(base, "source-store")))
	ok(t, os.Remove(path))
	if _, e = b.Maintain(ctx, permit(t, b, maintenance, one)); !errors.Is(e, ErrProtected) {
		t.Fatal(e)
	}
	for _, test := range []struct {
		id, version string
		want        []byte
	}{{one, first.Version, old}, {newID, second.Version, newData}} {
		kit := filepath.Join(base, "kit-"+test.id)
		ok(t, b.ExportKit(ctx, test.id, test.version, kit))
		restoreKit(t, kit, test.version, owner, test.want)
	}
	ok(t, b.ReleasePin(ctx, pin))
	n, e := b.Maintain(ctx, permit(t, b, maintenance, one))
	ok(t, e)
	if n == 0 {
		t.Fatal("old physical dependencies retained forever")
	}
	ok(t, b.Close())
	ok(t, os.RemoveAll(filepath.Join(base, "holder-b")))
	restoreKit(t, precreated, first.Version, owner, old)
}
func restoreKit(t *testing.T, kit, version string, owner filekit.Owner, want []byte) {
	t.Helper()
	owner.SigningKey = nil
	r, e := filekit.OpenStore(kit, owner, false)
	ok(t, e)
	defer r.Close()
	dest := kit + "-restored"
	d, e := r.Restore(ctx, version, dest)
	ok(t, e)
	got, e := os.ReadFile(filepath.Join(dest, d.Names[0]))
	ok(t, e)
	if !bytes.Equal(got, want) {
		t.Fatal("independent bytes differ")
	}
	a, e := os.Stat(filepath.Join(dest, d.Names[0]))
	ok(t, e)
	b, e := os.Stat(filepath.Join(dest, d.Names[1]))
	ok(t, e)
	if !os.SameFile(a, b) || a.Mode().Perm() != 0640 {
		t.Fatal("metadata/alias mismatch")
	}
}
