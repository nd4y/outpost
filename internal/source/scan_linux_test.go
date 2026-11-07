package source

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/teststore"
	"golang.org/x/sys/unix"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func setup(t *testing.T) (string, *os.Root, *filekit.Store, Selection) {
	t.Helper()
	base := teststore.Root(t)
	tree := filepath.Join(base, "tree")
	must(t, os.Mkdir(tree, 0700))
	r, e := os.OpenRoot(tree)
	must(t, e)
	t.Cleanup(func() { r.Close() })
	o, e := filekit.NewOwner()
	must(t, e)
	s, e := filekit.OpenStore(filepath.Join(base, "cache"), o, true)
	must(t, e)
	t.Cleanup(func() { s.Close() })
	return base, r, s, Selection{Rules: []policy.Rule{{Prefix: ".", Domain: o.Domain}}, Domains: map[string]bool{o.Domain: true}, EntryLimit: 100}
}
func findEntry(t *testing.T, p Plan, name string) Entry {
	t.Helper()
	for _, e := range p.Entries {
		for _, n := range e.Names {
			if n == name {
				return e
			}
		}
	}
	t.Fatal("missing entry", name)
	return Entry{}
}

func TestScanCapturesCompleteAliasesDirectoriesAndLinksWithoutFollowing(t *testing.T) {
	base, r, s, sel := setup(t)
	ctx := context.Background()
	tree := filepath.Join(base, "tree")
	body := bytes.Repeat([]byte("private payload"), 200)
	must(t, os.Mkdir(filepath.Join(tree, "каталог"), 0750))
	must(t, os.WriteFile(filepath.Join(tree, "каталог/data"), body, 0600))
	must(t, os.Link(filepath.Join(tree, "каталог/data"), filepath.Join(tree, "alias")))
	outside := filepath.Join(base, "outside")
	must(t, os.WriteFile(outside, []byte("not in backup"), 0600))
	must(t, os.Symlink(outside, filepath.Join(tree, "link")))
	p, e := Scan(ctx, r, sel)
	must(t, e)
	if len(p.Entries) != 3 || len(p.Observed) != 4 || p.SourceBytes != int64(len(body)) {
		t.Fatalf("bad inventory %+v", p)
	}
	entry := findEntry(t, p, "alias")
	if len(entry.Names) != 2 {
		t.Fatal("aliases not grouped")
	}
	got, e := p.CaptureEntry(ctx, r, entry, s, "", "")
	must(t, e)
	d, e := s.RestoreVersion(ctx, got.Version, filepath.Join(base, "restored"))
	must(t, e)
	if len(d.Names) != 2 {
		t.Fatal("lost aliases")
	}
	a, e := os.Stat(filepath.Join(base, "restored/alias"))
	must(t, e)
	b, e := os.Stat(filepath.Join(base, "restored/каталог/data"))
	must(t, e)
	if !os.SameFile(a, b) {
		t.Fatal("hardlink not restored")
	}
	link, e := p.CaptureEntry(ctx, r, findEntry(t, p, "link"), s, "", "")
	must(t, e)
	_, ld, e := s.LoadVersion(link.Version)
	must(t, e)
	if ld.LinkTarget != outside || ld.Size != int64(len(outside)) {
		t.Fatal("link target followed")
	}
	must(t, p.Recheck(ctx, r))
}
func TestScanDeniedAliasNeverCapturesAllowedName(t *testing.T) {
	base, r, _, sel := setup(t)
	tree := filepath.Join(base, "tree")
	must(t, os.WriteFile(filepath.Join(tree, "allow"), []byte("sensitive"), 0600))
	must(t, os.Link(filepath.Join(tree, "allow"), filepath.Join(tree, "deny")))
	sel.Rules = append(sel.Rules, policy.Rule{Prefix: "deny", Deny: true})
	p, e := Scan(context.Background(), r, sel)
	must(t, e)
	if len(p.Entries) != 0 || p.Excluded != 2 {
		t.Fatal("denied inode escaped", p)
	}
	sel.Rules = sel.Rules[:1]
	other := strings.Repeat("a", 64)
	sel.Domains[other] = true
	sel.Rules = append(sel.Rules, policy.Rule{Prefix: "deny", Domain: other, Priority: 1})
	if _, e = Scan(context.Background(), r, sel); !errors.Is(e, policy.ErrAmbiguous) {
		t.Fatal("cross-domain aliases accepted", e)
	}
}
func TestScanRefusesOutsideHardlinksAndSelectedSpecialFiles(t *testing.T) {
	base, r, _, sel := setup(t)
	tree := filepath.Join(base, "tree")
	must(t, os.WriteFile(filepath.Join(tree, "data"), []byte("secret"), 0600))
	must(t, os.Link(filepath.Join(tree, "data"), filepath.Join(base, "outside-alias")))
	if _, e := Scan(context.Background(), r, sel); !errors.Is(e, ErrLinks) {
		t.Fatal("external alias accepted", e)
	}
	sel.Rules = append(sel.Rules, policy.Rule{Prefix: "data", Deny: true})
	p, e := Scan(context.Background(), r, sel)
	must(t, e)
	if p.Excluded != 1 {
		t.Fatal("denied entry not counted")
	}
	must(t, unix.Mkfifo(filepath.Join(tree, "pipe"), 0600))
	if _, e = Scan(context.Background(), r, sel); !errors.Is(e, ErrBoundary) {
		t.Fatal("FIFO accepted", e)
	}
	sel.Rules = append(sel.Rules, policy.Rule{Prefix: "pipe", Deny: true})
	_, e = Scan(context.Background(), r, sel)
	must(t, e)
}
func TestScanRejectsRacesBeforeReadAndBeforePublication(t *testing.T) {
	base, r, s, sel := setup(t)
	ctx := context.Background()
	name := filepath.Join(base, "tree/data")
	must(t, os.WriteFile(name, []byte("aaaa"), 0600))
	p, e := Scan(ctx, r, sel)
	must(t, e)
	entry := findEntry(t, p, "data")
	old, e := os.Stat(name)
	must(t, e)
	// Live-tree checks rely on observable filesystem metadata. Advance beyond
	// the filesystem timestamp tick; atomic consistency requires a snapshot.
	time.Sleep(20 * time.Millisecond)
	must(t, os.WriteFile(name, []byte("bbbb"), 0600))
	must(t, os.Chtimes(name, old.ModTime(), old.ModTime()))
	if _, e = p.CaptureEntry(ctx, r, entry, s, "", ""); !errors.Is(e, ErrChanged) {
		t.Fatal("same-size changed inode accepted", e)
	}
	versions, e := os.ReadDir(filepath.Join(base, "cache/versions"))
	must(t, e)
	if len(versions) != 0 {
		t.Fatal("captured before recheck")
	}
	p, e = Scan(ctx, r, sel)
	must(t, e)
	entry = findEntry(t, p, "data")
	_, e = p.CaptureEntry(ctx, r, entry, s, "", "")
	must(t, e)
	must(t, os.Link(name, filepath.Join(base, "tree/new-alias")))
	if e = p.Recheck(ctx, r); !errors.Is(e, ErrChanged) {
		t.Fatal("new alias ignored", e)
	}
}
func TestScanBoundsCancellationAndSymlinkAncestorReplacement(t *testing.T) {
	base, r, s, sel := setup(t)
	tree := filepath.Join(base, "tree")
	must(t, os.Mkdir(filepath.Join(tree, "dir"), 0700))
	must(t, os.WriteFile(filepath.Join(tree, "dir/data"), []byte("ok"), 0600))
	sel.EntryLimit = 1
	if _, e := Scan(context.Background(), r, sel); !errors.Is(e, ErrLimit) {
		t.Fatal("scan unbounded", e)
	}
	sel.EntryLimit = 100
	p, e := Scan(context.Background(), r, sel)
	must(t, e)
	entry := findEntry(t, p, "dir/data")
	must(t, os.Rename(filepath.Join(tree, "dir"), filepath.Join(base, "moved")))
	must(t, os.Symlink(filepath.Join(base, "moved"), filepath.Join(tree, "dir")))
	if _, e = p.CaptureEntry(context.Background(), r, entry, s, "", ""); e == nil {
		t.Fatal("symlink ancestor followed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, e = Scan(ctx, r, sel); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel ignored", e)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel delayed")
	}
}
