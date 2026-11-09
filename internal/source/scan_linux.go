// Package source performs trusted, bounded source planning. Paths and labels
// stay on this node; replicas receive only encrypted file kits and opaque jobs.
package source

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/policy"
	"golang.org/x/sys/unix"
)

var (
	ErrChanged  = errors.New("source changed since planning")
	ErrLimit    = errors.New("source profile limit exceeded")
	ErrBoundary = errors.New("unsupported source boundary or entry")
	ErrLinks    = errors.New("incomplete source hardlink aliases")
)

const MaxEntries = 32768
const MaxNameBytes = 16 << 20
const MaxDepth = 128

type Selection struct {
	Rules      []policy.Rule     `json:"rules"`
	Domains    map[string]bool   `json:"domains"`
	Labels     map[string]string `json:"labels,omitempty"`
	EntryLimit int               `json:"entryLimit"`
}
type Entry struct {
	Names    []string               `json:"names"`
	Domain   string                 `json:"domain"`
	Identity filekit.SourceIdentity `json:"identity"`
}

// Plan is private source metadata, not an atomic filesystem snapshot. Recheck
// immediately before capture and before publication; applications still need an
// explicit consistency provider to obtain transaction-consistent snapshots.
type Plan struct {
	Root        filekit.SourceIdentity            `json:"root"`
	Entries     []Entry                           `json:"entries"`
	Observed    map[string]filekit.SourceIdentity `json:"observed"`
	SourceBytes int64                             `json:"sourceBytes"`
	Excluded    int                               `json:"excluded"`
}

func Scan(ctx context.Context, root *os.Root, sel Selection) (Plan, error) {
	var p Plan
	if root == nil || sel.EntryLimit < 1 || sel.EntryLimit > MaxEntries {
		return p, ErrLimit
	}
	if e := policy.ValidateRules(sel.Rules, sel.Domains); e != nil {
		return p, e
	}
	// Validate labels even when an empty tree has no matching entries.
	if _, e := policy.Select([]policy.Rule{{Prefix: ".", Domain: firstDomain(sel.Domains)}}, "entry", sel.Labels); e != nil {
		return p, e
	}
	initial, e := filekit.InspectEntry(root, ".")
	if e != nil {
		return p, e
	}
	if initial.Kind() != "directory" {
		return p, ErrBoundary
	}
	p.Root = initial
	p.Observed = map[string]filekit.SourceIdentity{}
	fd, e := root.Open(".")
	if e != nil {
		return p, e
	}
	defer fd.Close()
	mount, e := mountID(int(fd.Fd()), ".")
	if e != nil {
		return p, e
	}
	namesBytes := 0
	var walk func(*os.File, string, int) error
	walk = func(dir *os.File, prefix string, depth int) error {
		if depth > MaxDepth {
			return ErrLimit
		}
		for {
			if e := ctx.Err(); e != nil {
				return e
			}
			batch, e := dir.Readdirnames(128)
			if e != nil && !errors.Is(e, io.EOF) {
				return e
			}
			for _, base := range batch {
				name := path.Join(prefix, base)
				if !policy.Relative(name) || !utf8.ValidString(name) || strings.Contains(base, "/") {
					return ErrBoundary
				}
				if len(p.Observed) >= sel.EntryLimit {
					return ErrLimit
				}
				namesBytes += len(name)
				if namesBytes > MaxNameBytes {
					return ErrLimit
				}
				var st unix.Stat_t
				if e := unix.Fstatat(int(dir.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
					return e
				}
				childMount, e := mountID(int(dir.Fd()), base)
				if e != nil {
					return e
				}
				if childMount != mount {
					return ErrBoundary
				}
				// Inspect via the approved root again: a renamed ancestor must not
				// turn an old directory handle into a new accepted policy path.
				i, e := filekit.InspectEntry(root, name)
				if e != nil {
					return e
				}
				if i.Device != uint64(st.Dev) || i.Inode != st.Ino || i.Device != initial.Device {
					return ErrBoundary
				}
				if _, exists := p.Observed[name]; exists {
					return ErrChanged
				}
				p.Observed[name] = i
				if i.Kind() == "directory" {
					child, e := unix.Openat(int(dir.Fd()), base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
					if e != nil {
						return e
					}
					f := os.NewFile(uintptr(child), "source-directory")
					var opened unix.Stat_t
					err := unix.Fstat(child, &opened)
					if err == nil && (opened.Dev != st.Dev || opened.Ino != st.Ino) {
						err = ErrChanged
					}
					if err == nil {
						err = walk(f, name, depth+1)
					}
					f.Close()
					if err != nil {
						return err
					}
				}
			}
			if errors.Is(e, io.EOF) {
				return nil
			}
		}
	}
	if e = walk(fd, "", 0); e != nil {
		return Plan{}, e
	}
	groups := map[[2]uint64][]string{}
	for name, i := range p.Observed {
		key := [2]uint64{i.Device, i.Inode}
		groups[key] = append(groups[key], name)
	}
	for _, names := range groups {
		sort.Strings(names)
		i := p.Observed[names[0]]
		for _, name := range names {
			if p.Observed[name] != i {
				return Plan{}, ErrChanged
			}
		}
		domain, e := policy.SelectAliases(sel.Rules, names, sel.Labels)
		if errors.Is(e, policy.ErrDenied) {
			p.Excluded += len(names)
			continue
		}
		if e != nil {
			return Plan{}, e
		}
		if i.Kind() == "unsupported" {
			return Plan{}, ErrBoundary
		}
		if i.Kind() != "directory" && (i.Links != uint64(len(names)) || len(names) > 256) {
			return Plan{}, ErrLinks
		}
		if i.Kind() != "regular" && len(names) != 1 {
			return Plan{}, ErrLinks
		}
		if i.Kind() == "regular" {
			if i.Size < 0 || i.Size > filekit.MaxFileBytes {
				return Plan{}, ErrLimit
			}
			p.SourceBytes += i.Size
		}
		p.Entries = append(p.Entries, Entry{Names: names, Domain: domain, Identity: i})
	}
	sort.Slice(p.Entries, func(i, j int) bool { return p.Entries[i].Names[0] < p.Entries[j].Names[0] })
	if e = p.Recheck(ctx, root); e != nil {
		return Plan{}, e
	}
	return p, nil
}
func firstDomain(domains map[string]bool) string {
	for id := range domains {
		return id
	}
	return ""
}
func mountID(fd int, name string) (uint64, error) {
	var st unix.Statx_t
	if e := unix.Statx(fd, name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &st); e != nil {
		return 0, e
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, ErrBoundary
	}
	return st.Mnt_id, nil
}

// Recheck includes excluded entries and directory identities so an alias added,
// removed or moved after the scan invalidates the planned tree. This detects
// ordinary concurrent changes; it is not an adversarial filesystem snapshot.
func (p Plan) Recheck(ctx context.Context, root *os.Root) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	i, e := filekit.InspectEntry(root, ".")
	if e != nil {
		return e
	}
	if i != p.Root {
		return ErrChanged
	}
	for name, old := range p.Observed {
		if e := ctx.Err(); e != nil {
			return e
		}
		i, e := filekit.InspectEntry(root, name)
		if e != nil {
			return e
		}
		if i != old {
			return ErrChanged
		}
	}
	return nil
}

// CaptureEntry rechecks every hardlink alias around the rooted read. The caller
// must preserve the plan and call Recheck before publishing the generation.
func (p Plan) CaptureEntry(ctx context.Context, root *os.Root, entry Entry, s *filekit.Store, file, previous string) (filekit.Stats, error) {
	return p.CaptureEntryProgress(ctx, root, entry, s, file, previous, "")
}
func (p Plan) CaptureEntryProgress(ctx context.Context, root *os.Root, entry Entry, s *filekit.Store, file, previous, operation string, prior ...string) (filekit.Stats, error) {
	if len(prior) > 1 {
		return filekit.Stats{}, filekit.ErrInvalid
	}
	var previousProgress string
	if len(prior) != 0 {
		previousProgress = prior[0]
	}
	if s == nil || entry.Domain != s.Owner.Domain || len(entry.Names) == 0 {
		return filekit.Stats{}, policy.ErrDenied
	}
	approved := false
	for _, item := range p.Entries {
		if item.Domain == entry.Domain && item.Identity == entry.Identity && sameNames(item.Names, entry.Names) {
			approved = true
			break
		}
	}
	if !approved {
		return filekit.Stats{}, policy.ErrDenied
	}
	check := func() error {
		for _, name := range entry.Names {
			i, e := filekit.InspectEntry(root, name)
			if e != nil {
				return e
			}
			if i != entry.Identity {
				return ErrChanged
			}
		}
		return nil
	}
	if e := check(); e != nil {
		return filekit.Stats{}, e
	}
	stats, e := s.BackupEntry(ctx, root, entry.Names[0], filekit.BackupOptions{File: file, Previous: previous, Names: entry.Names, Expected: &entry.Identity, Progress: operation, PreviousProgress: previousProgress})
	if e != nil {
		return stats, e
	}
	return stats, check()
}
func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
