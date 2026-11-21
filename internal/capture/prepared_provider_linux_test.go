package capture

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/source"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func preparedProviderFixture(t *testing.T) (string, string, PreparedProviderOptions) {
	t.Helper()
	base, _, trust, _, _, raw := preparedFixture(t)
	runtime := teststore.Root(t)
	parent, e := localfs.OpenRoot(runtime)
	must(t, e)
	t.Cleanup(func() { parent.Close() })
	tree, e := ProbeTree(context.Background(), base, trust.Origin)
	must(t, e)
	return base, runtime, PreparedProviderOptions{Parent: parent, Directory: "provider", Operation: storage.Hash(raw), Tree: tree, Trust: trust, Manifest: raw, Initialize: true}
}

func TestPreparedProviderFreezesExactViewAndReleasesWithoutSourceCleanup(t *testing.T) {
	base, runtime, o := preparedProviderFixture(t)
	ctx := context.Background()
	p, e := OpenPreparedProvider(ctx, o)
	must(t, e)
	root, e := p.Open(ctx, o.Operation)
	must(t, e)
	domain := storage.Hash([]byte("domain"))
	selected, e := source.Scan(ctx, root, source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: domain}}, Domains: map[string]bool{domain: true}, EntryLimit: 128})
	must(t, e)
	must(t, p.Validate(ctx, o.Operation, root, selected, domain))
	root.Close()
	must(t, p.Close())
	before, e := os.ReadFile(filepath.Join(runtime, "provider/view.json"))
	must(t, e)
	o.Initialize = false
	o.Manifest = nil
	p, e = OpenPreparedProvider(ctx, o)
	must(t, e)
	defer p.Close()
	root, e = p.Open(ctx, o.Operation)
	must(t, e)
	root.Close()
	if e = p.Release(ctx, storage.Hash([]byte("other")), o.Operation); e == nil {
		t.Fatal("released wrong operation")
	}
	changed := o
	changed.Operation = storage.Hash([]byte("new export pointer"))
	if other, e := OpenPreparedProvider(ctx, changed); e == nil {
		other.Close()
		t.Fatal("rebound retained view")
	}
	after, e := os.ReadFile(filepath.Join(runtime, "provider/view.json"))
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("read/rejected rebind changed retained view")
	}
	// The producer moves its fixture export away; release must use only the
	// consumer journal, and must not delete or mutate the retained artifact.
	must(t, os.Rename(filepath.Join(base, "export"), filepath.Join(base, "producer-retained")))
	must(t, p.Release(ctx, o.Operation, o.Operation))
	must(t, p.Release(ctx, o.Operation, o.Operation))
	if _, e = os.Stat(filepath.Join(base, "producer-retained/nested/private.dump")); e != nil {
		t.Fatal("producer export changed", e)
	}
	must(t, os.Rename(filepath.Join(base, "producer-retained"), filepath.Join(base, "export")))
	if reopened, e := p.Open(ctx, o.Operation); e == nil {
		reopened.Close()
		t.Fatal("released consumer lease reopened")
	}
}

func TestPreparedProviderRejectsSelectionAndLateContentChange(t *testing.T) {
	base, _, o := preparedProviderFixture(t)
	ctx := context.Background()
	p, e := OpenPreparedProvider(ctx, o)
	must(t, e)
	defer p.Close()
	root, e := p.Open(ctx, o.Operation)
	must(t, e)
	defer root.Close()
	domain := storage.Hash([]byte("domain"))
	selection := source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: domain}}, Domains: map[string]bool{domain: true}, EntryLimit: 128}
	plan, e := source.Scan(ctx, root, selection)
	must(t, e)
	must(t, p.Validate(ctx, o.Operation, root, plan, domain))
	partial := plan
	partial.Excluded = 1
	if p.Validate(ctx, o.Operation, root, partial, domain) == nil {
		t.Fatal("partial application inventory accepted")
	}
	partial = plan
	partial.Entries = append([]source.Entry(nil), plan.Entries...)
	partial.Entries[0].Domain = storage.Hash([]byte("other domain"))
	if p.Validate(ctx, o.Operation, root, partial, domain) == nil {
		t.Fatal("cross-domain subset accepted")
	}
	partial = plan
	partial.Entries = append([]source.Entry(nil), plan.Entries...)
	partial.Entries[0].Names = []string{"substituted"}
	if p.Validate(ctx, o.Operation, root, partial, domain) == nil {
		t.Fatal("substituted plan accepted")
	}
	file := filepath.Join(base, "export/nested/private.dump")
	data, e := os.ReadFile(file)
	must(t, e)
	data[0] ^= 1
	must(t, os.WriteFile(file, data, 0600))
	// Even a newly scanned plan for the changed bytes must not pass the signed
	// producer checksum. This closes the admission-to-plan timing window.
	changed, e := source.Scan(ctx, root, selection)
	must(t, e)
	if p.Validate(ctx, o.Operation, root, changed, domain) == nil {
		t.Fatal("late changed export accepted")
	}
}

func TestPreparedProviderRefusesMissingHistoryQuotaGuardAndOverlap(t *testing.T) {
	for _, kind := range []string{"missing", "quota", "guard", "overlap", "lost-release-reply"} {
		t.Run(kind, func(t *testing.T) {
			_, runtime, o := preparedProviderFixture(t)
			ctx := context.Background()
			switch kind {
			case "missing":
				o.Initialize = false
				o.Manifest = nil
			case "quota":
				o.Admission = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
			case "guard":
				o.Guard = func(context.Context) error { return errors.New("withdrawn volume") }
			case "overlap":
				root, e := localfs.OpenRoot(o.Tree.Path)
				must(t, e)
				defer root.Close()
				o.Parent = root
			case "lost-release-reply":
				o.Fault = func(point string) error {
					if point == "prepared-view-released" {
						return errors.New("lost release reply")
					}
					return nil
				}
			}
			p, e := OpenPreparedProvider(ctx, o)
			if kind == "lost-release-reply" {
				must(t, e)
				if p.Release(ctx, o.Operation, o.Operation) == nil {
					t.Fatal("interruption absent")
				}
				must(t, p.Close())
				o.Initialize = false
				o.Fault = nil
				o.Manifest = nil
				p, e = OpenPreparedProvider(ctx, o)
				must(t, e)
				defer p.Close()
				must(t, p.Release(ctx, o.Operation, o.Operation))
				return
			}
			if kind == "overlap" {
				if e == nil {
					p.Close()
					t.Fatal("runtime inside producer root initialized")
				}
				if _, e = os.Stat(filepath.Join(o.Tree.Path, "provider")); !os.IsNotExist(e) {
					t.Fatal("overlap refusal wrote into producer root", e)
				}
				return
			}
			if e == nil {
				p.Close()
				t.Fatal("unadmitted provider initialized", kind)
			}
			if _, e = os.Stat(filepath.Join(runtime, "provider/view.json")); !os.IsNotExist(e) {
				t.Fatal("rejected operation wrote journal", kind, e)
			}
		})
	}
}

type captureVerifier struct {
	Provider
	calls, failAt int
}

func (p *captureVerifier) Consistency() string { return "best-effort" }
func (p *captureVerifier) Validate(ctx context.Context, _ string, _ *os.Root, _ source.Plan, _ string) error {
	p.calls++
	if p.calls == p.failAt {
		return ErrInvalid
	}
	return ctx.Err()
}

func TestPreparedProviderValidationBlocksSealAndIsNotRepeatedAfterSeal(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "refuse-before-seal", false: "resume-without-source"}[fail], func(t *testing.T) {
			f := setup(t, 1)
			must(t, f.job.Close())
			f.job = nil
			v := &captureVerifier{Provider: f.provider}
			if fail {
				v.failAt = 2
			}
			f.options.Provider = v
			f.options.Directory = filepath.Join(f.base, "validated-job")
			f.provider.checkpoint = filepath.Join(f.options.Directory, "state/checkpoint.json")
			var e error
			f.job, e = Open(context.Background(), f.options)
			must(t, e)
			if v.calls != 1 {
				t.Fatal("provider did not validate durable plan")
			}
			if !fail {
				f.job.Fault = func(point string) error {
					if point == "source-catalog-durable" {
						return errors.New("sealed before reply")
					}
					return nil
				}
			}
			if f.job.Run(context.Background()) == nil {
				t.Fatal("interruption absent")
			}
			s, e := f.job.Status(context.Background())
			must(t, e)
			if v.calls != 2 || f.provider.released || f.sink.acks != 0 {
				t.Fatal("wrong validation/release boundary", v.calls)
			}
			if fail {
				if s.Phase == "SEALED" {
					t.Fatal("unverified export sealed")
				}
				v.failAt = 0
			} else {
				if s.Phase != "SEALED" {
					t.Fatal("fixture not sealed")
				}
				v.failAt = 3
				// Fixture provider release is allowed to see an already absent file;
				// it still validates the durable checkpoint before removing its tree.
				must(t, os.Remove(filepath.Join(f.provider.path, "folder/private.bin")))
			}
			f.job.Fault = nil
			must(t, f.job.Run(context.Background()))
			f.restore(t)
			if !fail && v.calls != 2 {
				t.Fatal("sealed recovery reopened producer proof")
			}
		})
	}
}
