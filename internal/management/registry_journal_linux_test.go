package management

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManagementRegistryJournalInitialCopyResumesExactBytes(t *testing.T) {
	f := newJournalFixture(t, true)
	ctx := context.Background()
	primary := filepath.Join(f.dir, "registry.json")
	initial, e := f.r.store.Read("registry.json")
	must(t, e)
	must(t, f.r.Close())
	f.r = nil
	options := f.options
	options.Initialize = true
	for _, missingAnchor := range []bool{false, true} {
		must(t, os.Remove(primary))
		if missingAnchor {
			must(t, os.Remove(filepath.Join(f.dir, registryJournalAnchorName)))
		}
		r, e := InitializeRegistry(ctx, options)
		must(t, e)
		actual, e := r.store.Read("registry.json")
		must(t, e)
		if !bytes.Equal(initial, actual) {
			t.Fatal("initialization changed exact signed bytes")
		}
		must(t, r.Close())
	}
	f.r, e = Open(f.options)
	must(t, e)
	f.enroll(t)
	if r, e := InitializeRegistry(ctx, options); !errors.Is(e, ErrConflict) {
		if r != nil {
			r.Close()
		}
		t.Fatal("nonempty registry admitted as an initialization", e)
	}
}

func TestManagementRegistryJournalEnablesFromExactLegacyPredecessor(t *testing.T) {
	for _, point := range []string{"management-registry-copy-durable", "management-registry-anchor-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			_, req, _ := commandFixture(t, f)
			receipt, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
			must(t, e)
			before, e := f.r.load()
			must(t, e)
			f.r.journalCopy = true
			f.r.Fault = interruptAt(point)
			e = f.r.store.WithLock(ctx, func() error { return f.r.enableRegistryJournal(ctx) })
			if e == nil {
				t.Fatal("missing migration interruption")
			}
			pending, e := f.r.readRegistryJournal()
			must(t, e)
			must(t, f.r.Close())
			f.r = nil
			if r, e := Open(f.options); !errors.Is(e, ErrRegistryJournal) {
				if r != nil {
					r.Close()
				}
				t.Fatal("old profile bypassed pending migration", e)
			}
			f.options.JournalCopy = true
			if r, e := RecoverRegistry(ctx, f.options); !errors.Is(e, ErrRegistryJournal) {
				if r != nil {
					r.Close()
				}
				t.Fatal("ordinary recovery performed profile migration", e)
			}
			f.r, e = EnableRegistryJournal(ctx, f.options)
			must(t, e)
			actual, e := f.r.store.Read("registry.json")
			must(t, e)
			after, e := f.r.load()
			must(t, e)
			if !bytes.Equal(actual, pending.Registry) || !sameRegistryAfterEnabling(before, after) || after.Revision != before.Revision+1 {
				t.Fatal("migration changed original state")
			}
			repeated, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
			must(t, e)
			if repeated != receipt {
				t.Fatal("migration changed original receipt", repeated)
			}
		})
	}
}

func TestManagementRegistryJournalRepairsInterruptedCommit(t *testing.T) {
	for _, point := range []string{"management-registry-copy-durable", "management-registry-anchor-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newJournalFixture(t, true)
			ctx := context.Background()
			raw, e := SignEnrollment(f.e, f.owner)
			must(t, e)
			f.r.Fault = interruptAt(point)
			op := id("enroll")
			if _, e = f.r.ApplyEnrollment(ctx, f.p, op, "INITIAL_ENROLLMENT", raw, 0); e == nil {
				t.Fatal("missing interruption")
			}
			copy, e := f.r.readRegistryJournal()
			must(t, e)
			must(t, f.r.Close())
			f.r = nil
			if r, e := Open(f.options); !errors.Is(e, ErrRegistryJournal) {
				if r != nil {
					r.Close()
				}
				t.Fatal("ordinary open accepted an interrupted write", e)
			}
			f.r, e = RecoverRegistry(ctx, f.options)
			must(t, e)
			actual, e := f.r.store.Read("registry.json")
			must(t, e)
			if !bytes.Equal(actual, copy.Registry) {
				t.Fatal("repair rewrote signed bytes")
			}
			receipt, e := f.r.ApplyEnrollment(ctx, f.p, op, "INITIAL_ENROLLMENT", raw, 0)
			must(t, e)
			if receipt.Operation != op || receipt.State != "COMPLETE" {
				t.Fatal(receipt)
			}
		})
	}
}

func TestManagementRegistryJournalRejectsStaleCopyAndMissingDependencies(t *testing.T) {
	f := newJournalFixture(t, true)
	ctx := context.Background()
	stale, e := f.r.store.Read(registryJournalCopyName)
	must(t, e)
	_, req, _ := commandFixture(t, f)
	_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
	current, e := f.r.store.Read(registryJournalCopyName)
	must(t, e)
	registry, e := f.r.store.Read("registry.json")
	must(t, e)
	s, e := f.r.load()
	must(t, e)
	dep := filepath.Join(f.dir, "blobs", "command-request-"+s.CommandOperations[req.Operation].Request+".json")
	dependentBytes, e := os.ReadFile(dep)
	must(t, e)
	must(t, f.r.Close())
	f.r = nil
	primary := filepath.Join(f.dir, "registry.json")
	copy := filepath.Join(f.dir, registryJournalCopyName)
	must(t, os.Remove(primary))
	assertRejected := func() {
		t.Helper()
		r, e := RecoverRegistry(ctx, f.options)
		if r != nil {
			r.Close()
		}
		if !errors.Is(e, ErrRegistryJournal) {
			t.Fatal("unsafe recovery accepted", e)
		}
		if _, e = os.Stat(primary); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("unsafe repair published a registry", e)
		}
	}
	must(t, os.WriteFile(copy, stale, 0600))
	assertRejected()
	must(t, os.WriteFile(copy, current, 0600))
	must(t, os.Remove(dep))
	assertRejected()
	must(t, os.WriteFile(dep, dependentBytes, 0600))
	f.r, e = RecoverRegistry(ctx, f.options)
	must(t, e)
	actual, e := f.r.store.Read("registry.json")
	must(t, e)
	if !bytes.Equal(actual, registry) {
		t.Fatal("loss repair changed current signed registry")
	}
}
