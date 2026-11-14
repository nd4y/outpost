package ingress

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func registryAuthority(t *testing.T, f *registryFixture, revision uint64) []byte {
	t.Helper()
	a := f.authority
	a.Revision, a.NotBefore, a.ExpiresUnix = revision, time.Now().Unix()-1, time.Now().Unix()+3600
	raw, e := SignAuthority(a, f.control)
	must(t, e)
	return raw
}

func TestRegistryRenewalPreservesSameSlotSettlementAndNextGeneration(t *testing.T) {
	f := shortSettlementRegistry(t)
	ctx := context.Background()
	expectedOld, e := os.ReadFile(f.input)
	must(t, e)
	first, _, _ := f.complete(t)
	ack, e := f.client.AcknowledgeStep(ctx, first)
	must(t, e)
	if !ack.Clean {
		t.Fatal("fixture not acknowledged")
	}
	grant := grantFor(t, f, first.Generation)
	must(t, f.registry.Close())
	f.registry = nil
	f.options.Initialize = false
	legacy, e := os.ReadFile(filepath.Join(f.options.Directory, "state/registry.json"))
	must(t, e)
	time.Sleep(time.Until(time.Unix(f.authority.ExpiresUnix, 0)) + 20*time.Millisecond)
	fresh := registryAuthority(t, f, 2)
	result, e := RenewRegistry(ctx, f.options, fresh, nil, nil)
	must(t, e)
	if result.Format != RenewedRegistryFormat || result.Revision != 2 || result.LegacyDigest != storage.Hash(legacy) {
		t.Fatal("wrong renewal result", result)
	}
	saved, e := os.ReadFile(filepath.Join(f.options.Directory, "state/registry-v1-"+result.LegacyDigest+".json"))
	must(t, e)
	if !bytes.Equal(saved, legacy) {
		t.Fatal("original registry checkpoint changed")
	}
	replay, e := RenewRegistry(ctx, f.options, fresh, nil, nil)
	must(t, e)
	if replay != result {
		t.Fatal("renewal replay differs")
	}
	current := f.options
	current.Authority = fresh
	f.registry, e = OpenRegistry(ctx, current)
	must(t, e)
	settle := provisionSettlement(t, f, grant)
	original, e := settle.SettlementReceipt(ctx)
	must(t, e)
	if original != first {
		t.Fatal("renewal lost retained original receipt")
	}
	_, e = settle.AcknowledgeStep(ctx, original)
	must(t, e)
	must(t, f.registry.Close())
	f.registry = nil
	f.options = current
	f.registry, e = OpenRegistry(ctx, current)
	must(t, e)
	f.authority, e = VerifyAuthority(fresh, current.Owner, time.Now())
	must(t, e)
	f.intent.Authority, f.intent.NotBefore, f.intent.ExpiresUnix = storage.Hash(fresh), f.authority.NotBefore, f.authority.ExpiresUnix
	f.intent.Policy = f.authority.Revision
	next := f.next(t, first)
	must(t, f.source.Close())
	f.source = nil
	f.client.Close()
	f.client, e = NewClient(f.server.URL, fresh, next, current.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, e)
	t.Cleanup(f.client.Close)
	f.source, e = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, f.client)
	must(t, e)
	must(t, f.registry.Close())
	f.registry = nil
	for _, point := range []string{"capture-intent-durable", "capture-slot-replaced"} {
		killRenewedSlot(t, f, next, point)
	}
	f.registry, e = OpenRegistry(ctx, current)
	must(t, e)
	expectedNew := bytes.Clone(expectedOld)
	expectedNew[0] ^= 1
	must(t, os.WriteFile(f.input, expectedNew, 0600))
	second, _, _ := f.complete(t)
	if second.Generation == first.Generation {
		t.Fatal("new capture did not advance")
	}
	for index, selected := range []struct {
		generation string
		expected   []byte
	}{{first.Generation, expectedOld}, {second.Generation, expectedNew}} {
		out := filepath.Join(f.base, []string{"renewal-old", "renewal-new"}[index])
		_, e = generation.RecoverMaterialized(ctx, filepath.Join(f.base, "replica"), selected.generation, f.authority.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "data"))
		must(t, e)
		if !bytes.Equal(got, selected.expected) {
			t.Fatal("retained version changed", index)
		}
	}
}

func TestRegistryRenewalEmptyHistoryMonotonicReplayAndLegacyTamper(t *testing.T) {
	f := registryNetwork(t)
	ctx := context.Background()
	must(t, f.registry.Close())
	f.registry = nil
	f.options.Initialize = false
	second, third := registryAuthority(t, f, 2), registryAuthority(t, f, 3)
	one, e := RenewRegistry(ctx, f.options, second, nil, nil)
	must(t, e)
	oldOptions := f.options
	if g, e := OpenRegistry(ctx, oldOptions); e == nil {
		g.Close()
		t.Fatal("old still-valid authority admitted after renewal")
	}
	f.options.Authority = second
	two, e := RenewRegistry(ctx, f.options, third, nil, nil)
	must(t, e)
	if one.LegacyDigest != two.LegacyDigest || two.Revision != 3 {
		t.Fatal("legacy anchor replaced", two)
	}
	if _, e = RenewRegistry(ctx, oldOptions, second, nil, nil); e == nil {
		t.Fatal("old migration replay rolled back current grant")
	}
	f.options.Authority = third
	f.registry, e = OpenRegistry(ctx, f.options)
	must(t, e)
	must(t, f.registry.Close())
	f.registry = nil
	checkpoint := filepath.Join(f.options.Directory, "state/registry-v1-"+one.LegacyDigest+".json")
	raw, e := os.ReadFile(checkpoint)
	must(t, e)
	raw[len(raw)-1] ^= 1
	must(t, os.WriteFile(checkpoint, raw, 0600))
	if g, e := OpenRegistry(ctx, f.options); e == nil {
		g.Close()
		t.Fatal("corrupt migration anchor accepted")
	}
}

func TestRegistryRenewalRefusesIncompleteUnacknowledgedDirtyAndQuota(t *testing.T) {
	for _, phase := range []string{"active", "complete", "dirty", "quota", "guard", "expanded"} {
		t.Run(phase, func(t *testing.T) {
			f := registryNetwork(t)
			ctx := context.Background()
			if phase == "active" {
				must(t, f.client.Begin(ctx))
			} else if phase == "complete" || phase == "dirty" {
				receipt, _, _ := f.complete(t)
				if phase == "dirty" {
					_, e := f.client.AcknowledgeStep(ctx, receipt)
					must(t, e)
					must(t, os.WriteFile(filepath.Join(f.options.Directory, "current/objects/.uncertain"), []byte("unaccepted"), 0600))
				}
			}
			must(t, f.registry.Close())
			f.registry = nil
			f.options.Initialize = false
			path := filepath.Join(f.options.Directory, "state/registry.json")
			before, e := os.ReadFile(path)
			must(t, e)
			fresh := registryAuthority(t, f, 2)
			var guard func(context.Context) error
			if phase == "guard" {
				guard = func(context.Context) error { return errors.New("volume unavailable") }
			}
			if phase == "quota" {
				f.options.Admission = func(string) statefile.Admission {
					return func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
				}
			}
			if phase == "expanded" {
				a, e := VerifyAuthority(fresh, f.options.Owner, time.Now())
				must(t, e)
				a.MaxBytes++
				fresh, e = SignAuthority(a, f.control)
				must(t, e)
			}
			if _, e = RenewRegistry(ctx, f.options, fresh, guard, nil); e == nil {
				t.Fatal("unsafe renewal accepted", phase)
			}
			after, e := os.ReadFile(path)
			must(t, e)
			if !bytes.Equal(before, after) {
				t.Fatal("refused renewal changed registry", phase)
			}
			if phase == "dirty" {
				if _, e = os.Stat(filepath.Join(f.options.Directory, "current/objects/.uncertain")); e != nil {
					t.Fatal("unknown staging removed", e)
				}
			}
		})
	}
}
