package ingress

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryJournalRestoresExactIntentAndReceiptAfterLoss(t *testing.T) {
	x := registryNetwork(t)
	ctx := context.Background()
	stateDir := filepath.Join(x.options.Directory, "state")
	primary := filepath.Join(stateDir, "registry.json")
	copyPath := filepath.Join(stateDir, registryJournalCopyName)
	legacy, e := os.ReadFile(primary)
	must(t, e)
	must(t, x.registry.Close())
	x.registry = nil
	x.options.Initialize = false
	must(t, EnableRegistryJournalCopy(ctx, x.options))
	x.registry, e = OpenRegistry(ctx, x.options)
	must(t, e)
	stale, e := os.ReadFile(copyPath)
	must(t, e)
	x.registry.Fault = func(point string) error {
		if point == "ingress-registry-copy-durable" {
			return errors.New("interrupted registry write")
		}
		return nil
	}
	if e = x.client.Begin(ctx); e == nil {
		t.Fatal("interrupted admission reported success")
	}
	must(t, x.registry.Close())
	x.registry = nil
	if prior, e := OpenRegistry(ctx, x.options); !errors.Is(e, ErrRegistryRecovery) {
		if prior != nil {
			prior.Close()
		}
		t.Fatal("divergent anchored registry accepted", e)
	}
	changed, e := RecoverRegistryJournalCopy(ctx, x.options)
	must(t, e)
	if !changed {
		t.Fatal("exact predecessor did not recover interrupted intent")
	}
	x.registry, e = OpenRegistry(ctx, x.options)
	must(t, e)
	first, _, _ := x.complete(t)
	raw, e := x.options.Replica.Catalog(ctx, first.Generation)
	must(t, e)
	must(t, x.registry.Close())
	x.registry = nil
	current, e := os.ReadFile(copyPath)
	must(t, e)
	must(t, os.WriteFile(primary, legacy, 0600))
	must(t, os.Remove(copyPath))
	if prior, e := OpenRegistry(ctx, x.options); !errors.Is(e, ErrRegistryRecovery) {
		if prior != nil {
			prior.Close()
		}
		t.Fatal("surviving anchor did not reject pre-mirror registry", e)
	}
	must(t, os.Remove(primary))
	must(t, os.WriteFile(copyPath, stale, 0600))
	if changed, e = RecoverRegistryJournalCopy(ctx, x.options); changed || !errors.Is(e, ErrRegistryRecovery) {
		t.Fatal("stale signed copy bypassed durable anchor", changed, e)
	}
	must(t, os.WriteFile(copyPath, current, 0600))
	slot := filepath.Join(x.options.Directory, "current")
	must(t, os.Rename(slot, slot+"-fixture-hold"))
	if changed, e = RecoverRegistryJournalCopy(ctx, x.options); changed || !errors.Is(e, ErrRegistryRecovery) {
		t.Fatal("missing session was inferred", changed, e)
	}
	must(t, os.Rename(slot+"-fixture-hold", slot))
	changed, e = RecoverRegistryJournalCopy(ctx, x.options)
	must(t, e)
	if !changed {
		t.Fatal("missing registry did not recover")
	}
	x.registry, e = OpenRegistry(ctx, x.options)
	must(t, e)
	_, repeated, e := x.client.FinishStep(ctx, raw)
	must(t, e)
	if repeated == nil || *repeated != first {
		t.Fatal("registry recovery changed the original publication receipt", repeated)
	}
	_, e = x.client.AcknowledgeStep(ctx, first)
	must(t, e)
	must(t, x.registry.Close())
	x.registry = nil
	fresh := registryAuthority(t, x, 2)
	_, e = RenewRegistry(ctx, x.options, fresh, nil, nil)
	must(t, e)
	x.options.Authority = fresh
	committed, e := os.ReadFile(primary)
	must(t, e)
	must(t, os.Remove(primary))
	changed, e = RecoverRegistryJournalCopy(ctx, x.options)
	must(t, e)
	if !changed {
		t.Fatal("renewed registry did not recover")
	}
	again, e := os.ReadFile(primary)
	must(t, e)
	if !bytes.Equal(again, committed) {
		t.Fatal("reconstruction rewrote authority history")
	}
}
