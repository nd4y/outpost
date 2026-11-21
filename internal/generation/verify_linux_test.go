package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nd4y/outpost/internal/filekit"
)

func TestContentVerificationIndependentVersionsAndKnownDamage(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	owner, e := filekit.NewOwner()
	ok(t, e)
	trust.Domain = owner.Domain
	source := filepath.Join(base, "input")
	ok(t, os.WriteFile(source, []byte("first secret payload"), 0600))
	cache := filepath.Join(base, "cache")
	s, e := filekit.OpenStore(cache, owner, true)
	ok(t, e)
	first, e := s.Backup(ctx, source, filekit.BackupOptions{Names: []string{"private/данные"}})
	ok(t, e)
	ok(t, os.WriteFile(source, []byte("new secret payload"), 0600))
	second, e := s.Backup(ctx, source, filekit.BackupOptions{File: first.File, Previous: first.Version, Names: []string{"private/данные"}})
	ok(t, e)
	other, e := s.Backup(ctx, source, filekit.BackupOptions{Names: []string{"another-name"}})
	ok(t, e)
	dir := filepath.Join(base, "replica")
	r := openTest(t, dir, trust)
	id, e := Seal(ctx, s, []string{first.Version, second.Version, other.Version}, r, Catalog{Format: Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1, KitFormat: KitFormat}, key)
	ok(t, e)
	raw, e := r.Catalog(ctx, id)
	ok(t, e)
	c, e := VerifyCatalog(raw, trust)
	ok(t, e)
	ok(t, s.Close())
	ok(t, os.RemoveAll(cache))
	ok(t, os.Remove(source))
	owner.SigningKey = nil
	report, e := VerifyMaterialized(ctx, dir, id, trust, owner, nil)
	ok(t, e)
	if !report.Complete || !report.WholeGeneration || len(report.Versions) != 3 {
		t.Fatal(report)
	}
	for _, v := range report.Versions {
		if v.State != "DECRYPTED" || v.Content == nil || v.VerifiedUnix < report.StartedUnix {
			t.Fatal(v)
		}
	}
	selection := RecoverySelection{Versions: []string{second.Version}}
	fetch := func(ctx context.Context, object Object) ([]byte, error) { return r.ReadObject(ctx, id, object) }
	plan, e := PlanRecoveryCatalog(ctx, id, raw, trust, owner, selection, fetch)
	ok(t, e)
	if plan.Files != 1 || plan.Bytes != int64(len("new secret payload")) {
		t.Fatal("wrong output admission plan", plan)
	}
	if _, e = PlanRecoveryCatalog(ctx, id, raw, trust, owner, RecoverySelection{}, fetch); !errors.Is(e, filekit.ErrInvalid) {
		t.Fatal("ambiguous restore plan admitted", e)
	}
	parent, e := os.OpenRoot(base)
	ok(t, e)
	restored, e := RecoverCatalogAt(ctx, id, raw, trust, owner, selection, fetch, parent, "admitted-output")
	ok(t, e)
	ok(t, parent.Close())
	if restored.Restored != plan {
		t.Fatal("admitted restore differs", restored, plan)
	}
	encoded, e := json.Marshal(report)
	ok(t, e)
	for _, secret := range []string{"private", "данные", "another-name", "secret payload"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("plaintext in report")
		}
	}
	var victim Object
	for _, k := range c.Kits {
		if k.Version == first.Version {
			victim = k.Root
		}
	}
	bad, e := os.ReadFile(filepath.Join(dir, "objects", victim.ID))
	ok(t, e)
	bad[0] ^= 1
	ok(t, os.WriteFile(filepath.Join(dir, "objects", victim.ID), bad, 0600))
	if e = r.Complete(ctx, id); !errors.Is(e, ErrIncomplete) {
		t.Fatal(e)
	}
	known, e := r.KnownDamage(ctx, id)
	ok(t, e)
	if !known.Damaged || len(known.Affected) != 1 || known.Affected[0].Version != first.Version || len(known.Affected[0].Objects) != 1 {
		t.Fatal(known)
	}
	ok(t, r.Close())
	ok(t, os.Remove(filepath.Join(dir, "state.json")))
	report, e = VerifyMaterialized(ctx, dir, id, trust, owner, nil)
	if !errors.Is(e, ErrIncomplete) || report.Complete || !report.WholeGeneration {
		t.Fatal(report, e)
	}
	for _, v := range report.Versions {
		if v.Version == first.Version {
			if v.State != "UNREADABLE" || v.Content != nil || v.VerifiedUnix != 0 {
				t.Fatal(v)
			}
		} else if v.State != "DECRYPTED" {
			t.Fatal("unaffected version mislabeled", v)
		}
	}
	report, e = VerifyMaterialized(ctx, dir, id, trust, owner, []string{second.Version})
	ok(t, e)
	if !report.Complete || report.WholeGeneration || len(report.Versions) != 1 {
		t.Fatal(report)
	}
	_, e = RecoverMaterialized(ctx, dir, id, trust, owner, RecoverySelection{Versions: []string{second.Version}}, filepath.Join(base, "selected"))
	ok(t, e)
	body, e := os.ReadFile(filepath.Join(base, "selected/private/данные"))
	ok(t, e)
	if string(body) != "new secret payload" {
		t.Fatal("wrong selected restore")
	}
	owner.Master = bytes.Repeat([]byte{7}, 32)
	report, e = VerifyMaterialized(ctx, dir, id, trust, owner, []string{second.Version})
	if !errors.Is(e, ErrIncomplete) || report.Complete || report.Versions[0].State != "UNREADABLE" {
		t.Fatal("wrong key verified", report, e)
	}
}

func TestContentVerificationCancellationAndCatalogClosure(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	owner, e := filekit.NewOwner()
	ok(t, e)
	trust.Domain = owner.Domain
	s, e := filekit.OpenStore(filepath.Join(base, "cache"), owner, true)
	ok(t, e)
	defer s.Close()
	input := filepath.Join(base, "input")
	ok(t, os.WriteFile(input, []byte("content"), 0600))
	one, e := s.Backup(ctx, input, filekit.BackupOptions{Names: []string{"one"}})
	ok(t, e)
	two, e := s.Backup(ctx, input, filekit.BackupOptions{Names: []string{"two"}})
	ok(t, e)
	r := openTest(t, filepath.Join(base, "replica"), trust)
	defer r.Close()
	id, e := Seal(ctx, s, []string{one.Version, two.Version}, r, Catalog{Format: Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1, KitFormat: KitFormat}, key)
	ok(t, e)
	raw, e := r.Catalog(ctx, id)
	ok(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	reads := 0
	report, e := VerifyCatalogContents(ctx, id, raw, trust, owner, nil, func(ctx context.Context, o Object) ([]byte, error) {
		reads++
		cancel()
		return r.ReadObject(context.Background(), id, o)
	})
	if !errors.Is(e, context.Canceled) || report.Complete || reads != 1 {
		t.Fatal(report, e, reads)
	}
	for _, v := range report.Versions {
		if v.State != "NOT_VERIFIED" || v.VerifiedUnix != 0 {
			t.Fatal(v)
		}
	}
	reads = 0
	for _, selected := range [][]string{{one.Version, one.Version}, {Hash([]byte("absent"))}} {
		_, e = VerifyCatalogContents(context.Background(), id, raw, trust, owner, selected, func(context.Context, Object) ([]byte, error) { reads++; return nil, nil })
		if !errors.Is(e, ErrInvalid) || reads != 0 {
			t.Fatal("invalid selection read payload", e, reads)
		}
	}
	c, e := VerifyCatalog(raw, trust)
	ok(t, e)
	for i := range c.Kits {
		if c.Kits[i].Version == one.Version {
			c.Kits[i].File = Hash([]byte("wrong file identity"))
		}
	}
	sort.Slice(c.Kits, func(i, j int) bool {
		return c.Kits[i].File+"/"+c.Kits[i].Version < c.Kits[j].File+"/"+c.Kits[j].Version
	})
	raw, e = SignCatalog(c, key)
	ok(t, e)
	report, e = VerifyCatalogContents(context.Background(), Hash(raw), raw, trust, owner, []string{one.Version}, func(ctx context.Context, o Object) ([]byte, error) { return r.ReadObject(ctx, id, o) })
	if !errors.Is(e, ErrIncomplete) || report.Complete {
		t.Fatal("wrong catalog file binding accepted", report, e)
	}
}
