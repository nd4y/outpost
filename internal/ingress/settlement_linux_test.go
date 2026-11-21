package ingress

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func settlementFixture(t *testing.T) (Settlement, []byte, []byte, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Now()
	owner, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	writer, signer, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	maintenance, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	id := func(s string) string { return storage.Hash([]byte(s)) }
	a := Authority{Format: AuthorityFormat, Tenant: id("tenant"), Profile: id("profile"), Source: id("source"), Ingress: id("ingress"), Revision: 1, NotBefore: now.Unix() - 100, ExpiresUnix: now.Unix() - 1, Trust: generation.Trust{Domain: id("domain"), Repository: id("repository"), Epoch: 1, Writer: writer, Maintenance: maintenance}, MaxBytes: 1 << 20, MaxObjects: 8}
	authority, e := SignAuthority(a, key)
	must(t, e)
	i := Intent{Format: IntentFormat, Operation: id("operation"), Authority: storage.Hash(authority), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: now.Unix() - 50, NotBefore: now.Unix() - 50, ExpiresUnix: a.ExpiresUnix, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	intent, e := SignIntent(i, authority, owner, signer, time.Unix(i.NotBefore, 0))
	must(t, e)
	s := Settlement{Format: SettlementFormat, ID: id("settlement"), Authority: storage.Hash(authority), Intent: storage.Hash(intent), Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Generation: id("selected-generation"), NotBefore: now.Unix() - 1, ExpiresUnix: now.Unix() + 600}
	return s, authority, intent, key, now
}

func TestSettlementCapabilityDoesNotRenewOriginalWriteIntent(t *testing.T) {
	s, authority, intent, key, now := settlementFixture(t)
	owner := key.Public().(ed25519.PublicKey)
	if _, _, e := VerifyIntent(intent, authority, owner, now); !errors.Is(e, ErrDenied) {
		t.Fatal("original write authority unexpectedly current", e)
	}
	raw, e := SignSettlement(s, authority, intent, key, now)
	must(t, e)
	got, e := VerifySettlement(raw, authority, intent, owner, now)
	must(t, e)
	if got.ID != s.ID || got.Generation != s.Generation {
		t.Fatal("changed selection")
	}
	if _, _, e = VerifyIntent(intent, authority, owner, now); !errors.Is(e, ErrDenied) {
		t.Fatal("settlement extended write permission", e)
	}
	for _, when := range []time.Time{time.Unix(s.NotBefore-1, 0), time.Unix(s.ExpiresUnix, 0)} {
		if _, e = VerifySettlement(raw, authority, intent, owner, when); !errors.Is(e, ErrDenied) {
			t.Fatal("inactive settlement accepted", e)
		}
	}
	_, other, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	if _, e = VerifySettlement(raw, authority, intent, other.Public().(ed25519.PublicKey), now); !errors.Is(e, ErrDenied) {
		t.Fatal("wrong owner", e)
	}
	changed := append([]byte(nil), raw...)
	changed[len(changed)-4] ^= 1
	if _, e = VerifySettlement(changed, authority, intent, owner, now); !errors.Is(e, ErrDenied) {
		t.Fatal("tampered grant", e)
	}
}

func TestSettlementCapabilityRejectsScopeSubstitutionAndAmbiguousDocuments(t *testing.T) {
	original, authority, intent, key, now := settlementFixture(t)
	for _, change := range []func(*Settlement){
		func(s *Settlement) { s.Authority = storage.Hash([]byte("another-authority")) },
		func(s *Settlement) { s.Intent = storage.Hash([]byte("another-intent")) },
		func(s *Settlement) { s.Operation = storage.Hash([]byte("another-operation")) },
		func(s *Settlement) { s.Source = storage.Hash([]byte("another-source")) },
		func(s *Settlement) { s.Ingress = storage.Hash([]byte("another-ingress")) },
		func(s *Settlement) { s.Tenant = storage.Hash([]byte("another-tenant")) },
		func(s *Settlement) { s.Domain = storage.Hash([]byte("another-domain")) },
		func(s *Settlement) { s.Repository = storage.Hash([]byte("another-repository")) },
		func(s *Settlement) { s.Epoch++ },
	} {
		s := original
		change(&s)
		if _, e := SignSettlement(s, authority, intent, key, now); !errors.Is(e, ErrDenied) {
			t.Fatal("expanded original operation", e)
		}
	}
	raw, e := SignSettlement(original, authority, intent, key, now)
	must(t, e)
	for _, prefix := range []string{`{"format":"outpost-source-settlement-1",`, `{"allowUpload":true,`} {
		changed := append([]byte(prefix), raw[1:]...)
		if _, e = VerifySettlement(changed, authority, intent, key.Public().(ed25519.PublicKey), now); !errors.Is(e, ErrDenied) {
			t.Fatal("ambiguous capability accepted", e)
		}
	}
	var changed Settlement
	must(t, json.Unmarshal(raw, &changed))
	changed.Generation = storage.Hash([]byte("another-generation"))
	raw, e = json.Marshal(changed)
	must(t, e)
	if _, e = VerifySettlement(raw, authority, intent, key.Public().(ed25519.PublicKey), now); !errors.Is(e, ErrDenied) {
		t.Fatal("unsigned generation substitution", e)
	}
}
