package observation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestObservationCannotChangeIdentityGenerationGrantOrOriginalAge(t *testing.T) {
	key := func() ed25519.PrivateKey {
		_, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	owner, node, writer, maint := key(), key(), key(), key()
	now := time.Now().Truncate(time.Second)
	g := Grant{Format: GrantFormat, Trust: generation.Trust{Domain: storage.Hash([]byte("domain")), Repository: storage.Hash([]byte("repository")), Epoch: 1, Writer: writer.Public().(ed25519.PublicKey), Maintenance: maint.Public().(ed25519.PublicKey)}, Reader: storage.Hash([]byte("reader")), Collector: storage.Hash([]byte("collector")), Targets: []string{Identity(node.Public().(ed25519.PublicKey))}, Epoch: 1, NotBefore: now.Unix() - 300, ExpiresUnix: now.Unix() + 3600, MaxAgeSeconds: 60}
	grant, e := SignGrant(g, owner)
	if e != nil {
		t.Fatal(e)
	}
	pub := owner.Public().(ed25519.PublicKey)
	id := storage.Hash([]byte("generation"))
	raw, e := SignProof(grant, pub, id, now.Unix()-30, node, now)
	if e != nil {
		t.Fatal(e)
	}
	p, e := VerifyProof(raw, grant, pub, id, now)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Proof){func(p *Proof) { p.Target = g.Collector }, func(p *Proof) { p.ObservedUnix = now.Unix() }, func(p *Proof) { p.Generation = storage.Hash([]byte("other")) }, func(p *Proof) { p.Grant = storage.Hash([]byte("grant")) }} {
		bad := p
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if _, e := VerifyProof(b, grant, pub, id, now); e == nil {
			t.Fatal("tampered observation accepted")
		}
	}
	if _, e := VerifyProof(raw, grant, pub, id, now.Add(31*time.Second)); e == nil {
		t.Fatal("stale observation became fresh")
	}
	if old, e := VerifyProofDocument(raw, grant, pub, id); e != nil || old.ObservedUnix != p.ObservedUnix {
		t.Fatal("historical evidence lost", e)
	}
	if _, e := SignProof(grant, pub, id, now.Unix()+1, node, now); e == nil {
		t.Fatal("future observation accepted")
	}
	if _, e := SignProof(grant, pub, id, now.Unix(), key(), now); e == nil {
		t.Fatal("unapproved node signed")
	}
	g.Epoch++
	other, e := SignGrant(g, owner)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyProof(raw, other, pub, id, now); e == nil {
		t.Fatal("old grant replay accepted")
	}
}
