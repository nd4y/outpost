package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestObservationWindowRenewsExpiredProofOnlyAfterNewContentRead(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	ctx := context.Background()
	now := time.Now()
	g := observation.Grant{Format: observation.GrantFormat, Trust: f.domain.Trust, Reader: f.nodes[1].node, Collector: w.node, Targets: []string{w.node}, Epoch: 1, NotBefore: now.Add(-time.Hour).Unix(), ExpiresUnix: now.Add(time.Hour).Unix(), MaxAgeSeconds: 60}
	grant, e := observation.SignGrant(g, f.owner)
	must(t, e)
	oldTime := now.Add(-2 * time.Minute)
	old, e := observation.SignProof(grant, w.owner, f.generation, oldTime.Unix(), w.cert.PrivateKey.(ed25519.PrivateKey), oldTime)
	must(t, e)
	name := observationName(storage.Hash(grant), f.generation, w.node)
	must(t, w.state.Write(name, old))
	dir := filepath.Join(DomainDirectory(w.dir, f.domain.Trust), "replica")
	replica, e := generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	v := &view{domains: map[string]*domainState{f.domain.Trust.Domain: {replica: replica}}}
	catalog, e := replica.Catalog(ctx, f.generation)
	must(t, e)
	refs, e := generation.Dependencies(catalog, f.domain.Trust)
	must(t, e)
	victim := filepath.Join(dir, "objects", refs[0].ID)
	original, e := os.ReadFile(victim)
	must(t, e)
	bad := bytes.Clone(original)
	bad[0] ^= 1
	must(t, os.WriteFile(victim, bad, 0600))
	if e = w.observeOne(ctx, v, grant, g, f.generation); !errors.Is(e, generation.ErrIncomplete) {
		t.Fatal("renewal did not read corrupt payload", e)
	}
	kept, e := w.readObservation(ctx, grant, f.generation, w.node)
	must(t, e)
	if !bytes.Equal(kept, old) {
		t.Fatal("failed refresh replaced historical proof")
	}
	// Repair the synthetic fault through the durable quarantine path, then
	// verify publication before retrying the same persisted observation window.
	must(t, replica.RepairPut(ctx, f.generation, refs[0].ID, original))
	must(t, replica.Complete(ctx, f.generation))
	must(t, w.observeOne(ctx, v, grant, g, f.generation))
	fresh, e := w.readObservation(ctx, grant, f.generation, w.node)
	must(t, e)
	p, e := observation.VerifyProof(fresh, grant, w.owner, f.generation, time.Now())
	must(t, e)
	if p.ObservedUnix <= oldTime.Unix() || bytes.Equal(fresh, old) {
		t.Fatal("old proof was relabelled")
	}
	must(t, w.observeOne(ctx, v, grant, g, f.generation))
	replay, e := w.readObservation(ctx, grant, f.generation, w.node)
	must(t, e)
	if !bytes.Equal(replay, fresh) {
		t.Fatal("unchanged proof refreshed without a new read")
	}
	// A verification request must not publish an admitted but unfinished copy,
	// even when all its objects are already present in this replica.
	catalogValue, e := generation.VerifyCatalog(catalog, f.domain.Trust)
	must(t, e)
	catalogValue.Sequence = 2
	catalogValue.Parent = f.generation
	nextRaw, e := generation.SignCatalog(catalogValue, f.writer)
	must(t, e)
	pending, e := replica.Begin(ctx, nextRaw)
	must(t, e)
	if e = w.observeOne(ctx, v, grant, g, pending); e == nil {
		t.Fatal("observation published pending generation")
	}
	status, e := replica.Status(ctx)
	must(t, e)
	if status.LatestComplete != f.generation {
		t.Fatal("observation changed complete head")
	}
}

func TestObservationWindowExpiresWithoutChangingOldEvidenceAndPreservesCorruption(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[0]
	ctx := context.Background()
	now := time.Now()
	g := observation.Grant{MaxAgeSeconds: 60}
	grant := []byte("synthetic binding")
	first, e := w.observationWindow(ctx, grant, g, f.generation, nil, now)
	must(t, e)
	repeated, e := w.observationWindow(ctx, grant, g, f.generation, nil, now.Add(30*time.Second))
	must(t, e)
	if repeated != first {
		t.Fatal("unexpired window replaced")
	}
	next, e := w.observationWindow(ctx, grant, g, f.generation, nil, now.Add(61*time.Second))
	must(t, e)
	if next == first {
		t.Fatal("expired window reused")
	}
	if _, e = w.observationWindow(ctx, grant, g, f.generation, nil, now); !errors.Is(e, ErrDenied) {
		t.Fatal("clock rollback accepted", e)
	}
	scope := storage.Hash([]byte(storage.Hash(grant) + "/" + f.generation + "/" + w.node))
	name := "observation-window-" + scope + ".json"
	must(t, w.state.Write(name, []byte("{}")))
	if _, e = w.observationWindow(ctx, grant, g, f.generation, nil, now.Add(62*time.Second)); !errors.Is(e, ErrDenied) {
		t.Fatal("malformed checkpoint replaced", e)
	}
	kept, e := w.state.Read(name)
	must(t, e)
	if string(kept) != "{}" {
		t.Fatal("corruption discarded")
	}
	w.state.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if _, e = w.observationWindow(ctx, grant, g, storage.Hash([]byte("new generation")), nil, now); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("new window bypassed quota", e)
	}
}
