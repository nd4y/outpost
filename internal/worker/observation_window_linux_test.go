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
	v := &view{cfg: f.cfg, domains: map[string]*domainState{f.domain.Trust.Domain: {replica: replica}}}
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

func TestObservationVerificationBurstBoundsProgressAndPreservesOldestRead(t *testing.T) {
	ctx := context.Background()
	calls := 0
	partial, err := verifyObservationBurst(ctx, func(context.Context) (generation.BatchResult, error) {
		calls++
		return generation.BatchResult{VerifiedObjects: calls, ReadBytes: generation.MaxObject}, nil
	})
	if !errors.Is(err, observation.ErrPending) || calls != 8 || partial.VerifiedObjects != calls {
		t.Fatal("progress exceeded its grant slot", calls, partial, err)
	}

	calls = 0
	const oldest = 17
	complete, err := verifyObservationBurst(ctx, func(context.Context) (generation.BatchResult, error) {
		calls++
		return generation.BatchResult{
			VerifiedObjects: calls, ReadBytes: 1, Complete: calls == 2, VerifiedAt: oldest,
		}, nil
	})
	must(t, err)
	if calls != 2 || !complete.Complete || complete.VerifiedAt != oldest {
		t.Fatal("completion did not retain its oldest supporting read", calls, complete)
	}
}

func TestObservationVerificationBurstYieldsOnErrorsTimeoutAndNoProgress(t *testing.T) {
	for _, tt := range []struct {
		name   string
		second generation.BatchResult
		err    error
		want   error
	}{
		{"damage", generation.BatchResult{VerifiedObjects: 3, ReadBytes: 1}, generation.ErrIncomplete, generation.ErrIncomplete},
		{"empty", generation.BatchResult{VerifiedObjects: 3}, nil, observation.ErrPending},
		{"unchanged", generation.BatchResult{VerifiedObjects: 2, ReadBytes: 1}, nil, observation.ErrPending},
		{"regressed", generation.BatchResult{VerifiedObjects: 1, ReadBytes: 1}, nil, observation.ErrPending},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			_, err := verifyObservationBurst(context.Background(), func(context.Context) (generation.BatchResult, error) {
				calls++
				if calls == 1 {
					return generation.BatchResult{VerifiedObjects: 2, ReadBytes: 1}, nil
				}
				return tt.second, tt.err
			})
			if calls != 2 || !errors.Is(err, tt.want) {
				t.Fatal("immediate retry despite stopped progress", calls, err)
			}
		})
	}
	expired, done := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer done()
	_, err := verifyObservationBurst(expired, func(context.Context) (generation.BatchResult, error) {
		t.Fatal("verification started after the attempt deadline")
		return generation.BatchResult{}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("attempt timeout was not preserved", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err = verifyObservationBurst(ctx, func(context.Context) (generation.BatchResult, error) {
		calls++
		cancel()
		return generation.BatchResult{Complete: true, VerifiedObjects: 1, ReadBytes: 1}, nil
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("revocation after a batch permitted completion or another read", calls, err)
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
	g.ExpiresUnix = first.StartedUnix + 100
	if first.deadline(g).Unix() != first.StartedUnix+g.MaxAgeSeconds+1 {
		t.Fatal("verification deadline exceeds the persisted age")
	}
	g.ExpiresUnix = first.StartedUnix + 10
	if first.deadline(g).Unix() != g.ExpiresUnix {
		t.Fatal("verification deadline exceeds grant expiry")
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
