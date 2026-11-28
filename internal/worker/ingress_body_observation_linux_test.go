package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerIngressObjectBodyObservationRestartsAndQuotaDoesNotRefusePut(t *testing.T) {
	f := newFixture(t)
	w := f.nodes[1]
	w.observeIngressObjectBodies = true
	f.cfg.Limits.AttemptMillis = 60000
	server := f.endpoint(t, nil)
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")),
		Source: f.nodes[0].node, Ingress: w.node, Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix,
		Trust: f.domain.Trust, MaxBytes: 1 << 20, MaxObjects: 32}
	raw, err := ingress.SignAuthority(a, f.owner)
	must(t, err)
	f.cfg.Ingress = []json.RawMessage{raw}
	f.config(t, 1, nil)
	ctx := context.Background()
	stop := start(t, w)
	waitActive := func() {
		wait(t, func() bool {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.active != nil
		})
	}
	waitActive()

	i := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte("object body observation")),
		Authority: storage.Hash(raw), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress,
		Domain: a.Trust.Domain, Repository: a.Trust.Repository, Epoch: a.Trust.Epoch, Sequence: 1, Policy: 1,
		SnapshotUnix: time.Now().Unix(), NotBefore: a.NotBefore, ExpiresUnix: a.ExpiresUnix, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	owner := f.owner.Public().(ed25519.PublicKey)
	intent, err := ingress.SignIntent(i, raw, owner, f.writer, time.Now())
	must(t, err)
	client, err := ingress.NewClient(server.URL, raw, intent, owner, f.nodes[0].cert, f.ca.pool,
		peer.Limits{Concurrency: 1, Timeout: 60 * time.Second, Attempts: 1})
	must(t, err)
	defer client.Close()
	must(t, client.Begin(ctx))

	write := func(ctx context.Context, body []byte, newObject bool) {
		t.Helper()
		created, err := client.Write(ctx, filekit.Object{ID: storage.Hash(body), Bytes: len(body)}, body)
		must(t, err)
		if created != newObject {
			t.Fatalf("unexpected object acknowledgement: created=%v", created)
		}
	}
	observation := func() []IngressObjectBodyObservation {
		t.Helper()
		local, err := w.LocalStatus(ctx)
		must(t, err)
		return local.IngressObjectBodyObservations
	}
	// The HTTP path enqueues best-effort telemetry. A single acknowledged PUT
	// can outlive the recorder's opportunistic disk admission for that sample.
	// Require a real end-to-end sample within a small, bounded set of PUTs.
	observeWrite := func(body []byte, newObject bool) ([]byte, IngressObjectBodyObservation) {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		route := ingressBodyRoute(a)
		var wanted IngressObjectBodyObservation
		const attempts = 8
		for attempt := 0; attempt < attempts && bounded.Err() == nil; attempt++ {
			candidate := body
			if newObject && attempt != 0 {
				// Each retry of the new-object assertion must itself admit a
				// distinct object, distinguishable by its observed byte count.
				candidate = append(bytes.Clone(body), bytes.Repeat([]byte{'.'}, attempt)...)
			}
			wanted = IngressObjectBodyObservation{Route: route, ObservedUnixMillis: time.Now().UnixMilli(), AcceptedBodyBytes: len(candidate)}
			if !newObject {
				wanted.AlreadyPresentBodyBytes = len(candidate)
			}
			write(bounded, candidate, newObject)
			for until := time.Now().Add(500 * time.Millisecond); time.Now().Before(until) && bounded.Err() == nil; {
				status, err := w.LocalStatus(bounded)
				if bounded.Err() != nil {
					break
				}
				must(t, err)
				if samples := status.IngressObjectBodyObservations; len(samples) == 1 &&
					samples[0].Route == wanted.Route && samples[0].ObservedUnixMillis >= wanted.ObservedUnixMillis &&
					samples[0].AcceptedBodyBytes == wanted.AcceptedBodyBytes && samples[0].AlreadyPresentBodyBytes == wanted.AlreadyPresentBodyBytes {
					return candidate, samples[0]
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		w.mu.Lock()
		observerLive, queued := w.active != nil && w.active.ingressBodies != nil, 0
		if observerLive {
			queued = len(w.active.ingressBodies)
		}
		w.mu.Unlock()
		stop()
		// Diagnose storage and signed readback without the active consumer.
		// A direct write never satisfies the end-to-end assertion above.
		before := observation()
		probe, abort := context.WithTimeout(ctx, 3*time.Second)
		defer abort()
		writeError := w.writeIngressObjectBody(probe, wanted)
		after, readError := w.LocalStatus(probe)
		t.Fatalf("accepted PUTs did not yield the required observation: new=%v observer=%v queued=%d before=%d quiescentWrite=%v quiescentRead=%v after=%d",
			newObject, observerLive, queued, len(before), writeError, readError, len(after.IngressObjectBodyObservations))
		return nil, IngressObjectBodyObservation{}
	}
	awaitObservation := func(length, alreadyPresent int) IngressObjectBodyObservation {
		t.Helper()
		var found IngressObjectBodyObservation
		wait(t, func() bool {
			samples := observation()
			if len(samples) != 1 {
				return false
			}
			found = samples[0]
			return found.Route == ingressBodyRoute(a) && found.AcceptedBodyBytes == length && found.AlreadyPresentBodyBytes == alreadyPresent
		})
		return found
	}
	if len(observation()) != 0 {
		t.Fatal("an unobserved route reported traffic")
	}
	body, _ := observeWrite([]byte("first accepted object body"), true)
	_, previous := observeWrite(body, false)
	stop()
	reopened, err := Open(Options{Directory: w.dir, Node: w.node, Owner: owner, Certificate: w.cert,
		Roots: f.ca.pool, ObserveIngressObjectBodies: true})
	must(t, err)
	local, err := reopened.LocalStatus(ctx)
	must(t, errors.Join(err, reopened.Close()))
	if samples := local.IngressObjectBodyObservations; len(samples) != 1 || samples[0] != previous {
		t.Fatal("reopen changed the original observation", samples)
	}

	stop = start(t, w)
	defer stop()
	waitActive()
	if after := awaitObservation(len(body), len(body)); after != previous {
		t.Fatal("restart changed the original observation")
	}
	older := previous
	older.ObservedUnixMillis--
	older.AlreadyPresentBodyBytes = 0
	must(t, w.writeIngressObjectBody(ctx, older))
	if samples := observation(); len(samples) != 1 || samples[0] != previous {
		t.Fatal("late persistence replaced a newer observation", samples)
	}

	budget, err := w.budget.Status(ctx)
	must(t, err)
	remaining := budget.Limits.Telemetry - budget.Used["telemetry"]
	if remaining < diskbudget.WriteCharge(1) || remaining > 1<<20 {
		t.Fatal("fixture telemetry headroom unavailable", remaining)
	}
	// Hold all but a sub-block of the existing telemetry allowance without
	// affecting data space. A reservation is independent of compression.
	const block = 4096
	fill := (remaining-diskbudget.WriteCharge(1))/block*block + block
	release, err := w.budget.Reserve(ctx, "telemetry/fixture-reservation", int(fill))
	must(t, err)
	defer func() { must(t, release(false)) }()
	other := []byte("another object accepted with exhausted telemetry")
	write(ctx, other, true)
	err = w.writeIngressObjectBody(ctx, IngressObjectBodyObservation{
		Route: ingressBodyRoute(a), ObservedUnixMillis: time.Now().UnixMilli(), AcceptedBodyBytes: len(other),
	})
	if !errors.Is(err, statefile.ErrCapacity) {
		t.Fatalf("telemetry limit did not refuse the sample: %v", err)
	}
	if samples := observation(); len(samples) != 1 || samples[0] != previous {
		t.Fatal("telemetry refusal replaced the previous observation", samples)
	}
	stop()
	sidecar, err := statefile.OpenAt(w.root, ingressBodiesDirectory, maxIngressBodyObservation, false)
	must(t, err)
	defer sidecar.Close()
	name := previous.Route + ".json"
	signed, err := sidecar.Read(name)
	must(t, err)
	must(t, sidecar.Write(name, []byte("{}")))
	if samples := observation(); len(samples) != 0 {
		t.Fatal("an unsupported telemetry record supplied evidence", samples)
	}
	must(t, sidecar.Write(name, signed))
	if samples := observation(); len(samples) != 1 || samples[0] != previous {
		t.Fatal("valid historical sample missing before the policy change", samples)
	}

	revoked := f.cfg
	revoked.Node, revoked.Domains = w.node, []control.Domain{f.domain}
	revoked.Revision++
	revoked.Ingress = nil
	newConfig, err := control.Sign(revoked, f.owner)
	must(t, err)
	beforeGuard := w.guard
	defer func() { w.guard = beforeGuard }()
	guardChecks := 0
	replaced := false
	w.guard = func(ctx context.Context) error {
		guardChecks++
		if guardChecks == 2 {
			err := w.cache.Accept(ctx, newConfig, time.Now())
			replaced = err == nil
			return err
		}
		return nil
	}
	if samples := observation(); !replaced || len(samples) != 0 {
		t.Fatal("retired ingress route stayed visible during status readback", replaced, samples)
	}
}
