package ingress

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestActiveInspectionDistinguishesDurableFenceFromNonAdmission(t *testing.T) {
	ctx := t.Context()
	f := registryNetwork(t)
	i := f.intent
	i.NotBefore = f.authority.NotBefore
	i.ExpiresUnix = i.NotBefore + 2
	raw, err := SignIntent(i, f.options.Authority, f.options.Owner, f.writer, time.Unix(i.NotBefore, 0))
	must(t, err)
	f.fixture.options.Intent = raw
	now := time.Now().Unix()
	grant := Settlement{Format: SettlementFormat, Purpose: SettlementInspect,
		ID: storage.Hash([]byte("inspect")), Authority: i.Authority, Intent: storage.Hash(raw),
		Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant,
		Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, NotBefore: now, ExpiresUnix: now + 300}
	signed, err := SignSettlement(grant, f.options.Authority, raw, f.control, time.Now())
	must(t, err)
	c := provisionSettlement(t, f, signed)
	report, err := c.Reconcile(ctx)
	must(t, err)
	if report.Phase != "UNKNOWN" {
		t.Fatal("registry created after the intent gave a negative proof", report)
	}
	// Simulate a registry already durable before the historical intent.
	f.registry.mu.Lock()
	f.registry.state.ObservedUnix = i.NotBefore
	err = f.registry.save()
	f.registry.mu.Unlock()
	must(t, err)
	f.reopen(t)
	report, err = c.Reconcile(ctx)
	must(t, err)
	if report.Phase != "NOT_ADMITTED" {
		t.Fatal("initial inspected receiver had unexpected evidence", report)
	}
	if _, err = c.SettlementReceipt(ctx); !errors.Is(err, ErrDenied) {
		t.Fatal("inspection was allowed to retrieve a receipt", err)
	}
	if err = c.Begin(ctx); !errors.Is(err, ErrDenied) {
		t.Fatal("inspection was allowed to admit", err)
	}
	if _, err = f.registry.root.Lstat("current"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection created a session", err)
	}
	// Model a process exit immediately after the intent fence was synced.
	f.registry.mu.Lock()
	f.registry.state.Intent = raw
	err = f.registry.save()
	f.registry.mu.Unlock()
	must(t, err)
	f.reopen(t)
	report, err = c.Reconcile(ctx)
	must(t, err)
	if report.Phase != "FENCED" {
		t.Fatal("durable fence was mistaken for no admission", report)
	}
}

func TestRegistryReadinessLeavesNoFenceAndRequiresExactParent(t *testing.T) {
	f := registryNetwork(t)
	ctx := t.Context()
	must(t, f.client.Ready(ctx))
	i := f.intent
	i.Sequence++
	i.Parent = storage.Hash([]byte("missing predecessor"))
	raw, err := SignIntent(i, f.options.Authority, f.options.Owner, f.writer, time.Now())
	must(t, err)
	c, err := NewClient(f.server.URL, f.options.Authority, raw, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, err)
	defer c.Close()
	if err = c.Ready(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal("readiness accepted a missing exact predecessor", err)
	}
	if err = c.Begin(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal("admission accepted a missing exact predecessor", err)
	}
	if len(f.registry.state.Intent) != 0 {
		t.Fatal("readiness or rejected admission fenced the receiver")
	}
}

func TestRegistryRejectsCapacityBeforeFencingAndKeepsExactReplay(t *testing.T) {
	f := registryNetwork(t)
	ctx := t.Context()
	var full atomic.Bool
	full.Store(true)
	f.registry.mu.Lock()
	f.registry.options.CheckRegistryWrite = func(_ context.Context, size int) error {
		if size <= len(f.fixture.options.Intent) {
			return ErrProtocol
		}
		if full.Load() {
			return statefile.ErrCapacity
		}
		return nil
	}
	f.registry.mu.Unlock()
	if err := f.client.Ready(ctx); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("readiness did not report exhausted metadata capacity", err)
	}
	if err := f.client.Begin(ctx); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("admission did not reject exhausted metadata capacity", err)
	}
	f.registry.mu.Lock()
	fenced := len(f.registry.state.Intent) != 0 || f.registry.poisoned
	f.registry.mu.Unlock()
	if fenced {
		t.Fatal("capacity rejection modified the receiver fence")
	}
	full.Store(false)
	must(t, f.client.Ready(ctx))
	must(t, f.client.Begin(ctx))
	full.Store(true)
	must(t, f.client.Ready(ctx))
	must(t, f.client.Begin(ctx))
}

func TestGenerationCapacityReportsOverlapAndCreditsRetainedObjects(t *testing.T) {
	f := registryNetwork(t)
	ctx := t.Context()
	f.registry.mu.Lock()
	f.registry.options.CheckPublication = func(_ context.Context, peak diskbudget.Peak) error {
		return &diskbudget.PeakError{Required: peak}
	}
	f.registry.mu.Unlock()
	must(t, f.client.Begin(ctx))
	version, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
	must(t, err)
	raw, roots := f.catalog(t, []string{version.Version})
	refs, err := generation.Dependencies(raw, f.authority.Trust)
	must(t, err)
	if len(refs) == 0 || len(roots) == 0 {
		t.Fatal("test needs staged dependencies and a missing root")
	}
	var replica, unstaged int64
	for _, ref := range refs {
		replica += diskbudget.WriteCharge(ref.Bytes)
		if _, ok := roots[ref.ID]; ok {
			unstaged += diskbudget.WriteCharge(ref.Bytes)
		}
	}
	_, _, err = f.client.FinishStep(ctx, raw)
	var short *diskbudget.PeakError
	if !errors.As(err, &short) || short.Required.Data != replica+unstaged || short.Required.Spool == 0 {
		t.Fatal("estimate omitted staging or publication overlap", err)
	}
	status, err := f.options.Replica.Status(ctx)
	must(t, err)
	if len(status.Receiving) != 0 || status.LatestComplete != "" {
		t.Fatal("capacity check published or fenced a replica", status)
	}
	for id, b := range roots {
		_, err = f.client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, err)
	}
	ref := refs[0]
	payload, err := f.client.Read(ctx, filekit.Object{ID: ref.ID, Bytes: ref.Bytes})
	must(t, err)
	id, err := f.options.Replica.Begin(ctx, raw)
	must(t, err)
	must(t, f.options.Replica.Put(ctx, id, ref.ID, payload))
	_, _, err = f.client.FinishStep(ctx, raw)
	if !errors.As(err, &short) || short.Required.Data != replica-diskbudget.WriteCharge(ref.Bytes) || short.Required.Spool == 0 {
		t.Fatal("restart estimate counted an already staged or retained object", err)
	}
	f.registry.mu.Lock()
	f.registry.session.admitPublication = func(context.Context, diskbudget.Peak) error { return nil }
	f.registry.mu.Unlock()
	_, receipt, err := f.client.FinishStep(ctx, raw)
	must(t, err)
	if receipt == nil || receipt.Generation != id {
		t.Fatal("restored capacity did not allow exact publication", receipt)
	}
}

func TestGenerationCapacityResumesWithDurableVerification(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	must(t, os.WriteFile(f.input, []byte("capture with a durable verification checkpoint"), 0600))
	version, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"file"}})
	must(t, err)
	raw, roots := f.catalog(t, []string{version.Version})
	f.roots(t, roots)
	partial, _, err := f.session.FinishBatch(ctx, raw, 1, generation.MaxObject)
	must(t, err)
	if partial.Complete || partial.VerifiedObjects != 1 {
		t.Fatalf("fixture did not leave a partial checkpoint: %+v", partial)
	}

	// The ledger measures the fixture's existing staged data and partial
	// checkpoint. Subsequent session and replica writes use its real admission.
	limits := diskbudget.Limits{Capacity: 64 << 20, Reserve: 1 << 20, Spool: 8 << 20, Telemetry: 1 << 20}
	budget, err := diskbudget.Open(ctx, f.base, limits, true)
	must(t, err)
	defer budget.Close()
	var observed diskbudget.Peak
	f.options.CheckPublication = func(ctx context.Context, peak diskbudget.Peak) error {
		observed = peak
		return budget.CheckPeak(ctx, peak)
	}
	f.options.AdmitState = budget.Admission("session/state")
	f.options.AdmitObject = budget.Admission("session/objects")
	replica := f.options.Replica
	admitReplica := budget.Admission("replica")
	replica.Admit = admitReplica
	f.reopen(t)
	interrupted := errors.New("publication stopped after verification")
	replica.Fault = func(point string) error {
		if point == "before-complete" {
			return interrupted
		}
		return nil
	}
	if _, _, err = f.session.FinishBatch(ctx, raw, 256, 256<<20); !errors.Is(err, interrupted) {
		t.Fatalf("did not interrupt index publication: %v", err)
	}
	partialSpool := observed.Spool
	replica.Fault = nil
	f.reopen(t)

	// A second client reserves space for a concurrent metadata write. Keep
	// enough headroom for the final index and receipt but below the old peak.
	var available *diskbudget.PeakError
	if err = budget.CheckPeak(ctx, diskbudget.Peak{Spool: limits.Spool}); !errors.As(err, &available) {
		t.Fatalf("could not measure metadata headroom: %v", err)
	}
	headroom := partialSpool - diskbudget.WriteCharge(1)
	reserveBytes := available.Available.Spool - headroom - diskbudget.WriteCharge(1)
	if headroom <= 0 || reserveBytes <= 0 {
		t.Fatalf("invalid fixture capacity: partial=%d, available=%d", partialSpool, available.Available.Spool)
	}
	other, err := diskbudget.Open(ctx, f.base, limits, false)
	must(t, err)
	defer other.Close()
	finish, err := other.Reserve(ctx, "concurrent-metadata.json", int(reserveBytes))
	must(t, err)
	defer func() { must(t, finish(false)) }()
	var short *diskbudget.PeakError
	if err = budget.CheckPeak(ctx, diskbudget.Peak{Spool: partialSpool}); !errors.As(err, &short) || short.Available.Spool >= partialSpool {
		t.Fatalf("ledger did not reject the old metadata peak: %v", err)
	}
	before, err := budget.Status(ctx)
	must(t, err)
	if len(before.Pending) != 1 {
		t.Fatalf("concurrent reservation is missing: %+v", before.Pending)
	}

	verificationWrites := 0
	replica.Admit = func(name string, size int) (func(bool) error, error) {
		if strings.HasPrefix(name, "verification/") {
			verificationWrites++
		}
		return admitReplica(name, size)
	}
	result, receipt, err := f.session.FinishBatch(ctx, raw, 256, 256<<20)
	must(t, err)
	if observed.Data != 0 || observed.Spool <= 0 || observed.Spool > short.Available.Spool ||
		!result.Complete || result.ReadBytes != 0 || receipt.Generation != storage.Hash(raw) || verificationWrites != 0 {
		t.Fatalf("unexpected estimate or completed receipt: %+v, %+v, %+v, writes=%d", observed, result, receipt, verificationWrites)
	}
	after, err := budget.Status(ctx)
	must(t, err)
	if after.Revision <= before.Revision || len(after.Pending) != len(before.Pending) {
		t.Fatalf("publication did not use the ledger or lost the concurrent reservation: %+v", after)
	}
	for id, reservation := range before.Pending {
		if after.Pending[id] != reservation {
			t.Fatal("publication changed the other client's reservation")
		}
	}
	t.Logf("metadata bytes: old peak %d, available %d, resumed peak %d", partialSpool, short.Available.Spool, observed.Spool)
}
