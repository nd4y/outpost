package ingress

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
)

func TestRetiredUnsealedSlotKeepsStagingUntilFreshSameSequenceAdmission(t *testing.T) {
	ctx := t.Context()
	f := registryNetwork(t)
	previous, _, _ := f.complete(t)
	ack, err := f.client.AcknowledgeStep(ctx, previous)
	must(t, err)
	if !ack.Clean {
		t.Fatal("previous generation was not acknowledged")
	}
	f.next(t, previous)
	i := f.intent
	i.NotBefore = time.Now().Unix()
	i.SnapshotUnix, i.ExpiresUnix = i.NotBefore, i.NotBefore+20
	raw, err := SignIntent(i, f.options.Authority, f.options.Owner, f.writer, time.Now())
	must(t, err)
	f.fixture.options.Intent = raw
	old, err := NewClient(f.server.URL, f.options.Authority, raw, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, err)
	defer old.Close()
	must(t, old.Begin(ctx))
	payload := []byte("temporary ciphertext for the exact old operation")
	ref := filekit.Object{ID: storage.Hash(payload), Bytes: len(payload)}
	_, err = old.Write(ctx, ref, payload)
	must(t, err)
	stage := filepath.Join(f.options.Directory, "current", "objects", ref.ID)
	f.registry.mu.Lock()
	basePin := f.registry.session.pin("base")
	f.registry.mu.Unlock()

	next := i
	next.Operation = storage.Hash([]byte("fresh operation at the same sequence"))
	next.ExpiresUnix = f.authority.ExpiresUnix
	nextRaw, err := SignIntent(next, f.options.Authority, f.options.Owner, f.writer, time.Now())
	must(t, err)
	early, err := NewClient(f.server.URL, f.options.Authority, nextRaw, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, err)
	defer early.Close()
	if err = early.Ready(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal("a live unsealed slot was displaced", err)
	}
	timer := time.NewTimer(time.Until(time.Unix(i.ExpiresUnix, 0)) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	provision := func(seed string) *Client {
		t.Helper()
		now := time.Now().Unix()
		grant := Settlement{Format: SettlementFormat, Purpose: SettlementRetireUnsealed,
			ID: storage.Hash([]byte(seed)), Authority: i.Authority, Intent: storage.Hash(raw),
			Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant,
			Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, NotBefore: now, ExpiresUnix: now + 300}
		signed, err := SignSettlement(grant, f.options.Authority, raw, f.control, time.Now())
		must(t, err)
		return provisionSettlement(t, f, signed)
	}
	observer := provision("first retirement grant")
	report, err := observer.Reconcile(ctx)
	must(t, err)
	if report.Phase != "ADMITTED" {
		t.Fatal("preview did not distinguish the staged slot", report)
	}
	f.registry.mu.Lock()
	f.registry.Fault = func(point string) error {
		if point == "capture-unsealed-retirement-durable" {
			return errors.New("lost retirement reply")
		}
		return nil
	}
	f.registry.mu.Unlock()
	if _, err = observer.RetireUnsealed(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expected uncertain retirement reply", err)
	}
	observer = provision("replacement retirement grant")
	report, err = observer.RetireUnsealed(ctx)
	must(t, err)
	if report.Phase != UnsealedRetired {
		t.Fatal("durable retirement was not observed after restart", report)
	}
	data, err := os.ReadFile(stage)
	must(t, err)
	if !bytes.Equal(data, payload) {
		t.Fatal("retirement deleted or changed a staged object")
	}
	status, err := f.options.Replica.Status(ctx)
	must(t, err)
	if _, exists := status.Pins[basePin]; !exists || status.LatestComplete != previous.Generation {
		t.Fatal("retirement removed its predecessor protection", status)
	}
	if err = observer.Begin(ctx); !errors.Is(err, ErrDenied) {
		t.Fatal("retirement capability admitted a data operation", err)
	}

	must(t, f.registry.Close())
	f.registry = nil
	f.options.Settlement, f.options.SettlementIntent = nil, nil
	fresh := registryAuthority(t, f, 2)
	_, err = RenewRegistry(ctx, f.options, fresh, nil, nil)
	must(t, err)
	f.options.Authority = fresh
	f.registry, err = OpenRegistry(ctx, f.options)
	must(t, err)
	authority, err := VerifyAuthority(fresh, f.options.Owner, time.Now())
	must(t, err)
	next.Authority, next.Policy, next.NotBefore, next.ExpiresUnix = storage.Hash(fresh), authority.Revision, authority.NotBefore, authority.ExpiresUnix
	next.SnapshotUnix = time.Now().Unix()
	rewritten := next
	rewritten.Operation = i.Operation
	rewrittenRaw, err := SignIntent(rewritten, fresh, f.options.Owner, f.writer, time.Now())
	must(t, err)
	sameOperation, err := NewClient(f.server.URL, fresh, rewrittenRaw, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, err)
	defer sameOperation.Close()
	if err = sameOperation.Ready(ctx); !errors.Is(err, ErrConflict) {
		t.Fatal("retirement allowed the original operation identifier to return", err)
	}
	nextRaw, err = SignIntent(next, fresh, f.options.Owner, f.writer, time.Now())
	must(t, err)
	current, err := NewClient(f.server.URL, fresh, nextRaw, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, err)
	defer current.Close()
	must(t, current.Ready(ctx))
	f.registry.mu.Lock()
	f.registry.Fault = func(point string) error {
		if point == "capture-intent-durable" {
			return errors.New("lost replacement reply")
		}
		return nil
	}
	f.registry.mu.Unlock()
	if err = current.Begin(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expected uncertain replacement admission", err)
	}
	if _, err = os.Stat(stage); err != nil {
		t.Fatal("retained stage disappeared before the replacement commit", err)
	}
	f.reopen(t)
	must(t, current.Begin(ctx))
	if _, err = os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old stage survived successful slot replacement", err)
	}
	f.registry.mu.Lock()
	selected := f.registry.session.intent
	f.registry.mu.Unlock()
	if selected.Operation != next.Operation || selected.Sequence != i.Sequence {
		t.Fatal("replacement advanced the generation sequence")
	}
	must(t, f.options.Replica.VerifyComplete(ctx, previous.Generation))
}
