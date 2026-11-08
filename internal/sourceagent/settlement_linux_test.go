package sourceagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

type settlementReplyBuffer struct {
	*httptest.ResponseRecorder
	underlying http.ResponseWriter
}

func (b *settlementReplyBuffer) Unwrap() http.ResponseWriter { return b.underlying }

func (f *fixture) settlement(t *testing.T) control.SettlementAdmission {
	t.Helper()
	item, e := f.a.SettlementPreview(context.Background())
	must(t, e)
	item, e = SignSettlementAdmission(item, f.ownerSigner)
	must(t, e)
	return item
}
func (f *fixture) provisionSettlement(t *testing.T, item control.SettlementAdmission) {
	t.Helper()
	f.registryMu.Lock()
	defer f.registryMu.Unlock()
	must(t, f.registry.Close())
	g, e := ingress.OpenRegistry(context.Background(), ingress.RegistryOptions{Directory: filepath.Join(f.base, "registry"), Authority: item.Authority, Settlement: item.Grant, SettlementIntent: item.Intent, Owner: f.b.Local.Owner, Replica: f.replica, Certificate: f.destination, Roots: f.roots, Limits: peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1}, Initialize: false})
	must(t, e)
	f.registry = g
}
func (f *fixture) expire(t *testing.T) {
	t.Helper()
	time.Sleep(time.Until(time.Unix(f.grant.ExpiresUnix, 0)) + 30*time.Millisecond)
	if _, e := ingress.VerifyAuthority(f.authority, f.b.Local.Owner, time.Now()); e == nil {
		t.Fatal("original authority still current")
	}
}

func TestSourceSettlementLostReceiptPreservesOriginalAgeAndBothGenerations(t *testing.T) {
	f := newFixtureLifetime(t, 10)
	ctx := context.Background()
	expectedOld, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	old, e := f.a.Status(ctx)
	must(t, e)
	expectedNew := bytes.Clone(expectedOld)
	copy(expectedNew[100:110], []byte("new-value!"))
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), expectedNew, 0640))
	must(t, f.a.Next(ctx))
	var original ingress.Receipt
	f.registryMu.Lock()
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/catalog") {
			return false
		}
		recorded := &settlementReplyBuffer{ResponseRecorder: httptest.NewRecorder(), underlying: w}
		f.registry.ServeHTTP(recorded, r)
		var reply struct {
			Progress generation.BatchResult `json:"progress"`
			Receipt  *ingress.Receipt       `json:"receipt,omitempty"`
		}
		if recorded.Code == 200 && json.Unmarshal(recorded.Body.Bytes(), &reply) == nil && reply.Receipt != nil {
			original = *reply.Receipt
			http.Error(w, "lost original reply", 503)
			return true
		}
		for name, values := range recorded.Header() {
			w.Header()[name] = append([]string(nil), values...)
		}
		w.WriteHeader(recorded.Code)
		_, _ = w.Write(recorded.Body.Bytes())
		return true
	}
	f.registryMu.Unlock()
	if f.a.Run(ctx) == nil {
		t.Fatal("lost reply unexpectedly completed source")
	}
	f.registryMu.Lock()
	f.intercept = nil
	f.registryMu.Unlock()
	if original.Generation == "" {
		t.Fatal("receiver did not durably complete")
	}
	f.expire(t)
	f.reopen(t)
	before, e := f.a.Status(ctx)
	must(t, e)
	if before.Job == nil || before.Job.Phase != "SEALED" || before.Sequence != old.Sequence {
		t.Fatal("lost-reply pending state changed", before)
	}
	if f.a.Run(ctx) == nil {
		t.Fatal("ordinary expired capture resumed")
	}
	s, e := f.a.load()
	must(t, e)
	readonly, close, e := f.a.openJobMode(ctx, s, true, nil)
	must(t, e)
	if readonly.Run(ctx) == nil {
		t.Fatal("inspection mode allowed execution")
	}
	close()
	item := f.settlement(t)
	if f.a.Settle(ctx, item) == nil {
		t.Fatal("unprovisioned settlement accepted")
	}
	f.provisionSettlement(t, item)
	// This operation is already sealed. Its source bytes need not remain readable.
	must(t, os.Rename(f.tree, f.tree+"-offline"))
	must(t, f.a.Settle(ctx, item))
	f.reopen(t)
	must(t, f.a.Settle(ctx, item))
	after, e := f.a.Status(ctx)
	must(t, e)
	if after.Phase != "COMPLETE" || after.Sequence != 2 || after.Generation != original.Generation {
		t.Fatal("wrong settlement head", after)
	}
	cp, e := f.a.Checkpoint(ctx)
	must(t, e)
	checkpoint, e := capture.VerifyCheckpoint(cp, f.grant.Trust)
	must(t, e)
	if checkpoint.Receipt != original || checkpoint.Copies[0].ObservedUnix != original.VerifiedAt {
		t.Fatal("settlement refreshed original verification age")
	}
	current, e := f.a.load()
	must(t, e)
	if !bytes.Equal(current.Intent, s.Intent) {
		t.Fatal("immutable intent changed")
	}
	if f.a.Next(ctx) == nil {
		t.Fatal("settlement renewed payload authority")
	}
	for index, selected := range []struct {
		generation string
		expected   []byte
	}{{old.Generation, expectedOld}, {after.Generation, expectedNew}} {
		out := filepath.Join(f.base, []string{"restore-old", "restore-new"}[index])
		_, e = generation.RecoverMaterialized(ctx, f.replicaPath, selected.generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		if !bytes.Equal(got, selected.expected) {
			t.Fatal("settlement damaged version", index)
		}
	}
}

func TestSourceSettlementRequiresDurableReceiptAndExactPendingGeneration(t *testing.T) {
	f := newFixtureLifetime(t, 5)
	ctx := context.Background()
	must(t, f.a.Next(ctx))
	if _, e := f.a.SettlementPreview(ctx); e == nil {
		t.Fatal("unsealed preview admitted")
	}
	f.a.Fault = func(p string) error {
		if p == "source-catalog-durable" {
			return errors.New("stop before remote finish")
		}
		return nil
	}
	if f.a.Run(ctx) == nil {
		t.Fatal("fault not reached")
	}
	f.expire(t)
	f.reopen(t)
	item := f.settlement(t)
	f.provisionSettlement(t, item)
	if f.a.Settle(ctx, item) == nil {
		t.Fatal("missing receipt invented")
	}
	s, e := f.a.Status(ctx)
	must(t, e)
	if s.Job == nil || s.Job.Phase != "SEALED" || s.Sequence != 0 {
		t.Fatal("missing receipt advanced head", s)
	}
	var g ingress.Settlement
	must(t, json.Unmarshal(item.Grant, &g))
	g.Generation = storage.Hash([]byte("different-generation"))
	wrong := item
	wrong.Grant, e = ingress.SignSettlement(g, item.Authority, item.Intent, f.ownerSigner, time.Now())
	must(t, e)
	if f.a.Settle(ctx, wrong) == nil {
		t.Fatal("wrong sealed generation admitted")
	}
	wrong = item
	wrong.Grant = append([]byte(nil), item.Grant...)
	wrong.Grant[len(wrong.Grant)-3] ^= 1
	if f.a.Settle(ctx, wrong) == nil {
		t.Fatal("tampered grant accepted")
	}
	if _, e = f.a.Checkpoint(ctx); e == nil {
		t.Fatal("uncertain operation made checkpoint")
	}
}

func TestSourceSettlementDoesNotBypassExpiredSecondCopyPermission(t *testing.T) {
	f := newFixtureLifetime(t, 5)
	ctx := context.Background()
	// Set the two-copy profile before any source operation exists.
	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "two-copy-source")
	other := storage.Hash([]byte("independent-copy"))
	f.b.Profile.MinimumCopies = 2
	f.b.Profile.CopyTargets = append(f.b.Profile.CopyTargets, other)
	g := observation.Grant{Format: observation.GrantFormat, Trust: f.grant.Trust, Reader: f.grant.Source, Collector: f.grant.Ingress, Targets: []string{other}, Epoch: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix, MaxAgeSeconds: 3600}
	raw, e := observation.SignGrant(g, f.ownerSigner)
	must(t, e)
	f.b.ObservationFile = filepath.Join(f.base, "two-copy-grant.json")
	must(t, os.WriteFile(f.b.ObservationFile, raw, 0600))
	f.a, e = Open(ctx, f.b, true)
	must(t, e)
	must(t, f.a.Next(ctx))
	f.a.Fault = func(p string) error {
		if p == "source-receipt-durable" {
			return errors.New("stop before copy observation")
		}
		return nil
	}
	if f.a.Run(ctx) == nil {
		t.Fatal("receipt fault not reached")
	}
	f.expire(t)
	f.reopen(t)
	item := f.settlement(t)
	f.provisionSettlement(t, item)
	if f.a.Settle(ctx, item) == nil {
		t.Fatal("expired second-copy permission bypassed")
	}
	s, e := f.a.Status(ctx)
	must(t, e)
	if s.Job == nil || s.Job.Phase != "WAITING_COPIES" || s.Sequence != 0 {
		t.Fatal("copy threshold downgraded", s)
	}
	if _, e = f.a.Checkpoint(ctx); e == nil {
		t.Fatal("checkpoint without required copy")
	}
}
