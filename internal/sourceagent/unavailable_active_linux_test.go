package sourceagent

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
)

func TestSourceActiveCaptureSurvivesAllReceiversUnavailable(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	if f.b.Companion != nil || len(f.b.Profile.CopyTargets) != 1 || f.b.Profile.CopyTargets[0] != f.grant.Ingress {
		t.Fatal("expected one eligible, authenticated receiver")
	}
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	prior, err := f.a.Status(ctx)
	must(t, err)
	checkpoint, err := f.a.Checkpoint(ctx)
	must(t, err)
	if prior.Phase != "COMPLETE" || prior.Sequence != 1 {
		t.Fatal("old source generation did not complete", prior)
	}
	replica, err := generation.Open(f.replicaPath, f.grant.Trust, false)
	must(t, err)
	defer replica.Close()

	input := filepath.Join(f.tree, "private.bin")
	old, err := os.ReadFile(input)
	must(t, err)
	changed := bytes.Repeat([]byte("new bytes held through the active capture outage"), 8192)
	must(t, os.WriteFile(input, changed, 0640))
	must(t, f.a.Next(ctx))
	preparing, err := f.a.Status(ctx)
	must(t, err)
	if preparing.Phase != "PREPARING" || preparing.Operation == prior.Operation || preparing.Receiver != f.grant.Ingress {
		t.Fatal("new exact operation was not prepared while its receiver was healthy", preparing)
	}
	volume, err := os.Stat(f.b.Local.Volume.Root)
	must(t, err)
	operations := filepath.Join(f.b.Local.Directory, "operations")
	initialOps, err := os.ReadDir(operations)
	must(t, err)
	operation := filepath.Join(operations, preparing.Operation)
	view, err := os.Stat(filepath.Join(operation, "provider"))
	must(t, err)

	var down atomic.Bool
	var fileReceipts, refusals atomic.Int32
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if !down.Load() {
			return false
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 ||
			peer.Identity(r.TLS.PeerCertificates[0]) != f.grant.Source {
			t.Error("outage fixture received a request outside the authenticated source scope")
			http.Error(w, "wrong source", http.StatusForbidden)
			return true
		}
		refusals.Add(1)
		http.Error(w, "all eligible ingress unavailable", http.StatusServiceUnavailable)
		return true
	}
	f.a.Fault = func(point string) error {
		if point == "source-file-durable" && fileReceipts.Add(1) == 1 {
			down.Store(true)
		}
		return nil
	}

	failRun := func() {
		t.Helper()
		before := refusals.Load()
		if err := f.a.Run(ctx); !errors.Is(err, ingress.ErrUnavailable) || refusals.Load() <= before {
			t.Fatal("active capture did not reach an actual authenticated refusal", err)
		}
	}
	var peakCharged int64
	verifyPending := func() Status {
		t.Helper()
		s, err := f.a.Status(ctx)
		must(t, err)
		saved, err := f.a.Checkpoint(ctx)
		must(t, err)
		if s.Phase != "ACTIVE" || s.Operation != preparing.Operation || s.Receiver != preparing.Receiver ||
			s.Sequence != prior.Sequence || s.Generation != prior.Generation || !bytes.Equal(saved, checkpoint) ||
			s.Pending == nil || s.Pending.Action != "RESUME" || s.Job == nil || s.Job.CompletedFiles != 1 ||
			s.Job.Generation != "" || s.Job.Receipt != nil || len(s.Job.Copies) != 0 || s.Job.StagedRelease != "" ||
			s.Milestones == nil || s.Milestones.ProviderReleaseUnix != 0 {
			t.Fatal("failed active capture changed the head or advertised completion", s)
		}
		currentVolume, err := os.Stat(f.b.Local.Volume.Root)
		must(t, err)
		currentView, err := os.Stat(filepath.Join(operation, "provider"))
		must(t, err)
		if !os.SameFile(volume, currentVolume) || !os.SameFile(view, currentView) {
			t.Fatal("retry moved the admitted volume or replaced the original provider view")
		}
		currentOps, err := os.ReadDir(operations)
		must(t, err)
		if len(currentOps) != len(initialOps) {
			t.Fatal("retry admitted an extra source operation")
		}
		for i, entry := range currentOps {
			if entry.Name() != initialOps[i].Name() {
				t.Fatal("retry replaced an existing source operation")
			}
		}
		target, err := replica.Status(ctx)
		must(t, err)
		if target.LatestComplete != prior.Generation || len(target.Complete) != 1 || len(target.Receiving) != 0 {
			t.Fatal("receiver advanced or admitted a catalog while unavailable", target)
		}
		budget, err := f.a.budget.Status(ctx)
		must(t, err)
		var charged int64
		for _, size := range budget.Used {
			charged += size
		}
		for _, held := range budget.Pending {
			charged += held.Bytes
		}
		peakCharged = max(peakCharged, charged)
		if budget.Limits != f.b.Limits || charged > budget.Limits.Capacity-budget.Limits.Reserve {
			t.Fatal("retry exceeded its admitted source budget", charged, budget.Limits)
		}
		return s
	}

	failRun()
	if fileReceipts.Load() != 1 {
		t.Fatal("outage did not follow the actual durable file receipt", fileReceipts.Load())
	}
	pending := verifyPending()
	cache := filepath.Join(f.b.Local.Directory, "cache")
	cacheFiles, cacheBytes := unavailableCacheSnapshot(t, cache)
	const cacheLimit = 2 << 20
	if len(cacheFiles) == 0 || cacheBytes > cacheLimit {
		t.Fatal("active fixture exceeds its logical cache bound", cacheBytes)
	}

	for range 2 {
		f.reopen(t)
		must(t, f.a.Next(ctx))
		failRun()
		s := verifyPending()
		if s.Job.Plan != pending.Job.Plan || s.Milestones.SnapshotUnix != pending.Milestones.SnapshotUnix {
			t.Fatal("retry admitted a different plan or snapshot", s)
		}
		currentFiles, size := unavailableCacheSnapshot(t, cache)
		if size != cacheBytes || !reflect.DeepEqual(currentFiles, cacheFiles) {
			t.Fatal("unavailable receiver grew or changed the active cache", size, cacheBytes)
		}
	}

	owner := f.owner
	owner.SigningKey = nil
	restore := func(label, id string, want []byte) {
		t.Helper()
		output := filepath.Join(f.base, label)
		_, err := generation.RecoverMaterialized(ctx, f.replicaPath, id, f.grant.Trust, owner, generation.RecoverySelection{}, output)
		must(t, err)
		actual, err := os.ReadFile(filepath.Join(output, "private.bin"))
		must(t, err)
		if !bytes.Equal(actual, want) {
			t.Fatal("independently restored bytes differ", label)
		}
	}
	beforeRestore := refusals.Load()
	restore("old-while-active-receiver-unavailable", prior.Generation, old)
	if refusals.Load() != beforeRestore {
		t.Fatal("immutable recovery contacted unavailable ingress")
	}

	down.Store(false)
	must(t, f.a.Run(ctx))
	completed, err := f.a.Status(ctx)
	must(t, err)
	raw, err := f.a.Checkpoint(ctx)
	must(t, err)
	receipts, err := capture.VerifyCheckpoint(raw, f.grant.Trust)
	must(t, err)
	if completed.Phase != "COMPLETE" || completed.Sequence != 2 || completed.Operation != preparing.Operation ||
		completed.Generation == prior.Generation || completed.Receiver != preparing.Receiver ||
		receipts.Operation != completed.Operation || receipts.Generation != completed.Generation || len(receipts.Copies) != 1 ||
		receipts.Copies[0].Target != preparing.Receiver {
		t.Fatal("returning receiver did not finish the same operation exactly once", completed)
	}
	must(t, f.a.Run(ctx))
	target, err := replica.Status(ctx)
	must(t, err)
	if target.LatestComplete != completed.Generation || len(target.Complete) != 2 || len(target.Receiving) != 0 {
		t.Fatal("additional resume displaced protected history or published a duplicate", target)
	}
	must(t, f.a.Close())
	f.a = nil
	must(t, os.Rename(f.tree, filepath.Join(f.base, "source-offline")))
	down.Store(true)
	beforeRestore = refusals.Load()
	restore("old-after-active-receiver-return", prior.Generation, old)
	restore("new-after-active-receiver-return", completed.Generation, changed)
	if refusals.Load() != beforeRestore {
		t.Fatal("retained recovery depended on the source or ingress")
	}
	t.Logf("ACTIVE_INGRESS_OUTAGE receivers=1 refusedRequests=%d attempts=3 cacheBytes=%d sampledChargeBytes=%d durableFileReceipts=1 completeCopiesWhileUnavailable=0 preservedRestores=3",
		refusals.Load(), cacheBytes, peakCharged)
}
