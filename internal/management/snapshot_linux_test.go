package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func snapshotBytes(t *testing.T, f *fixture) ([]byte, SnapshotTrust, SnapshotReceipt) {
	t.Helper()
	var b bytes.Buffer
	receipt, e := f.r.Snapshot(context.Background(), &b, 1, id("private-profile"), 8<<20)
	must(t, e)
	trust := SnapshotTrust{SnapshotTrustFormat, f.options.Owner, f.options.Signer.Public().(ed25519.PublicKey), receipt.Checkpoint}
	return b.Bytes(), trust, receipt
}
func TestManagementSnapshotIndependentHistoryPreservesAbandonment(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, req, _ := commandFixture(t, f)
	f.r.Fault = interruptAt("management-command-intent-durable")
	if _, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req); e == nil {
		t.Fatal("missing interruption")
	}
	f.reopen(t)
	input := resolutionInput(t, f, req.Operation)
	_, e := f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, req.Operation, input)
	must(t, e)
	// A secret-shaped unreferenced file and stale report slot must not be copied.
	must(t, os.WriteFile(filepath.Join(f.dir, "not-a-dependency.pem"), []byte("private material excluded"), 0600))
	before, e := f.r.store.Read("registry.json")
	must(t, e)
	raw, trust, receipt := snapshotBytes(t, f)
	if bytes.Contains(raw, []byte("private material excluded")) {
		t.Fatal("unreferenced material exported")
	}
	after, e := f.r.store.Read("registry.json")
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("snapshot changed live registry")
	}
	must(t, f.r.Close())
	f.r = nil
	// No registry, keys, service, peers, cache or HTTP endpoint is available.
	result, e := InspectSnapshot(ctx, bytes.NewReader(raw), trust, 8<<20)
	must(t, e)
	if result.SnapshotReceipt != receipt || result.State != "HISTORICAL" || result.CurrentState != "UNKNOWN" || result.ReplayAllowed || len(result.Receipts) != 4 || len(result.Audit) != 4 {
		t.Fatal(result)
	}
	found := false
	for _, r := range result.Receipts {
		if r.Operation == req.Operation {
			found = true
			if r.State != "ABANDONED" || r.ErrorCode != "OWNER_ABANDONED" {
				t.Fatal(r)
			}
		}
	}
	if !found {
		t.Fatal("lost original operation")
	}
}
func TestManagementSnapshotKeepsPublishedCommandsAndDurableCacheBeforeReceipt(t *testing.T) {
	for _, point := range []string{"management-config-cache-durable", "management-config-intent-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			cfg, req, _ := commandFixture(t, f)
			_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
			must(t, e)
			cfg.Revision = 2
			next := configurationMutation(t, f, cfg, "pending-policy", 1)
			preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, next)
			must(t, e)
			next.PreviewDigest = preview.CandidateDigest
			f.r.Fault = interruptAt(point)
			if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, next); e == nil {
				t.Fatal("missing interruption")
			}
			f.reopen(t)
			raw, trust, _ := snapshotBytes(t, f)
			out, e := InspectSnapshot(ctx, bytes.NewReader(raw), trust, 8<<20)
			must(t, e)
			for _, r := range out.Receipts {
				if r.Operation == req.Operation && r.State != "ADMITTED" {
					t.Fatal("invented command acknowledgement", r)
				}
			}
			// Inspection did not reconcile the interrupted receipt.
			current, e := f.r.Operation(ctx, f.p, f.e.Tenant, next.Operation)
			must(t, e)
			if current.State != "ADMITTED" {
				t.Fatal(current)
			}
		})
	}
}
func TestManagementSnapshotPendingFirstCacheAbsenceAndCorruptDependency(t *testing.T) {
	f := newFixture(t)
	f.enroll(t)
	ctx := context.Background()
	cfg := configFixture(t, f)
	input := configurationMutation(t, f, cfg, "pending-first-config", 0)
	p, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	input.PreviewDigest = p.CandidateDigest
	f.r.Fault = interruptAt("management-config-intent-durable")
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input); e == nil {
		t.Fatal("missing interruption")
	}
	f.reopen(t)
	raw, trust, _ := snapshotBytes(t, f)
	_, e = InspectSnapshot(ctx, bytes.NewReader(raw), trust, 8<<20)
	must(t, e)
	must(t, f.r.blobs.Write("candidate-"+p.CandidateDigest+".json", []byte("corrupt")))
	var out bytes.Buffer
	receipt, e := f.r.Snapshot(ctx, &out, 1, id("profile"), 8<<20)
	if e == nil || receipt.Checkpoint != "" || out.Len() != 0 {
		t.Fatal("corrupt closure exported", receipt, e, out.Len())
	}
}
func TestManagementSnapshotRejectsTruncatedTamperedUntrustedAndOversized(t *testing.T) {
	f := newFixture(t)
	f.enroll(t)
	raw, trust, _ := snapshotBytes(t, f)
	ctx := context.Background()
	for _, cut := range []int{0, len(snapshotMagic), len(snapshotMagic) + 4, len(raw) - 1} {
		if _, e := InspectSnapshot(ctx, bytes.NewReader(raw[:cut]), trust, 8<<20); e == nil {
			t.Fatal("truncation", cut)
		}
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-1] ^= 1
	for _, b := range [][]byte{corrupt, append(append([]byte(nil), raw...), 0), append(append([]byte(nil), raw...), raw...)} {
		if _, e := InspectSnapshot(ctx, bytes.NewReader(b), trust, 8<<20); e == nil {
			t.Fatal("invalid stream accepted")
		}
	}
	wrong := trust
	wrong.Checkpoint = id("older-snapshot")
	if _, e := InspectSnapshot(ctx, bytes.NewReader(raw), wrong, 8<<20); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	wrong = trust
	wrong.Owner = wrong.Signer
	if _, e := InspectSnapshot(ctx, bytes.NewReader(raw), wrong, 8<<20); e == nil {
		t.Fatal("wrong owner")
	}
	if _, e := InspectSnapshot(ctx, bytes.NewReader(raw), trust, int64(len(raw)-1)); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := InspectSnapshot(canceled, bytes.NewReader(raw), trust, 8<<20); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	oversized := append([]byte(snapshotMagic), 0xff, 0xff, 0xff, 0xff)
	if _, e := InspectSnapshot(ctx, bytes.NewReader(oversized), trust, 8<<20); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
}
func TestManagementSnapshotRejectsSignedPathInjectionAndMissingClosure(t *testing.T) {
	f := newFixture(t)
	_, _, _ = commandFixture(t, f)
	raw, trust, _ := snapshotBytes(t, f)
	size := int(binary.BigEndian.Uint32(raw[len(snapshotMagic) : len(snapshotMagic)+4]))
	start := len(snapshotMagic) + 4
	var original SnapshotManifest
	must(t, json.Unmarshal(raw[start:start+size], &original))
	payload := raw[start+size:]
	for _, change := range []func(*SnapshotManifest){
		func(m *SnapshotManifest) { m.Files[1].Path = "../outside" },
		func(m *SnapshotManifest) { m.Files = append(m.Files, m.Files[1]) },
		func(m *SnapshotManifest) { m.Files = m.Files[:len(m.Files)-1] },
		func(m *SnapshotManifest) { m.Files[1].Absent = true; m.Files[1].Digest = ""; m.Files[1].Size = 0 },
	} {
		encoded, _ := json.Marshal(original)
		var m SnapshotManifest
		must(t, json.Unmarshal(encoded, &m))
		change(&m)
		m.Signature = nil
		unsigned, _ := json.Marshal(m)
		m.Signature = ed25519.Sign(f.options.Signer, append([]byte(SnapshotFormat+"\x00"), unsigned...))
		encoded, _ = json.Marshal(m)
		header := append([]byte(snapshotMagic), make([]byte, 4)...)
		binary.BigEndian.PutUint32(header[len(snapshotMagic):], uint32(len(encoded)))
		stream := append(header, encoded...)
		stream = append(stream, payload...)
		selected := trust
		selected.Checkpoint = storage.Hash(encoded)
		if _, e := InspectSnapshot(context.Background(), bytes.NewReader(stream), selected, 8<<20); e == nil {
			t.Fatal("invalid signed dependency set accepted")
		}
	}
}

type failingSnapshotWriter struct{ left int }

func (w *failingSnapshotWriter) Write(b []byte) (int, error) {
	if len(b) > w.left {
		return 0, io.ErrClosedPipe
	}
	w.left -= len(b)
	return len(b), nil
}
func TestManagementSnapshotBoundsInterruptionAndSymlink(t *testing.T) {
	f := newFixture(t)
	f.enroll(t)
	ctx := context.Background()
	var b bytes.Buffer
	receipt, e := f.r.Snapshot(ctx, &b, 1, id("profile"), 1)
	if !errors.Is(e, ErrCapacity) || receipt.Checkpoint != "" || b.Len() != 0 {
		t.Fatal(receipt, e)
	}
	receipt, e = f.r.Snapshot(ctx, &failingSnapshotWriter{left: 64}, 1, id("profile"), 8<<20)
	if !errors.Is(e, io.ErrClosedPipe) || receipt.Checkpoint != "" {
		t.Fatal(receipt, e)
	}
	before, e := f.r.store.Read("registry.json")
	must(t, e)
	name := filepath.Join(f.dir, "registry.json")
	old := filepath.Join(f.dir, "saved-registry.json")
	must(t, os.Rename(name, old))
	must(t, os.Symlink(old, name))
	if _, e = f.r.Snapshot(ctx, &b, 1, id("profile"), 8<<20); e == nil {
		t.Fatal("symlink exported")
	}
	after, e := os.ReadFile(old)
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("source changed")
	}
}

func TestManagementSnapshotCurrentReportSlotAndDependencyChanges(t *testing.T) {
	f := newFixture(t)
	f.enroll(t)
	ctx := context.Background()
	now := time.Now().Unix()
	node := Principal{Actor: f.e.Node, Roles: []string{"node"}, Scopes: []Scope{{f.e.Tenant, id("domain")}}}
	_, e := f.r.PublishReport(ctx, node.Actor, f.e.Tenant, f.e.Node, f.report(t, 1, now))
	must(t, e)
	_, e = f.r.PublishReport(ctx, node.Actor, f.e.Tenant, f.e.Node, f.report(t, 2, now))
	must(t, e)
	raw, trust, _ := snapshotBytes(t, f)
	_, e = InspectSnapshot(ctx, bytes.NewReader(raw), trust, 8<<20)
	must(t, e)
	s, e := f.r.load()
	must(t, e)
	key := reportKey(f.e.Node, id("domain"))
	pointer := s.Reports[key]
	// Unreferenced old slot is deliberately corrupt and must not be copied.
	must(t, f.r.store.Write(reportFile(key, 1-pointer.Slot), []byte("old broken slot")))
	again, againTrust, _ := snapshotBytes(t, f)
	if !bytes.Equal(raw, again) || againTrust.Checkpoint != trust.Checkpoint {
		t.Fatal("unreferenced slot changed snapshot")
	}
	// Detect an out-of-band change between the planning and writing passes.
	mutated := false
	writer := snapshotMutatingWriter{fn: func() {
		if !mutated {
			mutated = true
			must(t, f.r.store.Write(reportFile(key, pointer.Slot), []byte("changed")))
		}
	}}
	receipt, e := f.r.Snapshot(ctx, &writer, 1, id("private-profile"), 8<<20)
	if e == nil || receipt.Checkpoint != "" {
		t.Fatal("changed dependency accepted", e)
	}
}

type snapshotMutatingWriter struct {
	bytes.Buffer
	fn func()
}

func (w *snapshotMutatingWriter) Write(b []byte) (int, error) { w.fn(); return w.Buffer.Write(b) }
