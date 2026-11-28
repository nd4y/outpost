package sourceagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/storage"
)

func TestPrimaryIngressReadbackUsesDurableReceiptBeforeCopyCheckpoint(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	must(t, f.a.Next(ctx))
	options := StatusOptions{PrimaryIngressReadback: true}
	before, err := f.a.StatusWithOptions(ctx, options)
	must(t, err)
	if before.PrimaryIngressReadback != nil {
		t.Fatal("no full ingress readback was committed")
	}
	pause := errors.New("pause after durable ingress receipt")
	f.a.Fault = func(point string) error {
		if point == "source-receipt-durable" {
			return pause
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, pause) {
		t.Fatalf("full ingress receipt was not committed: %v", err)
	}
	normal, err := f.a.Status(ctx)
	must(t, err)
	if normal.Phase != "ACTIVE" || normal.Job == nil || normal.Job.Phase != "WAITING_COPIES" || normal.Job.Receipt == nil ||
		normal.PrimaryIngressReadback != nil || normal.Milestones == nil ||
		len(normal.Milestones.Replicas) != 0 || normal.Milestones.FirstReplicaVerifiedUnix != 0 {
		t.Fatalf("ordinary status or checkpoint milestones changed: %+v", normal)
	}
	legacy, err := json.Marshal(normal)
	must(t, err)
	if bytes.Contains(legacy, []byte(`"primaryIngressReadback"`)) {
		t.Fatal("the new field is present without opt-in")
	}
	jobFile := filepath.Join(f.b.Local.Directory, "operations", normal.Operation, "job", "state", "job.json")
	prior, err := os.ReadFile(jobFile)
	must(t, err)
	first, err := f.a.StatusWithOptions(ctx, options)
	must(t, err)
	receipt := normal.Job.Receipt
	want := capture.IngressReadback{Target: receipt.Ingress, Generation: receipt.Generation,
		Verification: "CIPHERTEXT_READBACK", Provenance: "RECEIVER_ATTESTED", VerifiedUnix: receipt.VerifiedAt}
	if first.PrimaryIngressReadback == nil || *first.PrimaryIngressReadback != want || len(first.Milestones.Replicas) != 0 {
		t.Fatalf("the persisted receipt did not produce an exact historical row: %+v", first.PrimaryIngressReadback)
	}
	encoded, err := json.Marshal(first)
	must(t, err)
	var projected struct {
		PrimaryIngressReadback map[string]json.RawMessage `json:"primaryIngressReadback"`
	}
	must(t, json.Unmarshal(encoded, &projected))
	if string(projected.PrimaryIngressReadback["provenance"]) != `"RECEIVER_ATTESTED"` ||
		string(projected.PrimaryIngressReadback["verification"]) != `"CIPHERTEXT_READBACK"` {
		t.Fatalf("verification kind or receipt provenance missing from status JSON: %v", projected.PrimaryIngressReadback)
	}
	// The optional view only reads the private journal, even when no receiver
	// is reachable and the source is reopened after the receipt checkpoint.
	f.server.Close()
	f.reopen(t)
	again, err := f.a.StatusWithOptions(ctx, options)
	must(t, err)
	if again.PrimaryIngressReadback == nil || *again.PrimaryIngressReadback != want {
		t.Fatal("offline restart changed the original readback", again.PrimaryIngressReadback)
	}
	later, err := os.ReadFile(jobFile)
	must(t, err)
	if !bytes.Equal(prior, later) {
		t.Fatal("reading ingress evidence changed the durable capture record")
	}
}

func TestPrimaryIngressReadbackRefusesMismatchedRouteClockAndCatalog(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	must(t, f.a.Next(ctx))
	pause := errors.New("pause after durable ingress receipt")
	f.a.Fault = func(point string) error {
		if point == "source-receipt-durable" {
			return pause
		}
		return nil
	}
	if err := f.a.Run(ctx); !errors.Is(err, pause) {
		t.Fatalf("full ingress receipt was not committed: %v", err)
	}
	first, err := f.a.Status(ctx)
	must(t, err)
	if first.Job == nil || first.Job.Receipt == nil || first.Milestones == nil {
		t.Fatal("the active job did not retain its full ingress receipt")
	}
	store := filepath.Join(f.b.Local.Directory, "operations", first.Operation, "job", "state")
	jobFile := filepath.Join(store, "job.json")
	job, err := os.ReadFile(jobFile)
	must(t, err)
	options := StatusOptions{PrimaryIngressReadback: true}
	for _, change := range []struct {
		name string
		edit func(*capture.State)
	}{
		{"wrong-receiver", func(s *capture.State) { s.Receipt.Ingress = storage.Hash([]byte("not selected")) }},
		{"wrong-tenant", func(s *capture.State) { s.Receipt.Tenant = storage.Hash([]byte("other tenant")) }},
		{"before-snapshot", func(s *capture.State) { s.Receipt.VerifiedAt = first.Milestones.SnapshotUnix - 1 }},
		{"after-commit-clock", func(s *capture.State) { s.Receipt.VerifiedAt = s.ObservedUnix + 1 }},
		{"substituted-generation", func(s *capture.State) {
			s.Generation = storage.Hash([]byte("wrong generation and receipt"))
			s.Receipt.Generation = s.Generation
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			var altered capture.State
			must(t, json.Unmarshal(job, &altered))
			change.edit(&altered)
			data, err := json.Marshal(altered)
			must(t, err)
			must(t, os.WriteFile(jobFile, data, 0600))
			t.Cleanup(func() { must(t, os.WriteFile(jobFile, job, 0600)) })
			status, err := f.a.StatusWithOptions(ctx, options)
			if status.PrimaryIngressReadback != nil || !errors.Is(err, capture.ErrInvalid) {
				t.Fatalf("unverified receipt produced a readback: %+v %v", status.PrimaryIngressReadback, err)
			}
		})
	}
	catalogFile := filepath.Join(store, "catalog.json")
	catalog, err := os.ReadFile(catalogFile)
	must(t, err)
	must(t, os.WriteFile(catalogFile, append(bytes.Clone(catalog), '\n'), 0600))
	t.Cleanup(func() { must(t, os.WriteFile(catalogFile, catalog, 0600)) })
	status, err := f.a.StatusWithOptions(ctx, options)
	if status.PrimaryIngressReadback != nil || !errors.Is(err, capture.ErrInvalid) {
		t.Fatalf("altered signed catalog produced a readback: %+v %v", status.PrimaryIngressReadback, err)
	}
}
