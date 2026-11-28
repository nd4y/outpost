package sourceagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/capture"
)

func TestSourceCaptureMeasurementsDistinguishUnavailableJobFromDamagedMetadata(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.Prepare(ctx, f.intent(t, 1, "")))
	must(t, f.a.Run(ctx))
	first, err := f.a.StatusWithCaptureMeasurements(ctx)
	must(t, err)
	if first.Phase != "COMPLETE" || first.CaptureMeasurements == nil {
		t.Fatal("expected completed local capture measurements")
	}

	// Retiring the source view leaves its local capture journal available.
	must(t, os.Rename(f.tree, f.tree+"-retired"))
	f.reopen(t)
	again, err := f.a.StatusWithCaptureMeasurements(ctx)
	must(t, err)
	if again.Generation != first.Generation || again.CaptureMeasurements == nil ||
		*again.CaptureMeasurements != *first.CaptureMeasurements {
		t.Fatal("retired source view affected local measurements")
	}

	job := filepath.Join(f.b.Local.Directory, "operations", first.Operation, "job")
	for _, file := range []string{"plan.json", "checkpoint.json"} {
		t.Run(file, func(t *testing.T) {
			metadata := filepath.Join(job, "state", file)
			backup := metadata + "-hidden"
			must(t, os.Rename(metadata, backup))
			t.Cleanup(func() { must(t, os.Rename(backup, metadata)) })
			if status, err := f.a.StatusWithCaptureMeasurements(ctx); !errors.Is(err, os.ErrNotExist) || status.CaptureMeasurements != nil {
				t.Fatalf("missing committed metadata was silently omitted: %+v, %v", status.CaptureMeasurements, err)
			}
			normal, err := f.a.Status(ctx)
			must(t, err)
			if normal.Generation != first.Generation || normal.CaptureMeasurements != nil {
				t.Fatal("ordinary status depends on the optional measurement")
			}
		})
	}

	t.Run("tampered-plan", func(t *testing.T) {
		metadata := filepath.Join(job, "state", "plan.json")
		raw, err := os.ReadFile(metadata)
		must(t, err)
		t.Cleanup(func() { must(t, os.WriteFile(metadata, raw, 0600)) })
		must(t, os.WriteFile(metadata, append(append([]byte(nil), raw...), '\n'), 0600))
		if status, err := f.a.StatusWithCaptureMeasurements(ctx); !errors.Is(err, capture.ErrInvalid) || status.CaptureMeasurements != nil {
			t.Fatalf("altered local plan did not fail measurement: %+v, %v", status.CaptureMeasurements, err)
		}
	})

	backup := job + "-hidden"
	must(t, os.Rename(job, backup))
	t.Cleanup(func() { must(t, os.Rename(backup, job)) })
	unavailable, err := f.a.StatusWithCaptureMeasurements(ctx)
	must(t, err)
	if unavailable.Phase != "COMPLETE" || unavailable.Generation != first.Generation || unavailable.CaptureMeasurements != nil {
		t.Fatal("completed checkpoint without local capture job reported a measurement")
	}
}
