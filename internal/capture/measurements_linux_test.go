package capture

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestCaptureMeasurementsRequireAuthenticatedCommittedReceipts(t *testing.T) {
	f := setup(t, 1)
	ctx := context.Background()
	interrupted := errors.New("stop before committing the first file")
	f.job.Fault = func(point string) error {
		if point == "source-file-durable" {
			return interrupted
		}
		return nil
	}
	if err := f.job.Run(ctx); !errors.Is(err, interrupted) {
		t.Fatalf("capture missed interrupted receipt: %v", err)
	}
	unknown, err := f.job.Measurements(ctx)
	must(t, err)
	if unknown != nil {
		t.Fatalf("uncommitted receipt was counted: %+v", unknown)
	}

	f.reopen(t)
	must(t, f.job.Run(ctx))
	measured, err := f.job.Measurements(ctx)
	must(t, err)
	if measured == nil || measured.IncludedEntries != len(f.job.plan.Files) || measured.SourceReadBytes != int64(len(f.content)) ||
		measured.NewPayloadBytes <= 0 || measured.NewMetadataBytes <= 0 || measured.NewObjects <= 0 {
		t.Fatalf("unexpected committed measurements: %+v", measured)
	}
	f.reopen(t)
	again, err := f.job.Measurements(ctx)
	must(t, err)
	if again == nil || *again != *measured {
		t.Fatalf("reopened measurement changed: %+v", again)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := f.job.Measurements(canceled); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled measurement returned %+v, %v", got, err)
	}

	file := f.job.plan.Files[0].File
	raw, err := f.job.files.Read(file)
	must(t, err)
	var receipt fileReceipt
	must(t, json.Unmarshal(raw, &receipt))
	receipt.Stats.SourceBytes++
	modified, err := json.Marshal(receipt)
	must(t, err)
	must(t, f.job.files.Write(file, modified))
	if got, err := f.job.Measurements(ctx); got != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("modified receipt returned %+v, %v", got, err)
	}
}
