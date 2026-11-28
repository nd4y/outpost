package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
)

// CaptureMeasurements summarizes the successful file receipts of one capture route.
// Work without a committed file receipt does not contribute to this total.
type CaptureMeasurements struct {
	IncludedEntries  int   `json:"includedEntries"`
	SourceReadBytes  int64 `json:"sourceReadBytes"`
	NewPayloadBytes  int64 `json:"newPayloadBytes"`
	NewMetadataBytes int64 `json:"newMetadataBytes"`
	NewObjects       int64 `json:"newObjects"`
}

// Measurements reads only the committed prefix of the current local job. An
// inherited sealed catalog carries no file-receipt measurements for this route.
func (j *Job) Measurements(ctx context.Context) (*CaptureMeasurements, error) {
	if err := j.guard(ctx); err != nil {
		return nil, err
	}
	s, err := j.Status(ctx)
	if err != nil {
		return nil, err
	}
	if j.options.InheritedCatalog != "" || s.CompletedFiles == 0 {
		return nil, nil
	}
	if s.CompletedFiles > len(j.plan.Files) {
		return nil, ErrInvalid
	}
	var result CaptureMeasurements
	for _, file := range j.plan.Files[:s.CompletedFiles] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stats, err := j.readFileReceipt(s.Plan, file.File)
		if err != nil {
			return nil, err
		}
		for _, item := range []struct {
			total *int64
			value int64
		}{
			{&result.SourceReadBytes, stats.SourceBytes},
			{&result.NewPayloadBytes, stats.NewPayloadBytes},
			{&result.NewMetadataBytes, stats.NewMetadataBytes},
			{&result.NewObjects, int64(stats.NewObjects)},
		} {
			if item.value < 0 || item.value > math.MaxInt64-*item.total {
				return nil, ErrInvalid
			}
			*item.total += item.value
		}
		result.IncludedEntries++
	}
	if err := j.guard(ctx); err != nil {
		return nil, err
	}
	return &result, nil
}

func (j *Job) readFileReceipt(plan, file string) (filekit.Stats, error) {
	raw, err := j.files.Read(file)
	if err != nil {
		return filekit.Stats{}, err
	}
	var r fileReceipt
	if storage.Decode(raw, &r, 65536) != nil || r.Plan != plan || r.Stats.File != file || !storage.ID(r.Stats.Version) {
		return filekit.Stats{}, ErrInvalid
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) {
		return filekit.Stats{}, ErrInvalid
	}
	signature := r.Signature
	r.Signature = nil
	payload, _ := json.Marshal(r)
	if !ed25519.Verify(j.authority.Trust.Writer, payload, signature) {
		return filekit.Stats{}, ErrInvalid
	}
	return r.Stats, nil
}
