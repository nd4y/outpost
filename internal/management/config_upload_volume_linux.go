package management

import (
	"context"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

const UploadVolumePreviewFormat = "outpost-management-preview-with-upload-volume-1"

// DeclaredUploadVolume describes one exact target plan across all its
// participants, before destination reuse or transfer overhead.
type DeclaredUploadVolume struct {
	Operation       string `json:"operationId"`
	Domain          string `json:"domain"`
	Generation      string `json:"generation"`
	Target          string `json:"target"`
	UniquePartBytes int64  `json:"uniquePartBytes"`
	UniqueParts     int    `json:"uniqueParts"`
	CatalogBytes    int    `json:"catalogBytes"`
}

type UploadVolumePreview struct {
	Format        string                 `json:"format"`
	Preview       Preview                `json:"preview"`
	UploadVolumes []DeclaredUploadVolume `json:"uploadVolumes"`
}

// The candidate and its embedded plans have already passed control.Verify and
// owner-scope admission. Decode only those exact plans and keep opaque totals.
func declaredUploadVolumes(ctx context.Context, candidate control.Config) ([]DeclaredUploadVolume, error) {
	out := make([]DeclaredUploadVolume, 0)
	for _, job := range candidate.Jobs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if job.Kind != "upload" {
			continue
		}
		var plan upload.Plan
		if err := storage.Decode(job.Plan, &plan, upload.MaxPlan); err != nil {
			return nil, err
		}
		if plan.MissingRepair != nil {
			continue
		}
		tasks, err := plan.Tasks()
		if err != nil {
			return nil, err
		}
		var bytes int64
		for _, task := range tasks {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			size := int64(task.Part.Bytes)
			if size <= 0 || size > MaxSafeInteger-bytes {
				return nil, ErrInvalid
			}
			bytes += size
		}
		out = append(out, DeclaredUploadVolume{
			Operation: job.Operation, Domain: job.Domain, Generation: job.Generation, Target: job.Target,
			UniquePartBytes: bytes, UniqueParts: len(tasks), CatalogBytes: len(plan.Catalog),
		})
	}
	return out, nil
}
