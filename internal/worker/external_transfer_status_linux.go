package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"math"
	"math/bits"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

const ExternalTransferStatusFormat = "outpost-external-transfer-status-1"

type ExternalTransferStatus struct {
	Format    string                   `json:"format"`
	Node      string                   `json:"node"`
	Domain    string                   `json:"domain"`
	Target    string                   `json:"target"`
	Operation string                   `json:"operation"`
	Attempt   *ExternalTransferAttempt `json:"attempt,omitempty"`
}

// ExternalTransferAttempt describes the locally observed HTTP bodies and
// elapsed wall clock of one attempt, including waits and verification.
type ExternalTransferAttempt struct {
	Number                     uint64 `json:"number"`
	StartedMillis              int64  `json:"startedMillis"`
	FinishedMillis             int64  `json:"finishedMillis"`
	RequestBodyBytes           int64  `json:"requestBodyBytes"`
	ResponseBodyBytes          int64  `json:"responseBodyBytes"`
	ReplayedRequestBodyBytes   int64  `json:"replayedRequestBodyBytes"`
	RequestBodyBytesPerSecond  *int64 `json:"requestBodyBytesPerSecond,omitempty"`
	ResponseBodyBytesPerSecond *int64 `json:"responseBodyBytesPerSecond,omitempty"`
}

// ExternalTransferStatus reads only local records. A signed HTTP attempt is
// eligible after its exact signed plan and queue/worker receipts agree.
func (w *Worker) ExternalTransferStatus(ctx context.Context, operation string) (ExternalTransferStatus, error) {
	var out ExternalTransferStatus
	if !storage.ID(operation) {
		return out, ErrDenied
	}
	if err := w.check(ctx); err != nil {
		return out, err
	}
	raw, err := w.cache.Raw(ctx)
	if err != nil {
		return out, err
	}
	cfg, err := w.cache.Verify(raw)
	if err != nil {
		return out, err
	}
	if err = cfg.Active(time.Now()); err != nil {
		return out, err
	}
	status, err := w.Status(ctx)
	if err != nil {
		return out, err
	}
	job, found := status.Jobs[operation]
	j := job.Job
	domain, admitted := cfg.DomainByID(j.Domain)
	_, target := cfg.TargetByID(j.Target)
	if !found || !admitted || !target || j.Kind != "upload" || j.Executor != w.node ||
		!domain.Placement.PermitsCloud(w.node, j.Target) {
		return out, ErrDenied
	}
	out = ExternalTransferStatus{Format: ExternalTransferStatusFormat, Node: w.node, Domain: j.Domain, Target: j.Target, Operation: operation}
	key := w.externalHTTPKey()
	if job.Phase != "COMPLETE" || key == nil {
		return out, nil
	}
	dir := w.relative(filepath.Join(DomainDirectory(w.dir, domain.Trust), "uploads", operation))
	queue, err := openExternalQueue(w.root, dir, w.node, upload.Authority{Generation: domain.Trust, Planner: domain.Planner}, false, cfg.Limits.OperationMillis, nil)
	if err != nil {
		return out, nil
	}
	defer queue.Close()
	q, err := queue.Status(ctx)
	if err != nil {
		return out, nil
	}
	store, err := statefile.OpenAt(w.root, externalHTTPDirectory, maxExternalHTTPRecord, false)
	if err != nil {
		return out, nil
	}
	defer store.Close()
	attempt, err := readExternalHTTPAttempt(store, w.node, j.Domain, j.Target, key.Public().(ed25519.PublicKey))
	if err != nil {
		return out, nil
	}
	latest, err := w.cache.Raw(ctx)
	if err != nil || !bytes.Equal(latest, raw) || cfg.Active(time.Now()) != nil || w.check(ctx) != nil {
		return out, nil
	}
	out.Attempt = completedExternalTransfer(job, q.Jobs[operation], attempt)
	return out, nil
}

func completedExternalTransfer(job JobState, queued upload.QueueJob, attempt upload.HTTPAttempt) *ExternalTransferAttempt {
	j := job.Job
	counts := attempt.Counts
	if job.Phase != "COMPLETE" || queued.Phase != "COMPLETE" || queued.Receipt == nil ||
		attempt.Outcome != "SUCCEEDED" || counts == nil || counts.Incomplete ||
		attempt.Node != j.Executor || attempt.Domain != j.Domain || attempt.Target != j.Target || attempt.Operation != j.Operation ||
		attempt.Attempt != queued.Attempts || attempt.Plan != storage.Hash(queued.Plan) ||
		attempt.FinishedMillis/1000 > job.UpdatedUnix {
		return nil
	}
	var receipt upload.Receipt
	if storage.Decode(job.Receipt, &receipt, 4096) != nil || receipt != *queued.Receipt ||
		receipt.Operation != j.Operation || receipt.Executor != j.Executor || receipt.Target != j.Target ||
		receipt.Generation != j.Generation || receipt.ObservedUnix > attempt.FinishedMillis/1000 {
		return nil
	}
	elapsed := attempt.FinishedMillis - attempt.StartedMillis
	return &ExternalTransferAttempt{
		Number: attempt.Attempt, StartedMillis: attempt.StartedMillis, FinishedMillis: attempt.FinishedMillis,
		RequestBodyBytes: counts.RequestBytes, ResponseBodyBytes: counts.ResponseBytes, ReplayedRequestBodyBytes: counts.RepeatedRequestBytes,
		RequestBodyBytesPerSecond: bodyBytesPerSecond(counts.RequestBytes, elapsed), ResponseBodyBytesPerSecond: bodyBytesPerSecond(counts.ResponseBytes, elapsed),
	}
}

func bodyBytesPerSecond(count, millis int64) *int64 {
	if millis <= 0 || count < 0 {
		return nil
	}
	high, low := bits.Mul64(uint64(count), 1000)
	if high >= uint64(millis) {
		return nil
	}
	value, _ := bits.Div64(high, low, uint64(millis))
	if value > math.MaxInt64 {
		return nil
	}
	rate := int64(value)
	return &rate
}
