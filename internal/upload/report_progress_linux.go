package upload

import (
	"bytes"
	"context"
	"os"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
)

type ProgressBinding struct {
	Operation  string
	Generation string
	Target     string
	Plan       string
	Delegation string
}

type JobProgress struct {
	ConfirmedBytes int64
	PlanBytes      int64
}

type queueProgressObservation struct {
	operation string
	alternate string
	plan      Plan
}

// ObserveProgressAt reads immutable part acknowledgements from the worker's
// existing standard or long-window queue. It claims no target completion.
func ObserveProgressAt(ctx context.Context, parent *os.Root, dir, worker string, authority Authority, limits QueueLimits, binding ProgressBinding) (JobProgress, error) {
	if !storage.ID(binding.Operation) || !storage.ID(binding.Generation) || !storage.ID(binding.Target) ||
		(binding.Plan == "") == (binding.Delegation == "") ||
		(binding.Plan != "" && !storage.ID(binding.Plan)) || (binding.Delegation != "" && !storage.ID(binding.Delegation)) {
		return JobProgress{}, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		return JobProgress{}, err
	}
	queue, err := openQueueRoot(parent, dir, worker, authority, limits, nil)
	if err != nil {
		return JobProgress{}, err
	}
	defer queue.Close()
	long := limits
	long.AttemptMillis = MaxAttemptMillis
	observation := queueProgressObservation{operation: binding.Operation, alternate: queueIdentity(worker, authority, long)}
	return queue.observeProgress(ctx, binding, &observation)
}

func (q *Queue) observeProgress(ctx context.Context, binding ProgressBinding, observation *queueProgressObservation) (JobProgress, error) {
	files, err := openObservedDocuments(ctx, q.root, "queue.lock", "queue.json")
	if err != nil {
		return JobProgress{}, err
	}
	raw, err := readObservedDocument(ctx, files[0], maxQueueBytes)
	_ = files[0].Close()
	if err != nil {
		return JobProgress{}, err
	}
	queue, err := q.decodeState(ctx, raw, observation)
	if err != nil {
		return JobProgress{}, err
	}
	job, ok := queue.Jobs[binding.Operation]
	if !ok || job.Phase != "RUNNING" || job.Attempts == 0 {
		return JobProgress{}, ErrDenied
	}
	plan := observation.plan
	planID := storage.Hash(job.Plan)
	now := time.Now()
	if plan.Generation != binding.Generation || plan.Profile.ID() != binding.Target || plan.MissingRepair != nil ||
		now.UnixMilli() < plan.StartMillis || now.Unix() >= plan.ExpiresUnix ||
		binding.Plan != "" && binding.Plan != planID ||
		binding.Delegation != "" && (len(plan.Delegation) == 0 || storage.Hash(plan.Delegation) != binding.Delegation) {
		return JobProgress{}, ErrDenied
	}
	return q.observeParts(ctx, plan, planID, job.Plan)
}

func (q *Queue) observeParts(ctx context.Context, plan Plan, planID string, expected []byte) (JobProgress, error) {
	if err := ctx.Err(); err != nil {
		return JobProgress{}, err
	}
	root, err := localfs.OpenAt(q.root, "jobs/"+plan.Operation, false)
	if err != nil {
		return JobProgress{}, err
	}
	defer root.Close()
	files, err := openObservedDocuments(ctx, root, "state.lock", "plan.json", "state.json")
	if err != nil {
		return JobProgress{}, err
	}
	for _, file := range files {
		defer file.Close()
	}
	saved, err := readObservedDocument(ctx, files[0], MaxPlan)
	if err != nil {
		return JobProgress{}, err
	}
	if !bytes.Equal(saved, expected) {
		return JobProgress{}, ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return JobProgress{}, err
	}
	tasks, err := plan.Tasks()
	if err != nil {
		return JobProgress{}, err
	}
	journal := Journal{plan: plan, planID: planID, worker: q.worker, tasks: make(map[string]bool, len(tasks))}
	for _, task := range tasks {
		journal.tasks[task.Part.ID] = true
	}
	raw, err := readObservedDocument(ctx, files[1], maxJournal)
	if err != nil {
		return JobProgress{}, err
	}
	state, err := journal.decodeState(raw)
	if err != nil {
		return JobProgress{}, err
	}
	if err := ctx.Err(); err != nil {
		return JobProgress{}, err
	}
	if state.Phase != "TRANSFERRING" || len(state.Parts) == 0 {
		return JobProgress{}, ErrDenied
	}
	var out JobProgress
	for _, task := range tasks {
		if err := ctx.Err(); err != nil {
			return JobProgress{}, err
		}
		// The validated signed plan bounds the part size and unique part count.
		out.PlanBytes += int64(task.Part.Bytes)
		if state.Parts[task.Part.ID].Complete {
			out.ConfirmedBytes += int64(task.Part.Bytes)
		}
	}
	if time.Now().Unix() >= plan.ExpiresUnix {
		return JobProgress{}, ErrDenied
	}
	return out, ctx.Err()
}

// Writers atomically replace documents while holding the existing exclusive
// lock. Flock is nonblocking, and only opening the files holds the read lock.
func openObservedDocuments(ctx context.Context, root *os.Root, lockName string, names ...string) ([]*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lockFile, err := localfs.OpenFile(root, lockName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer lockFile.Close()
	info, err := lockFile.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrDenied
	}
	if err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	files := make([]*os.File, 0, len(names))
	for _, name := range names {
		file, err := localfs.OpenFile(root, name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			for _, opened := range files {
				_ = opened.Close()
			}
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func readObservedDocument(ctx context.Context, file *os.File, maximum int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := readRegular(file, maximum)
	if err != nil {
		return nil, err
	}
	return data, ctx.Err()
}
