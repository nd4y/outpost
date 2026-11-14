package worker

import (
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/upload"
)

// Retained queues preserve their original resource identity. Opening tries only
// the two known ceilings; it never initializes, migrates or broadens old state.
// A new long queue requires the explicit signed operation window. Its effective
// lifetime is still bounded by the caller's operation/configuration context.
func openExternalQueue(parent *os.Root, dir, node string, authority upload.Authority, initialize bool, operationMillis int64, admit statefile.Admission) (*upload.Queue, error) {
	if operationMillis < 0 || operationMillis != 0 && operationMillis < 100 || operationMillis > upload.MaxAttemptMillis {
		return nil, ErrDenied
	}
	limits := externalQueueLimits
	if !initialize {
		queue, err := upload.OpenQueueAt(parent, dir, node, authority, limits, false, admit)
		if err == nil || !errors.Is(err, upload.ErrConflict) {
			return queue, err
		}
		limits.AttemptMillis = upload.MaxAttemptMillis
		return upload.OpenQueueAt(parent, dir, node, authority, limits, false, admit)
	}
	if operationMillis > upload.DefaultAttemptMillis {
		limits.AttemptMillis = upload.MaxAttemptMillis
	}
	return upload.OpenQueueAt(parent, dir, node, authority, limits, true, admit)
}
