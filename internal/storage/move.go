package storage

import "context"

const WebDAVMoveMode = "webdav-move-1"
const MoveBookFormat = "outpost-storage-move-attempts-1"

// A separate local attempt book is required for non-conditional staging PUT.
// Its records contain opaque keys and byte digests, never payload or credentials.
type MoveAttempt struct {
	Nonce              string `json:"nonce"`
	Phase              string `json:"phase"`
	WriteStartedMillis int64  `json:"writeStartedMillis,omitempty"`
}
type MoveRecord struct {
	Key         string        `json:"key"`
	Digest      string        `json:"digest"`
	Bytes       int           `json:"bytes"`
	UpdatedUnix int64         `json:"updatedUnix"`
	Attempts    []MoveAttempt `json:"attempts"`
}
type MoveTransaction interface {
	State() MoveRecord
	Allocate() (MoveAttempt, error)
	Transition(string, string) error
	Temporary(MoveAttempt) (string, error)
}
type WriteAttempts interface {
	Check(context.Context) error
	WithRecord(context.Context, string, string, string, int, func(MoveTransaction) error) error
}
type writeAttemptsKey struct{}

// WithWriteAttempts is local execution context, not an externally supplied
// configuration field. It leaves a shared backend's rate limiter unchanged.
func WithWriteAttempts(ctx context.Context, book WriteAttempts) context.Context {
	if book == nil {
		return ctx
	}
	return context.WithValue(ctx, writeAttemptsKey{}, book)
}
