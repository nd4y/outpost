package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/nd4y/outpost/internal/storage"
)

// Export returns a verified checkpoint and the completed file lineage. It does
// not reopen the source or require the ingress endpoint to be available.
func (j *Job) Export(ctx context.Context) ([]byte, map[string]string, error) {
	var checkpoint []byte
	heads := map[string]string{}
	e := j.lease.WithLock(ctx, func() error {
		if e := j.guard(ctx); e != nil {
			return e
		}
		s, e := j.Status(ctx)
		if e != nil {
			return e
		}
		if s.Phase != "COMPLETE" {
			return ErrCopies
		}
		if e = j.validateCheckpoint(s); e != nil {
			return e
		}
		checkpoint, e = j.state.Read("checkpoint.json")
		if e != nil {
			return e
		}
		for _, file := range j.plan.Files {
			raw, e := j.files.Read(file.File)
			if e != nil {
				return e
			}
			var r fileReceipt
			if storage.Decode(raw, &r, 65536) != nil || r.Plan != s.Plan || r.Stats.File != file.File || !storage.ID(r.Stats.Version) {
				return ErrInvalid
			}
			canonical, _ := json.Marshal(r)
			if !bytes.Equal(raw, canonical) {
				return ErrInvalid
			}
			signature := r.Signature
			r.Signature = nil
			payload, _ := json.Marshal(r)
			if !ed25519.Verify(j.authority.Trust.Writer, payload, signature) {
				return ErrInvalid
			}
			heads[file.File] = r.Stats.Version
		}
		return nil
	})
	if e != nil {
		return nil, nil, e
	}
	return checkpoint, heads, nil
}
