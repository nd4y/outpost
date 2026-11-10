package worker

import (
	"bytes"
	"context"
	"os"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
)

// ApplyRetentionProtection is a local operation on a stopped trusted holder.
// The accepted configuration is rechecked while committing the short update.
func (w *Worker) ApplyRetentionProtection(ctx context.Context, domain string, raw []byte) (generation.RetentionProtectionReceipt, error) {
	var receipt generation.RetentionProtectionReceipt
	e := w.withStoppedReplica(ctx, domain, func(_ *os.Root, path string, trust generation.Trust, admission statefile.Admission) error {
		r, e := w.openReplicaAt(path, trust, false)
		if e != nil {
			return e
		}
		defer r.Close()
		r.Admit = admission
		admit := func(commit func() error) error {
			return w.cache.WithCurrent(ctx, time.Now(), func(cfg control.Config, _ []byte) error {
				d, exists := cfg.DomainByID(domain)
				node, known := cfg.NodeByID(w.node)
				if !exists || !known || node.Class != "trusted" || !slices.Contains(d.Placement.Holders, w.node) ||
					d.Trust.Repository != trust.Repository || d.Trust.Epoch != trust.Epoch ||
					!bytes.Equal(d.Trust.Writer, trust.Writer) || !bytes.Equal(d.Trust.Maintenance, trust.Maintenance) {
					return ErrDenied
				}
				if e := w.check(ctx); e != nil {
					return e
				}
				return commit()
			})
		}
		if e := admit(func() error { return nil }); e != nil {
			return e
		}
		receipt, e = r.ApplyRetentionProtection(ctx, raw, admit)
		return e
	})
	return receipt, e
}
