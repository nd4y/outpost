package capture

import "context"

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
		if j.options.InheritedCatalog != "" {
			raw, err := j.state.Read("catalog.json")
			if err != nil {
				return err
			}
			heads, err = j.sealedHeads(raw, s.Generation)
			return err
		}
		for _, file := range j.plan.Files {
			stats, e := j.readFileReceipt(s.Plan, file.File)
			if e != nil {
				return e
			}
			heads[file.File] = stats.Version
		}
		return nil
	})
	if e != nil {
		return nil, nil, e
	}
	return checkpoint, heads, nil
}
