package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"slices"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func (w *Worker) ReplicaDamageStatus(ctx context.Context, domain, id string) (generation.RecordedDamage, error) {
	var out generation.RecordedDamage
	if !storage.ID(domain) || !storage.ID(id) {
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
	d, ok := cfg.DomainByID(domain)
	if !ok || !slices.Contains(d.Placement.Holders, w.node) {
		return out, ErrDenied
	}
	path := w.relative(filepath.Join(DomainDirectory(w.dir, d.Trust), "replica"))
	report, err := generation.ReadRecordedDamageAt(ctx, w.root, path, d.Trust, w.cert.PrivateKey.(ed25519.PrivateKey), id)
	if err != nil {
		return out, err
	}
	latest, err := w.cache.Raw(ctx)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(latest, raw) {
		return out, generation.ErrConflict
	}
	if err = cfg.Active(time.Now()); err != nil {
		return out, err
	}
	if err = w.check(ctx); err != nil {
		return out, err
	}
	return report, nil
}
