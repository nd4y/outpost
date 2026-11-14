package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
)

// maintenancePlanAuthority authenticates the plan through the existing index
// and signed retention ledger. It grants no new deletion or execution window.
func (r *Replica) maintenancePlanAuthority(s *state, operation string) (gcRecord, Permit, string, error) {
	record, exists := s.GC[operation]
	digest := s.Receipts[operation]
	if !exists || !validID(record.Plan) || !validID(digest) {
		return gcRecord{}, Permit{}, "", ErrMigrationRequired
	}
	ledger, _, err := r.retention(s)
	if err != nil {
		return gcRecord{}, Permit{}, "", err
	}
	raw := ledger.Records[operation]
	permit, err := verifyPermit(raw, r.trust)
	if err != nil || permit.Operation != operation || Hash(raw) != digest {
		return gcRecord{}, Permit{}, "", ErrInvalid
	}
	return record, permit, digest, nil
}

// MaintenancePlanCheckpoint returns the exact canonical frozen plan. Keep its
// digest independently. Missing plans are never recreated by this read path.
func (r *Replica) MaintenancePlanCheckpoint(ctx context.Context, operation string) ([]byte, error) {
	if !validID(operation) {
		return nil, ErrInvalid
	}
	var raw []byte
	err := r.exclusive(ctx, func() error {
		s, err := r.load()
		if err != nil {
			return err
		}
		record, permit, digest, err := r.maintenancePlanAuthority(&s, operation)
		if err != nil {
			return err
		}
		plan, _, err := r.gcPlan(ctx, permit, digest, record.Plan, nil, nil, &s)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err = json.Marshal(plan)
		return err
	})
	return raw, err
}

// RestoreMaintenancePlanCheckpoint restores only an absent pending plan from
// independently selected exact bytes. The current index and signed retention
// ledger must survive. No candidates, receipts, pins or revisions are changed.
func (r *Replica) RestoreMaintenancePlanCheckpoint(ctx context.Context, operation string, raw []byte, expected string) (bool, error) {
	if !validID(operation) || !validID(expected) || len(raw) == 0 || len(raw) > MaxState || Hash(raw) != expected {
		return false, ErrInvalid
	}
	restored := false
	err := r.exclusive(ctx, func() error {
		s, err := r.load()
		if err != nil {
			return err
		}
		record, _, digest, err := r.maintenancePlanAuthority(&s, operation)
		if err != nil {
			return err
		}
		if record.Plan != expected {
			return ErrInvalid
		}
		if _, err := decodeGCPlan(raw, digest, expected); err != nil {
			return err
		}
		name := gcName(operation)
		info, err := r.root.Lstat(name)
		if err == nil {
			if !info.Mode().IsRegular() {
				return ErrConflict
			}
			existing, err := read(r.root, name, MaxState)
			if err != nil {
				return err
			}
			if bytes.Equal(existing, raw) {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if record.Result != nil {
			return ErrConflict
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.createMaintenancePlanCheckpoint(ctx, name, raw); err != nil {
			return err
		}
		if err := r.point("maintenance-plan-restored"); err != nil {
			return err
		}
		restored = true
		return nil
	})
	return restored, err
}

func (r *Replica) createMaintenancePlanCheckpoint(ctx context.Context, name string, raw []byte) error {
	return statefile.Guard(r.Admit, name, len(raw), func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		temp := ".txn/" + id
		file, err := localfs.OpenFile(r.root, temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer r.root.Remove(temp)
		_, err = file.Write(raw)
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// A path created after admission must survive, including a symlink.
		// Link publishes the already synced inode without replacing that path.
		if err := r.root.Link(temp, name); err != nil {
			if errors.Is(err, os.ErrExist) {
				return ErrConflict
			}
			return err
		}
		return syncDir(r.root, ".")
	})
}
