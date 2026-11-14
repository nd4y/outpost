package generation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sort"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
)

const MetadataCheckpointFormat = "outpost-replica-metadata-checkpoint-1"

// A checkpoint contains supporting authority, not a replacement anti-rollback
// anchor. The node's existing current signed index copy must survive separately.
type metadataCheckpoint struct {
	Format    string                     `json:"format"`
	Index     string                     `json:"indexSHA256"`
	Retention json.RawMessage            `json:"retention"`
	Plans     map[string]json.RawMessage `json:"pendingPlans"`
}

func (r *Replica) anchoredIndex() (indexCopy, state, error) {
	copy, s, err := r.readIndexCopy()
	if err != nil {
		return copy, s, errors.Join(ErrIndexRecovery, err)
	}
	anchor, err := read(r.root, indexAnchorName, 64)
	if err != nil || string(anchor) != Hash(copy.Index) {
		return copy, s, errors.Join(ErrIndexRecovery, err)
	}
	return copy, s, nil
}

// MetadataCheckpoint exports one consistent exact ledger and all pending
// frozen plans. EnableIndexCopy must already have completed. The operator keeps
// these bytes and their digest independently of the replica's primary metadata.
func (r *Replica) MetadataCheckpoint(ctx context.Context) ([]byte, error) {
	var raw []byte
	err := r.exclusive(ctx, func() error {
		copy, s, err := r.anchoredIndex()
		if err != nil {
			return err
		}
		primary, err := read(r.root, "state.json", MaxState)
		if err != nil || !bytes.Equal(primary, copy.Index) {
			return errors.Join(ErrIndexRecovery, err)
		}
		ledger, _, err := r.retention(&s)
		if err != nil {
			return err
		}
		retention, err := json.Marshal(ledger)
		if err != nil {
			return err
		}
		checkpoint := metadataCheckpoint{MetadataCheckpointFormat, Hash(copy.Index), retention, map[string]json.RawMessage{}}
		size := len(retention)
		for operation, record := range s.GC {
			if err := ctx.Err(); err != nil {
				return err
			}
			if record.Result != nil {
				continue
			}
			permit, err := verifyPermit(ledger.Records[operation], r.trust)
			if err != nil {
				return err
			}
			plan, _, err := r.gcPlan(ctx, permit, s.Receipts[operation], record.Plan, nil, nil, &s)
			if err != nil {
				return err
			}
			planRaw, err := json.Marshal(plan)
			if err != nil {
				return err
			}
			size += len(planRaw)
			if size > MaxState {
				return statefile.ErrCapacity
			}
			checkpoint.Plans[operation] = planRaw
		}
		raw, err = json.Marshal(checkpoint)
		if err != nil {
			return err
		}
		if len(raw) > MaxState {
			return statefile.ErrCapacity
		}
		return ctx.Err()
	})
	return raw, err
}

// RestoreMetadataCheckpointAt restores missing primary metadata only against
// the surviving exact anchored index copy. It does not restore a lost anchor,
// infer newer state, recalculate candidates, or authorize any deletion. After a
// partial failure, repeat with the same independently selected checkpoint.
func RestoreMetadataCheckpointAt(parent *os.Root, ctx context.Context, path string, trust Trust, key ed25519.PrivateKey, admit statefile.Admission, raw []byte, expected string) (bool, error) {
	if !trust.valid() || len(key) != ed25519.PrivateKeySize {
		return false, ErrInvalid
	}
	root, err := localfs.Directory(parent, path, false)
	if err != nil {
		return false, err
	}
	defer root.Close()
	r := &Replica{root: root, trust: trust, Admit: admit}
	r.setIndexKey(key)
	return r.restoreMetadataCheckpoint(ctx, raw, expected)
}

func (r *Replica) restoreMetadataCheckpoint(ctx context.Context, raw []byte, expected string) (bool, error) {
	var checkpoint metadataCheckpoint
	if !validID(expected) || len(raw) == 0 || len(raw) > MaxState || Hash(raw) != expected ||
		canonical(raw, &checkpoint, MaxState) != nil || checkpoint.Format != MetadataCheckpointFormat ||
		!validID(checkpoint.Index) || checkpoint.Plans == nil || len(checkpoint.Plans) > MaxPins {
		return false, ErrInvalid
	}
	restored := false
	err := r.exclusive(ctx, func() error {
		copy, s, err := r.anchoredIndex()
		if err != nil || Hash(copy.Index) != checkpoint.Index {
			return errors.Join(ErrIndexRecovery, err)
		}
		if _, _, err := r.verifyRetention(&s, checkpoint.Retention); err != nil {
			return err
		}
		files := map[string][]byte{"retention.json": checkpoint.Retention, "state.json": copy.Index}
		pending := 0
		for operation, record := range s.GC {
			if err := ctx.Err(); err != nil {
				return err
			}
			if record.Result != nil {
				continue
			}
			pending++
			plan := checkpoint.Plans[operation]
			if _, err := decodeGCPlan(plan, s.Receipts[operation], record.Plan); err != nil {
				return err
			}
			files[gcName(operation)] = plan
		}
		if pending != len(checkpoint.Plans) {
			return ErrInvalid
		}
		// Check every destination before any write. A foreign existing path,
		// including a symlink, is never overwritten or treated as a replay.
		names := make([]string, 0, len(files))
		for name, body := range files {
			if _, err := r.metadataFileMatches(name, body); err != nil {
				return err
			}
			if name != "state.json" {
				names = append(names, name)
			}
		}
		if err := r.verifyIndexContents(ctx, &s); err != nil {
			return err
		}
		sort.Strings(names)
		// Supporting files are durable first. Publishing the original primary
		// last makes an interrupted all-missing recovery fail closed on reopen.
		names = append(names, "state.json")
		for _, name := range names {
			copyNow, _, err := r.anchoredIndex()
			if err != nil || !bytes.Equal(copyNow.Index, copy.Index) {
				return errors.Join(ErrIndexRecovery, err)
			}
			present, err := r.metadataFileMatches(name, files[name])
			if err != nil {
				return err
			}
			if present {
				continue
			}
			if err := r.createMaintenancePlanCheckpoint(ctx, name, files[name]); err != nil {
				return err
			}
			if err := r.point("replica-metadata-file-restored"); err != nil {
				return err
			}
			restored = true
		}
		return nil
	})
	return restored, err
}

func (r *Replica) metadataFileMatches(name string, expected []byte) (bool, error) {
	info, err := r.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, ErrConflict
	}
	raw, err := read(r.root, name, MaxState)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(raw, expected) {
		return false, ErrConflict
	}
	return true, nil
}
