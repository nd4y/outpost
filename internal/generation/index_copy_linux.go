package generation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
)

const IndexCopyFormat = "outpost-replica-index-copy-1"
const indexCopyName = "index-copy.json"
const indexAnchorName = "index-anchor"
const maxIndexCopy = MaxState + 4096

var ErrIndexRecovery = errors.New("replica index requires explicit verified recovery")

type indexCopy struct {
	Format    string          `json:"format"`
	Node      string          `json:"node"`
	Previous  string          `json:"previous"`
	Index     json.RawMessage `json:"index"`
	Signature []byte          `json:"signature,omitempty"`
}

func (r *Replica) setIndexKey(key ed25519.PrivateKey) {
	public := key.Public().(ed25519.PublicKey)
	der, _ := x509.MarshalPKIXPublicKey(public)
	r.indexKey, r.indexNode = bytes.Clone(key), Hash(der)
}

func (r *Replica) writeIndexCopy(node string, index []byte) error {
	if len(r.indexKey) != ed25519.PrivateKeySize || r.indexNode != node {
		return ErrIndexRecovery
	}
	previous, e := read(r.root, "state.json", MaxState)
	if e != nil {
		return e
	}
	copy := indexCopy{Format: IndexCopyFormat, Node: node, Previous: Hash(previous), Index: index}
	unsigned, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	copy.Signature = ed25519.Sign(r.indexKey, append([]byte(IndexCopyFormat+"\x00"), unsigned...))
	raw, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	if len(raw) > maxIndexCopy {
		return statefile.ErrCapacity
	}
	if e = r.write(indexCopyName, raw); e != nil {
		return e
	}
	if e = r.point("replica-index-copy-durable"); e != nil {
		return e
	}
	if e = r.write(indexAnchorName, []byte(Hash(index))); e != nil {
		return e
	}
	return r.point("replica-index-anchor-durable")
}

func (r *Replica) readIndexCopy() (indexCopy, state, error) {
	var copy indexCopy
	var s state
	if len(r.indexKey) != ed25519.PrivateKeySize {
		return copy, s, ErrIndexRecovery
	}
	raw, e := read(r.root, indexCopyName, maxIndexCopy)
	if e != nil {
		return copy, s, e
	}
	if canonical(raw, &copy, maxIndexCopy) != nil || copy.Format != IndexCopyFormat || copy.Node != r.indexNode || !validID(copy.Previous) {
		return copy, s, ErrIndexRecovery
	}
	sig := copy.Signature
	copy.Signature = nil
	unsigned, e := json.Marshal(copy)
	if e != nil || !ed25519.Verify(r.indexKey.Public().(ed25519.PublicKey), append([]byte(IndexCopyFormat+"\x00"), unsigned...), sig) {
		return copy, s, ErrIndexRecovery
	}
	s, e = r.decodeIndex(copy.Index)
	if e != nil || s.IndexNode != r.indexNode {
		return copy, s, errors.Join(ErrIndexRecovery, e)
	}
	return copy, s, nil
}

// EnableIndexCopy keeps the original index until the new signed copy is
// durable. Existing maintenance permits become stale at the new revision.
func (r *Replica) EnableIndexCopy(ctx context.Context) error {
	if len(r.indexKey) != ed25519.PrivateKeySize {
		return ErrIndexRecovery
	}
	return r.exclusive(ctx, func() error {
		s, e := r.load()
		if e != nil || s.IndexNode != "" {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		s.IndexNode = r.indexNode
		s.Revision++
		return r.save(s)
	})
}

// RecoverIndexCopyAt is an offline, explicit operation on an existing replica.
// It only accepts a missing index or the exact predecessor of the signed copy.
func RecoverIndexCopyAt(parent *os.Root, ctx context.Context, path string, trust Trust, key ed25519.PrivateKey, admit statefile.Admission) (bool, error) {
	if !trust.valid() || len(key) != ed25519.PrivateKeySize {
		return false, ErrInvalid
	}
	root, e := localfs.Directory(parent, path, false)
	if e != nil {
		return false, e
	}
	defer root.Close()
	r := &Replica{root: root, trust: trust, Admit: admit}
	r.setIndexKey(key)
	changed := false
	e = r.exclusive(ctx, func() error {
		copy, s, e := r.readIndexCopy()
		if e != nil {
			return errors.Join(ErrIndexRecovery, e)
		}
		primary, e := read(root, "state.json", MaxState)
		missing := errors.Is(e, os.ErrNotExist)
		if e != nil && !missing {
			return errors.Join(ErrIndexRecovery, e)
		}
		next := Hash(copy.Index)
		anchor, anchorErr := read(root, indexAnchorName, 64)
		pending := string(anchor) != next
		if pending {
			// If the anchor write did not complete, the live predecessor is
			// necessary to prove that this exact signed update was in progress.
			if missing || Hash(primary) != copy.Previous {
				return ErrIndexRecovery
			}
			if errors.Is(anchorErr, os.ErrNotExist) {
				old, e := r.decodeIndex(primary)
				if e != nil || old.IndexNode != "" {
					return ErrIndexRecovery
				}
			} else if anchorErr != nil || string(anchor) != copy.Previous {
				return ErrIndexRecovery
			}
		}
		if !missing && bytes.Equal(primary, copy.Index) && !pending {
			return nil
		}
		if !missing && Hash(primary) != copy.Previous {
			return ErrIndexRecovery
		}
		if e = r.verifyIndexDependencies(ctx, &s); e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if pending {
			if e = r.write(indexAnchorName, []byte(next)); e != nil {
				return e
			}
		}
		if e = r.write("state.json", copy.Index); e != nil {
			return e
		}
		changed = true
		return nil
	})
	return changed, e
}

func (r *Replica) verifyIndexDependencies(ctx context.Context, s *state) error {
	ledger, _, e := r.retention(s)
	if e != nil {
		return e
	}
	for operation, record := range s.GC {
		if e = ctx.Err(); e != nil {
			return e
		}
		if record.Result != nil {
			continue
		}
		p, e := VerifyPermit(ledger.Records[operation], r.trust)
		if e != nil {
			return e
		}
		if _, _, e = r.gcPlan(ctx, p, s.Receipts[operation], record.Plan, nil, nil, s); e != nil {
			return e
		}
	}
	return r.verifyIndexContents(ctx, s)
}

func (r *Replica) verifyIndexContents(ctx context.Context, s *state) error {
	for id, item := range s.Generations {
		if e := ctx.Err(); e != nil {
			return e
		}
		_, refs, e := r.catalogEntry(id, item, true)
		if e != nil {
			return errors.Join(ErrCatalogUnavailable, e)
		}
		if !item.Complete || item.Damaged {
			continue
		}
		for _, ref := range refs {
			if e = ctx.Err(); e != nil {
				return e
			}
			if _, e = r.object(ref); e != nil {
				return errors.Join(ErrIncomplete, e)
			}
		}
	}
	return nil
}
