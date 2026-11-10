package generation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
)

type retentionProtectionRecord struct {
	Hold    RetentionProtectionReceipt  `json:"hold"`
	Release *RetentionProtectionReceipt `json:"release,omitempty"`
}

func (r *Replica) validateRetentionProtections(s state) error {
	if len(s.RetentionProtections) > maxRetentionProtectionRecords || len(s.RetentionClosures) > maxRetentionProtectionRecords {
		return ErrInvalid
	}
	for operation, close := range s.RetentionClosures {
		if !close.valid() || close.State != "CLOSED" || close.Operation != operation || !r.retentionReceiptMatches(s, close) {
			return ErrInvalid
		}
	}
	activePins := make(map[string]bool, len(s.RetentionProtections))
	for operation, record := range s.RetentionProtections {
		hold := record.Hold
		if !hold.valid() || hold.State != "HELD" || hold.Operation != operation || !r.retentionReceiptMatches(s, hold) {
			return ErrInvalid
		}
		id := retentionPin(operation)
		if record.Release == nil {
			if s.Pins[id] != (Pin{Generation: hold.Generation, Kind: retentionPinKind}) {
				return ErrInvalid
			}
			activePins[id] = true
			continue
		}
		release := record.Release
		if !release.valid() || release.State != "RELEASED" || release.Node != hold.Node || release.Domain != hold.Domain ||
			release.Repository != hold.Repository || release.Epoch != hold.Epoch || release.Operation != operation ||
			release.Generation != hold.Generation || release.HoldDigest != hold.GrantDigest || release.Revision <= hold.Revision ||
			release.Revision > s.Revision || release.ObservedUnix < hold.ObservedUnix || !sameRetirement(release.Retirement, hold.Retirement) {
			return ErrInvalid
		}
	}
	for id, pin := range s.Pins {
		if pin.Kind == retentionPinKind && !activePins[id] {
			return ErrInvalid
		}
	}
	return nil
}

func (r *Replica) retentionReceiptMatches(s state, receipt RetentionProtectionReceipt) bool {
	return receipt.Domain == r.trust.Domain && receipt.Repository == r.trust.Repository && receipt.Epoch == r.trust.Epoch &&
		receipt.Revision <= s.Revision && (r.indexNode == "" || receipt.Node == r.indexNode) && (s.IndexNode == "" || receipt.Node == s.IndexNode)
}

// ApplyRetentionProtection verifies the complete ciphertext before adding a
// hold and saves its signed receipt with the pin. admit can serialize the
// short commit or readback with replacement of the caller's accepted policy.
func (r *Replica) ApplyRetentionProtection(ctx context.Context, raw []byte, admit func(func() error) error) (RetentionProtectionReceipt, error) {
	var out RetentionProtectionReceipt
	if len(r.indexKey) != ed25519.PrivateKeySize {
		return out, ErrInvalid
	}
	grant, e := VerifyRetentionProtection(raw, r.trust, r.indexNode)
	if e != nil {
		return out, e
	}
	if admit == nil {
		admit = func(fn func() error) error { return fn() }
	}
	digest := Hash(raw)
	e = r.locked(ctx, func(s *state) error {
		record, exists := s.RetentionProtections[grant.Operation]
		pin := retentionPin(grant.Operation)
		readback := func(receipt RetentionProtectionReceipt) error {
			return admit(func() error {
				out = receipt
				return nil
			})
		}
		switch grant.Action {
		case "CLOSE":
			if receipt, closed := s.RetentionClosures[grant.Operation]; closed {
				if receipt.GrantDigest != digest {
					return ErrConflict
				}
				return readback(receipt)
			}
			if len(s.RetentionClosures) >= maxRetentionProtectionRecords {
				return statefile.ErrCapacity
			}
		case "HOLD":
			if exists {
				if record.Release != nil || record.Hold.GrantDigest != digest {
					return ErrConflict
				}
				return readback(record.Hold)
			}
			if _, occupied := s.Pins[pin]; occupied {
				return ErrConflict
			}
			if len(s.Pins) >= MaxPins || len(s.RetentionProtections) >= maxRetentionProtectionRecords {
				return statefile.ErrCapacity
			}
			if now := time.Now().Unix(); now < grant.NotBefore || now >= grant.ExpiresUnix {
				return ErrMaintenanceWindow
			}
			if e := r.verifyComplete(ctx, s, grant.Generation); e != nil {
				return e
			}
		case "RELEASE":
			if !exists || record.Hold.Generation != grant.Generation || record.Hold.GrantDigest != grant.HoldDigest ||
				!sameRetirement(record.Hold.Retirement, grant.Retirement) {
				return ErrConflict
			}
			if record.Release != nil {
				if record.Release.GrantDigest != digest {
					return ErrConflict
				}
				return readback(*record.Release)
			}
		}
		return admit(func() error {
			var e error
			out, e = r.commitRetentionProtection(ctx, s, grant, record, pin, digest)
			return e
		})
	})
	if e != nil {
		return RetentionProtectionReceipt{}, e
	}
	return out, nil
}

func (r *Replica) commitRetentionProtection(ctx context.Context, s *state, grant RetentionProtection, record retentionProtectionRecord, pin, digest string) (RetentionProtectionReceipt, error) {
	var out RetentionProtectionReceipt
	if e := ctx.Err(); e != nil {
		return out, e
	}
	now := time.Now().Unix()
	if now < grant.NotBefore || now >= grant.ExpiresUnix || now < record.Hold.ObservedUnix {
		return out, ErrMaintenanceWindow
	}
	if s.Revision >= ^uint64(0)-1 {
		return out, statefile.ErrCapacity
	}
	receipt := RetentionProtectionReceipt{
		Format: RetentionProtectionReceiptFormat, Node: grant.Node, NodeKey: r.indexKey.Public().(ed25519.PublicKey),
		Domain: grant.Domain, Repository: grant.Repository, Epoch: grant.Epoch, Operation: grant.Operation, Generation: grant.Generation,
		GrantDigest: digest, Retirement: grant.Retirement, Revision: s.Revision + 1, ObservedUnix: now,
	}
	switch grant.Action {
	case "HOLD":
		receipt.State, receipt.HoldDigest = "HELD", digest
	case "RELEASE":
		receipt.State, receipt.HoldDigest = "RELEASED", grant.HoldDigest
	case "CLOSE":
		receipt.State = "CLOSED"
	}
	unsigned, e := json.Marshal(receipt)
	if e != nil {
		return out, e
	}
	receipt.Signature = ed25519.Sign(r.indexKey, append([]byte(RetentionProtectionReceiptFormat+"\x00"), unsigned...))
	if grant.Action == "CLOSE" {
		if s.RetentionClosures == nil {
			s.RetentionClosures = make(map[string]RetentionProtectionReceipt)
		}
		s.RetentionClosures[grant.Operation] = receipt
	} else {
		if grant.Action == "HOLD" {
			s.Pins[pin] = Pin{Generation: grant.Generation, Kind: retentionPinKind}
			record.Hold = receipt
		} else {
			delete(s.Pins, pin)
			record.Release = &receipt
		}
		if s.RetentionProtections == nil {
			s.RetentionProtections = make(map[string]retentionProtectionRecord)
		}
		s.RetentionProtections[grant.Operation] = record
	}
	s.Revision = receipt.Revision
	if e = r.save(*s); e != nil {
		return out, e
	}
	return receipt, nil
}
