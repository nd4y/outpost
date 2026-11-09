package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/storage"
)

const renewedFormat = "outpost-source-agent-2"

var ErrAuthorityChanged = errors.New("source authority changed; reopen the agent")

func sameAuthorityScope(a, b ingress.Authority) bool {
	return ingress.SameAuthorityScope(a, b)
}
func sameObservationScope(a, b observation.Grant) bool {
	a.Epoch = 0
	b.Epoch = 0
	a.NotBefore = 0
	b.NotBefore = 0
	a.ExpiresUnix = 0
	b.ExpiresUnix = 0
	a.Signature = nil
	b.Signature = nil
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
func (a *Agent) stateScope(s state, adopt bool) (ingress.Authority, error) {
	if s.Format == Format {
		if len(s.Authority)+len(s.Observation)+len(s.IntentAuthority)+len(s.CompanionAuthority)+len(s.IntentCompanionAuthority)+len(s.ReserveAuthority)+len(s.IntentReserveAuthority) != 0 || s.LegacyDigest != "" {
			return ingress.Authority{}, ErrInvalid
		}
		return a.grant, nil
	}
	current, e := ingress.VerifyAuthorityDocument(s.Authority, a.b.Local.Owner)
	if e != nil || !sameAuthorityScope(current, a.anchor) || current.Revision <= a.anchor.Revision || !storage.ID(s.LegacyDigest) {
		return current, ErrInvalid
	}
	if a.b.Profile.MinimumCopies == 2 && a.b.Reserve == nil {
		initialRaw := a.initialObservation
		initial, e := observation.VerifyGrant(initialRaw, a.b.Local.Owner)
		if e != nil {
			return current, e
		}
		now, e := observation.VerifyGrant(s.Observation, a.b.Local.Owner)
		if e != nil || !sameObservationScope(initial, now) || now.Epoch < initial.Epoch || now.Epoch == initial.Epoch && !bytes.Equal(initialRaw, s.Observation) {
			return current, ErrInvalid
		}
	} else if len(s.Observation) != 0 {
		return current, ErrInvalid
	}
	old, e := a.store.Read("agent-v1-" + s.LegacyDigest + ".json")
	if e != nil {
		return current, e
	}
	var legacy state
	if storage.Hash(old) != s.LegacyDigest || storage.Decode(old, &legacy, maxState) != nil || legacy.Format != Format || legacy.Binding != a.binding || legacy.Sequence > s.Sequence || legacy.ObservedUnix > s.ObservedUnix || legacy.Sequence == s.Sequence && legacy.Generation != s.Generation {
		return current, ErrInvalid
	}
	sig := legacy.Signature
	legacy.Signature = nil
	unsigned, _ := json.Marshal(legacy)
	if !ed25519.Verify(a.anchor.Trust.Writer, append([]byte(Format+"\x00"), unsigned...), sig) {
		return current, ErrInvalid
	}
	var prior ingress.Authority
	if s.Phase != "IDLE" {
		prior, e = ingress.VerifyAuthorityDocument(s.IntentAuthority, a.b.Local.Owner)
		if e != nil || !sameAuthorityScope(current, prior) || prior.Revision > current.Revision {
			return current, ErrInvalid
		}
		if s.Phase != "COMPLETE" && s.Phase != "ABANDONED" && !bytes.Equal(s.IntentAuthority, s.Authority) {
			return current, ErrInvalid
		}
	} else if len(s.IntentAuthority) != 0 {
		return current, ErrInvalid
	}
	if e = a.verifyCompanionState(s, current, prior); e != nil {
		return current, e
	}
	if e = a.verifyReserveState(s, current, prior); e != nil {
		return current, e
	}
	if !adopt && (!bytes.Equal(a.authority, s.Authority) || !bytes.Equal(a.observation, s.Observation) ||
		!bytes.Equal(a.companionAuthority, s.CompanionAuthority) || !bytes.Equal(a.reserveAuthority, s.ReserveAuthority)) {
		return current, ErrAuthorityChanged
	}
	return current, nil
}

func (a *Agent) verifyCompanionState(s state, current, prior ingress.Authority) error {
	if a.b.Companion == nil {
		if len(s.CompanionAuthority)+len(s.IntentCompanionAuthority) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if e := a.verifyCompanionAuthority(current, s.CompanionAuthority); e != nil {
		return e
	}
	if s.Phase == "IDLE" {
		if len(s.IntentCompanionAuthority) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if prior.Revision == current.Revision && !bytes.Equal(s.IntentCompanionAuthority, s.CompanionAuthority) {
		return ErrInvalid
	}
	return a.verifyCompanionAuthority(prior, s.IntentCompanionAuthority)
}
func (a *Agent) verifyReserveAuthority(primary ingress.Authority, raw []byte) error {
	reserve, err := ingress.VerifyAuthorityDocument(raw, a.b.Local.Owner)
	if err != nil {
		return err
	}
	if reserve.Ingress != a.reserve.Ingress || !sameReceiverPair(primary, reserve) {
		return ingress.ErrDenied
	}
	return nil
}

func (a *Agent) verifyReserveState(s state, current, prior ingress.Authority) error {
	if a.b.Reserve == nil {
		if len(s.ReserveAuthority)+len(s.IntentReserveAuthority) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if err := a.verifyReserveAuthority(current, s.ReserveAuthority); err != nil {
		return err
	}
	if s.Phase == "IDLE" {
		if len(s.IntentReserveAuthority) != 0 {
			return ErrInvalid
		}
		return nil
	}
	if prior.Revision == current.Revision && !bytes.Equal(s.IntentReserveAuthority, s.ReserveAuthority) {
		return ErrInvalid
	}
	return a.verifyReserveAuthority(prior, s.IntentReserveAuthority)
}

func (a *Agent) intentAuthority(s state) []byte {
	if a.b.Standby {
		var i ingress.Intent
		if storage.Decode(s.Intent, &i, ingress.MaxDocument) == nil && a.standbySelected(i.Ingress) {
			if s.Format == renewedFormat {
				return s.IntentCompanionAuthority
			}
			return a.companionAuthority
		}
	}
	if s.Format == renewedFormat {
		return s.IntentAuthority
	}
	return a.authority
}
func (a *Agent) stateIntent(s state) (ingress.Intent, error) {
	raw := a.intentAuthority(s)
	var i ingress.Intent
	if storage.Decode(s.Intent, &i, ingress.MaxDocument) != nil {
		return i, ErrInvalid
	}
	i, _, e := ingress.VerifyIntent(s.Intent, raw, a.b.Local.Owner, time.Unix(i.NotBefore, 0))
	return i, e
}

type Renewal struct {
	Format       string `json:"format"`
	Profile      string `json:"profile"`
	Revision     uint64 `json:"revision"`
	Sequence     uint64 `json:"sequence"`
	Generation   string `json:"generation,omitempty"`
	LegacyDigest string `json:"legacyDigest"`
	Reopen       bool   `json:"reopen"`
}

// Renew is explicit and quiescent. It never extends an immutable pending intent,
// changes source selection or drops an unfinished capture to make progress.
// Original private grant files remain bootstrap anchors; new inputs are separate.
func (a *Agent) Renew(ctx context.Context, authority, observed []byte) (Renewal, error) {
	return a.RenewPair(ctx, authority, nil, observed)
}

// RenewPair commits both matching owner grants in the same signed source
// journal. The receiver registries are renewed separately before new capture.
func (a *Agent) RenewPair(ctx context.Context, authority, companion, observed []byte) (Renewal, error) {
	return a.RenewReceivers(ctx, authority, companion, nil, observed)
}

// RenewReceivers commits all configured owner grants as one source revision.
func (a *Agent) RenewReceivers(ctx context.Context, authority, companion, reserve, observed []byte) (Renewal, error) {
	var out Renewal
	if (a.b.Companion != nil) != (len(companion) != 0) || (a.b.Reserve != nil) != (len(reserve) != 0) {
		return out, ErrUnsupported
	}
	next, e := ingress.VerifyAuthority(authority, a.b.Local.Owner, time.Now())
	if e != nil {
		return out, e
	}
	if !sameAuthorityScope(next, a.anchor) {
		return out, ingress.ErrDenied
	}
	if len(companion) != 0 {
		if e = a.verifyCompanionAuthority(next, companion); e != nil {
			return out, e
		}
	}
	if len(reserve) != 0 {
		if e = a.verifyReserveAuthority(next, reserve); e != nil {
			return out, e
		}
	}
	if observed == nil {
		observed = bytes.Clone(a.observation)
	}
	if a.b.Profile.MinimumCopies == 2 && a.b.Reserve == nil {
		old, e := observation.VerifyGrant(a.observation, a.b.Local.Owner)
		if e != nil {
			return out, e
		}
		new, e := observation.VerifyGrant(observed, a.b.Local.Owner)
		if e != nil || !sameObservationScope(old, new) || new.Epoch < old.Epoch || new.Epoch == old.Epoch && !bytes.Equal(observed, a.observation) || time.Now().Unix() < new.NotBefore || time.Now().Unix() >= new.ExpiresUnix {
			return out, observation.ErrDenied
		}
	} else if len(observed) != 0 {
		return out, ErrInvalid
	}
	e = a.lease.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		// Admission may have waited for another capture process. Validate the
		// current validity window again under the execution lease, not only
		// before that potentially long wait.
		if _, e := ingress.VerifyAuthority(authority, a.b.Local.Owner, time.Now()); e != nil {
			return e
		}
		if a.b.Profile.MinimumCopies == 2 && a.b.Reserve == nil {
			g, e := observation.VerifyGrant(observed, a.b.Local.Owner)
			now := time.Now().Unix()
			if e != nil || now < g.NotBefore || now >= g.ExpiresUnix {
				return observation.ErrDenied
			}
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		same := bytes.Equal(authority, a.authority) && bytes.Equal(observed, a.observation) && bytes.Equal(companion, a.companionAuthority) && bytes.Equal(reserve, a.reserveAuthority)
		if next.Revision < a.grant.Revision || next.Revision == a.grant.Revision && !same {
			return ingress.ErrConflict
		}
		if s.Format == renewedFormat && same {
			out = Renewal{renewedFormat, a.b.Profile.ID, next.Revision, s.Sequence, s.Generation, s.LegacyDigest, true}
			return nil
		}
		if next.Revision <= a.grant.Revision || s.Phase != "IDLE" && s.Phase != "COMPLETE" && s.Phase != "ABANDONED" {
			return ingress.ErrConflict
		}
		if s.Format == Format {
			raw, e := a.store.Read("agent.json")
			if e != nil {
				return e
			}
			s.LegacyDigest = storage.Hash(raw)
			name := "agent-v1-" + s.LegacyDigest + ".json"
			previous, e := a.store.Read(name)
			if errors.Is(e, os.ErrNotExist) {
				e = a.store.Write(name, raw)
			} else if e == nil && !bytes.Equal(previous, raw) {
				e = ErrInvalid
			}
			if e != nil {
				return e
			}
			if e = a.point("source-renewal-checkpoint-durable"); e != nil {
				return e
			}
			if len(s.Intent) > 0 {
				s.IntentAuthority = bytes.Clone(a.authority)
				s.IntentCompanionAuthority = bytes.Clone(a.companionAuthority)
				s.IntentReserveAuthority = bytes.Clone(a.reserveAuthority)
			}
		}
		s.Format = renewedFormat
		s.Authority = bytes.Clone(authority)
		s.CompanionAuthority = bytes.Clone(companion)
		s.ReserveAuthority = bytes.Clone(reserve)
		s.Observation = bytes.Clone(observed)
		if e = a.save(s); e != nil {
			return e
		}
		out = Renewal{renewedFormat, a.b.Profile.ID, next.Revision, s.Sequence, s.Generation, s.LegacyDigest, true}
		return a.point("source-renewal-committed")
	})
	return out, e
}
