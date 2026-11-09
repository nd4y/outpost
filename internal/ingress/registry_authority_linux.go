package ingress

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

// SameAuthorityScope compares only scope. Callers must independently verify
// owner signatures, current validity and monotonic revisions before admission.
func SameAuthorityScope(a, b Authority) bool {
	a.Revision, b.Revision = 0, 0
	a.NotBefore, b.NotBefore = 0, 0
	a.ExpiresUnix, b.ExpiresUnix = 0, 0
	a.Signature, b.Signature = nil, nil
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (g *Registry) intentAuthority() []byte {
	if g.state.Format == RenewedRegistryFormat {
		return g.state.IntentAuthority
	}
	return g.options.Authority
}

func decodeRegistry(raw []byte) (registryState, error) {
	var s registryState
	if storage.Decode(raw, &s, maxRegistryState) != nil {
		return s, ErrConflict
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(raw, canonical) || s.ObservedUnix < 1 || s.ObservedUnix > time.Now().Unix() {
		return s, ErrConflict
	}
	return s, nil
}

func legacyRegistry(raw, authority []byte, owner ed25519.PublicKey) (registryState, error) {
	s, e := decodeRegistry(raw)
	if e != nil {
		return s, e
	}
	if s.Format != RegistryFormat || s.Authority != storage.Hash(authority) || len(s.CurrentAuthority)+len(s.IntentAuthority)+len(s.OriginalAuthority)+len(s.PreviousAuthority) != 0 || s.LegacyDigest != "" {
		return s, ErrConflict
	}
	if len(s.Intent) != 0 {
		var i Intent
		if canonicalIntent(s.Intent, authority, owner, &i) != nil {
			return s, ErrConflict
		}
	}
	return s, nil
}

func (g *Registry) loadRegistry(raw []byte) error {
	s, e := decodeRegistry(raw)
	if e != nil {
		return e
	}
	if s.Format == RegistryFormat {
		s, e = legacyRegistry(raw, g.options.Authority, g.options.Owner)
		if e != nil {
			return e
		}
		g.state = s
		return nil
	}
	if s.Format != RenewedRegistryFormat || !storage.ID(s.LegacyDigest) || s.Authority != storage.Hash(s.CurrentAuthority) {
		return ErrConflict
	}
	current, e := VerifyAuthorityDocument(s.CurrentAuthority, g.options.Owner)
	if e != nil {
		return e
	}
	original, e := VerifyAuthorityDocument(s.OriginalAuthority, g.options.Owner)
	if e != nil || !SameAuthorityScope(current, original) || original.Revision >= current.Revision {
		return ErrConflict
	}
	previous, e := VerifyAuthorityDocument(s.PreviousAuthority, g.options.Owner)
	if e != nil || !SameAuthorityScope(current, previous) || previous.Revision < original.Revision || previous.Revision >= current.Revision || previous.Revision == original.Revision && !bytes.Equal(s.PreviousAuthority, s.OriginalAuthority) {
		return ErrConflict
	}
	checkpoint, e := g.store.Read("registry-v1-" + s.LegacyDigest + ".json")
	if e != nil {
		return e
	}
	if storage.Hash(checkpoint) != s.LegacyDigest {
		return ErrConflict
	}
	legacy, e := legacyRegistry(checkpoint, s.OriginalAuthority, g.options.Owner)
	if e != nil || legacy.ObservedUnix > s.ObservedUnix {
		return ErrConflict
	}
	if len(s.Intent) == 0 {
		if len(s.IntentAuthority)+len(legacy.Intent) != 0 {
			return ErrConflict
		}
	} else {
		historical, e := VerifyAuthorityDocument(s.IntentAuthority, g.options.Owner)
		if e != nil || !SameAuthorityScope(current, historical) || historical.Revision < original.Revision || historical.Revision > current.Revision || historical.Revision == original.Revision && !bytes.Equal(s.IntentAuthority, s.OriginalAuthority) || historical.Revision == current.Revision && !bytes.Equal(s.IntentAuthority, s.CurrentAuthority) {
			return ErrConflict
		}
		var i Intent
		if canonicalIntent(s.Intent, s.IntentAuthority, g.options.Owner, &i) != nil {
			return ErrConflict
		}
		if len(legacy.Intent) != 0 {
			var prior Intent
			if canonicalIntent(legacy.Intent, s.OriginalAuthority, g.options.Owner, &prior) != nil || i.Sequence < prior.Sequence || i.Sequence == prior.Sequence && !bytes.Equal(s.Intent, legacy.Intent) {
				return ErrConflict
			}
		}
	}
	if len(g.options.Settlement) != 0 {
		grant, err := VerifySettlement(g.options.Settlement, g.options.Authority, g.options.SettlementIntent, g.options.Owner, time.Now())
		if err != nil || !bytes.Equal(g.options.Authority, s.IntentAuthority) &&
			(!grant.inspect() || !bytes.Equal(g.options.Authority, s.CurrentAuthority)) {
			return ErrConflict
		}
	} else if !bytes.Equal(g.options.Authority, s.CurrentAuthority) {
		return ErrConflict
	}
	g.state = s
	return nil
}
