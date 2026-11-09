package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

const MaxSettlementAdmission = 2*ingress.MaxDocument + ingress.MaxSettlementDocument + 1024

// SettlementPreview exports only signed public authority/intent and an unsigned
// request. It neither contacts the receiver nor proves remote completion.
func (a *Agent) SettlementPreview(ctx context.Context) (control.SettlementAdmission, error) {
	return a.SettlementPreviewFor(ctx, "", "")
}

func (a *Agent) settlementReceiver(s state, receiver string) (ingress.Intent, []byte, []byte, string, error) {
	i, err := a.stateIntent(s)
	if err != nil {
		return i, nil, nil, "", err
	}
	if receiver == "" || receiver == i.Ingress {
		return i, a.intentAuthority(s), s.Intent, a.receiverEndpoint(i.Ingress), nil
	}
	if a.b.Companion == nil || a.b.Standby || receiver != a.companion.Ingress {
		return i, nil, nil, "", ErrInvalid
	}
	authority := a.companionAuthority
	if s.Format == renewedFormat {
		authority = s.IntentCompanionAuthority
	}
	i, raw, err := a.companionIntent(i, authority)
	return i, authority, raw, a.b.Companion.Endpoint, err
}

func (a *Agent) SettlementPreviewFor(ctx context.Context, purpose, receiver string) (control.SettlementAdmission, error) {
	if purpose != "" && purpose != ingress.SettlementPublish && purpose != ingress.SettlementInspect && purpose != ingress.SettlementRetire {
		return control.SettlementAdmission{}, ErrInvalid
	}
	var out control.SettlementAdmission
	e := a.lease.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		if s.Phase != "ACTIVE" {
			return ErrInvalid
		}
		i, authority, intent, _, e := a.settlementReceiver(s, receiver)
		if e != nil {
			return e
		}
		now := time.Now().Unix()
		if purpose != "" && now < i.ExpiresUnix {
			return ErrInvalid
		}
		var id string
		if purpose != ingress.SettlementInspect && purpose != ingress.SettlementRetire {
			job, close, e := a.openJobMode(ctx, s, true, nil)
			if e != nil {
				return e
			}
			defer close()
			j, e := job.Status(ctx)
			if e != nil || !storage.ID(j.Generation) {
				return ErrInvalid
			}
			id = j.Generation
		}
		var nonce [32]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return e
		}
		out.Authority, out.Intent = bytes.Clone(authority), bytes.Clone(intent)
		out.Grant, e = json.Marshal(ingress.Settlement{Format: ingress.SettlementFormat, ID: storage.Hash(nonce[:]), Authority: storage.Hash(out.Authority), Intent: storage.Hash(out.Intent), Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Purpose: purpose, Generation: id, NotBefore: now, ExpiresUnix: now + 600})
		return e
	})
	return out, e
}

// SignSettlementAdmission is an owner-side offline action. The returned
// admission must also be installed in a fresh signed control2 receiver view.
func SignSettlementAdmission(item control.SettlementAdmission, key ed25519.PrivateKey) (control.SettlementAdmission, error) {
	var g ingress.Settlement
	if storage.Decode(item.Grant, &g, ingress.MaxSettlementDocument) != nil || len(g.Signature) != 0 {
		return control.SettlementAdmission{}, ErrInvalid
	}
	raw, e := ingress.SignSettlement(g, item.Authority, item.Intent, key, time.Now())
	if e != nil {
		return control.SettlementAdmission{}, e
	}
	return control.SettlementAdmission{Authority: bytes.Clone(item.Authority), Intent: bytes.Clone(item.Intent), Grant: raw}, nil
}

// Settle never renews or discards an intent. It resumes only local durable
// metadata/cleanup for the exact already sealed generation under a fresh grant.
func (a *Agent) Settle(ctx context.Context, item control.SettlementAdmission) error {
	return a.SettleWithCompanion(ctx, item, nil)
}

func (a *Agent) SettleWithCompanion(ctx context.Context, item control.SettlementAdmission, companion *control.SettlementAdmission) error {
	item = control.SettlementAdmission{Authority: bytes.Clone(item.Authority), Intent: bytes.Clone(item.Intent), Grant: bytes.Clone(item.Grant)}
	return a.lease.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		if (s.Phase != "ACTIVE" && s.Phase != "COMPLETE") || !bytes.Equal(item.Authority, a.intentAuthority(s)) || !bytes.Equal(item.Intent, s.Intent) {
			return ErrInvalid
		}
		g, e := ingress.VerifySettlement(item.Grant, item.Authority, item.Intent, a.b.Local.Owner, time.Now())
		if e != nil {
			return e
		}
		if g.Purpose != "" && g.Purpose != ingress.SettlementPublish {
			return ErrInvalid
		}
		if s.Phase == "COMPLETE" {
			if s.Generation != g.Generation {
				return ErrInvalid
			}
			return nil
		}
		expiry := g.ExpiresUnix
		var paired [][]byte
		if companion != nil {
			if a.b.Companion == nil || a.b.Standby {
				return ErrInvalid
			}
			_, authority, intent, _, e := a.settlementReceiver(s, a.companion.Ingress)
			if e != nil || !bytes.Equal(authority, companion.Authority) || !bytes.Equal(intent, companion.Intent) {
				return ErrInvalid
			}
			other, e := ingress.VerifySettlement(companion.Grant, authority, intent, a.b.Local.Owner, time.Now())
			if e != nil {
				return e
			}
			if other.Purpose != g.Purpose || other.Generation != g.Generation {
				return ErrInvalid
			}
			paired = append(paired, bytes.Clone(companion.Grant))
			expiry = min(expiry, other.ExpiresUnix)
		} else if g.Purpose == ingress.SettlementPublish && a.b.Companion != nil && !a.b.Standby {
			return ErrInvalid
		}
		ctx, cancel := context.WithDeadline(ctx, time.Unix(expiry, 0))
		defer cancel()
		return a.runSettlement(ctx, item.Grant, paired...)
	})
}
