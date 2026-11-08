package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

type RegistryRenewal struct {
	Format            string `json:"format"`
	Revision          uint64 `json:"revision"`
	Authority         string `json:"authority"`
	PreviousAuthority string `json:"previousAuthority"`
	LegacyDigest      string `json:"legacyDigest"`
}

func (g *Registry) renewalResult() RegistryRenewal {
	return RegistryRenewal{Format: g.state.Format, Revision: g.authority.Revision, Authority: g.state.Authority, PreviousAuthority: storage.Hash(g.state.PreviousAuthority), LegacyDigest: g.state.LegacyDigest}
}

// RenewRegistry is an explicit local maintenance action. o.Authority is the
// signed previous authority, fresh is the separately signed current authority.
// The caller must exclude its worker, enforce current policy and provide the
// existing metadata quota/volume admission. No network handler is returned.
func RenewRegistry(ctx context.Context, o RegistryOptions, fresh []byte, guard func(context.Context) error, fault func(string) error) (RegistryRenewal, error) {
	var result RegistryRenewal
	if o.Initialize || len(o.Settlement)+len(o.SettlementIntent) != 0 || len(o.Authority) > MaxDocument || len(fresh) > MaxDocument {
		return result, ErrDenied
	}
	fresh = bytes.Clone(fresh)
	previous := bytes.Clone(o.Authority)
	old, e := VerifyAuthorityDocument(previous, o.Owner)
	if e != nil {
		return result, e
	}
	current, e := VerifyAuthority(fresh, o.Owner, time.Now())
	if e != nil || !SameAuthorityScope(old, current) || current.Revision <= old.Revision {
		return result, ErrDenied
	}
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if guard != nil {
			if e := guard(ctx); e != nil {
				return e
			}
		}
		_, e := VerifyAuthority(fresh, o.Owner, time.Now())
		return e
	}
	if e = check(); e != nil {
		return result, e
	}
	o.Authority = previous
	g, e := openRegistry(ctx, o, true)
	if errors.Is(e, ErrConflict) {
		// A lost reply after migration may leave exactly this new authority
		// committed. Read it back; never rewrite or roll back a later grant.
		currentOptions := o
		currentOptions.Authority = fresh
		g, e = OpenRegistry(ctx, currentOptions)
		if e != nil {
			return result, e
		}
		defer g.Close()
		if g.state.Format != RenewedRegistryFormat || !bytes.Equal(g.state.PreviousAuthority, previous) {
			return result, ErrConflict
		}
		if e = check(); e != nil {
			return result, e
		}
		return g.renewalResult(), nil
	}
	if e != nil {
		return result, e
	}
	defer g.Close()
	g.Fault = fault
	if e = check(); e != nil {
		return result, e
	}
	if e = g.renewalQuiescent(ctx); e != nil {
		return result, e
	}
	if e = check(); e != nil {
		return result, e
	}
	before := g.state
	if before.Format == RegistryFormat {
		raw, e := g.store.Read("registry.json")
		if e != nil {
			return result, e
		}
		digest := storage.Hash(raw)
		name := "registry-v1-" + digest + ".json"
		existing, e := g.store.Read(name)
		if errors.Is(e, os.ErrNotExist) {
			e = g.store.Write(name, raw)
		} else if e == nil && !bytes.Equal(existing, raw) {
			e = ErrConflict
		}
		if e != nil {
			return result, e
		}
		if e = g.point("ingress-renewal-legacy-durable"); e != nil {
			return result, e
		}
		g.state.OriginalAuthority = bytes.Clone(previous)
		g.state.LegacyDigest = digest
		if len(g.state.Intent) != 0 {
			g.state.IntentAuthority = bytes.Clone(previous)
		}
	}
	if e = check(); e != nil {
		return result, e
	}
	g.state.Format = RenewedRegistryFormat
	g.state.PreviousAuthority = bytes.Clone(previous)
	g.state.CurrentAuthority = bytes.Clone(fresh)
	g.state.Authority = storage.Hash(fresh)
	g.state.ObservedUnix = time.Now().Unix()
	if e = g.save(); e != nil {
		g.state = before
		return result, e
	}
	g.authority = current
	if e = g.point("ingress-renewal-committed"); e != nil {
		return result, e
	}
	if e = check(); e != nil {
		return result, e
	}
	return g.renewalResult(), nil
}

// Inspection is deliberately non-mutating: renewal does not complete an ACK,
// release a pin, delete a temporary object or infer completion from a head.
func (g *Registry) renewalQuiescent(ctx context.Context) error {
	if len(g.state.Intent) == 0 {
		_, e := g.root.Lstat("current")
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		return ErrConflict
	}
	o := g.sessionOptions(g.state.Intent)
	o.Initialize = false
	s, e := openSessionMode(ctx, o, true, true)
	if e != nil {
		return e
	}
	defer s.Close()
	if !s.state.Complete || !s.state.Acknowledged || s.state.Receipt == nil || len(s.refs) != 0 || s.bytes != 0 {
		return ErrConflict
	}
	d, e := s.objectRoot.Open(".")
	if e != nil {
		return e
	}
	names, e := d.ReadDir(1)
	d.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return e
	}
	if len(names) != 0 {
		return ErrConflict
	}
	status, e := g.options.Replica.Status(ctx)
	if e != nil {
		return e
	}
	for _, kind := range []string{"base", "receipt"} {
		if _, exists := status.Pins[s.pin(kind)]; exists {
			return ErrConflict
		}
	}
	return nil
}
