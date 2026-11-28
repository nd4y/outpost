package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

const RegistryJournalFormat = "outpost-ingress-registry-copy-1"
const registryJournalCopyName = "registry-copy.json"
const registryJournalAnchorName = "registry-anchor"
const maxRegistryJournal = maxRegistryState + 4096

var ErrRegistryRecovery = errors.New("ingress registry requires explicit verified recovery")

type registryJournal struct {
	Format    string          `json:"format"`
	Node      string          `json:"node"`
	Previous  string          `json:"previous"`
	Registry  json.RawMessage `json:"registry"`
	Signature []byte          `json:"signature,omitempty"`
}

func (g *Registry) journalKey() (ed25519.PrivateKey, error) {
	key, privateOK := g.options.Certificate.PrivateKey.(ed25519.PrivateKey)
	public, publicOK := g.leaf.PublicKey.(ed25519.PublicKey)
	if !privateOK || !publicOK || len(key) != ed25519.PrivateKeySize || peer.Identity(g.leaf) != g.authority.Ingress || !bytes.Equal(key.Public().(ed25519.PublicKey), public) {
		return nil, ErrRegistryRecovery
	}
	return key, nil
}

func (g *Registry) writeJournalCopy(raw []byte) error {
	key, e := g.journalKey()
	if e != nil || g.state.JournalNode != g.authority.Ingress {
		return ErrRegistryRecovery
	}
	old, e := g.store.Read("registry.json")
	if e != nil {
		return e
	}
	copy := registryJournal{Format: RegistryJournalFormat, Node: g.state.JournalNode, Previous: storage.Hash(old), Registry: raw}
	unsigned, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	copy.Signature = ed25519.Sign(key, append([]byte(RegistryJournalFormat+"\x00"), unsigned...))
	signed, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	if e = g.store.Write(registryJournalCopyName, signed); e != nil {
		return e
	}
	if e = g.point("ingress-registry-copy-durable"); e != nil {
		return e
	}
	if e = g.store.Write(registryJournalAnchorName, []byte(storage.Hash(raw))); e != nil {
		return e
	}
	return g.point("ingress-registry-anchor-durable")
}

func (g *Registry) readJournalCopy() (registryJournal, error) {
	var copy registryJournal
	raw, e := g.store.Read(registryJournalCopyName)
	if e != nil {
		return copy, e
	}
	key, e := g.journalKey()
	if e != nil || storage.Decode(raw, &copy, maxRegistryJournal) != nil || copy.Format != RegistryJournalFormat || copy.Node != g.authority.Ingress || !storage.ID(copy.Previous) {
		return copy, ErrRegistryRecovery
	}
	canonical, e := json.Marshal(copy)
	if e != nil || !bytes.Equal(raw, canonical) {
		return copy, ErrRegistryRecovery
	}
	sig := copy.Signature
	copy.Signature = nil
	unsigned, e := json.Marshal(copy)
	if e != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), append([]byte(RegistryJournalFormat+"\x00"), unsigned...), sig) {
		return copy, ErrRegistryRecovery
	}
	return copy, nil
}

func (g *Registry) checkJournalCopy(raw []byte) error {
	copy, e := g.readJournalCopy()
	if g.state.JournalNode == "" && errors.Is(e, os.ErrNotExist) {
		if _, e = g.store.Read(registryJournalAnchorName); errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return errors.Join(ErrRegistryRecovery, e)
	}
	if e != nil || g.state.JournalNode != g.authority.Ingress || !bytes.Equal(copy.Registry, raw) {
		return errors.Join(ErrRegistryRecovery, e)
	}
	anchor, e := g.store.Read(registryJournalAnchorName)
	if e != nil || string(anchor) != storage.Hash(raw) {
		return errors.Join(ErrRegistryRecovery, e)
	}
	return nil
}

// EnableRegistryJournalCopy upgrades an existing stopped receiver registry.
// It keeps the original intent, receipt and verification times.
func EnableRegistryJournalCopy(ctx context.Context, options RegistryOptions) error {
	g, e := openRegistry(ctx, options, true)
	if e != nil {
		return e
	}
	defer g.Close()
	return g.enableJournalCopy(ctx)
}

func (g *Registry) enableJournalCopy(ctx context.Context) error {
	if g.poisoned {
		return ErrRegistryRecovery
	}
	if g.state.JournalNode != "" {
		return nil
	}
	if _, e := g.journalKey(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	g.state.JournalNode = g.authority.Ingress
	return g.save()
}

// RecoverRegistryJournalCopy never activates a network handler or rebuilds a
// slot from absent data. It reconstructs the exact anchored registry bytes.
func RecoverRegistryJournalCopy(ctx context.Context, options RegistryOptions) (bool, error) {
	options.recoverJournal = true
	g, e := openRegistry(ctx, options, true)
	if e != nil {
		return false, e
	}
	defer g.Close()
	return g.journalReconstructed, nil
}

func (g *Registry) recoverJournal(ctx context.Context, primary []byte, primaryErr error) ([]byte, bool, error) {
	missing := errors.Is(primaryErr, os.ErrNotExist)
	if primaryErr != nil && !missing {
		return nil, false, primaryErr
	}
	copy, e := g.readJournalCopy()
	if e != nil {
		return nil, false, errors.Join(ErrRegistryRecovery, e)
	}
	anchor, anchorErr := g.store.Read(registryJournalAnchorName)
	next := storage.Hash(copy.Registry)
	pending := string(anchor) != next
	if pending {
		if missing || storage.Hash(primary) != copy.Previous {
			return nil, false, ErrRegistryRecovery
		}
		if errors.Is(anchorErr, os.ErrNotExist) {
			old, e := decodeRegistry(primary)
			if e != nil || old.JournalNode != "" {
				return nil, false, ErrRegistryRecovery
			}
		} else if anchorErr != nil || string(anchor) != copy.Previous {
			return nil, false, ErrRegistryRecovery
		}
	}
	if !missing && bytes.Equal(primary, copy.Registry) && !pending {
		return primary, false, nil
	}
	if !missing && storage.Hash(primary) != copy.Previous {
		return nil, false, ErrRegistryRecovery
	}
	if e = g.loadRegistry(copy.Registry); e != nil || g.state.JournalNode != g.authority.Ingress {
		return nil, false, errors.Join(ErrRegistryRecovery, e)
	}
	if e = g.verifyRecoveredSlot(ctx, primary); e != nil {
		return nil, false, e
	}
	if e = ctx.Err(); e != nil {
		return nil, false, e
	}
	if pending {
		if e = g.store.Write(registryJournalAnchorName, []byte(next)); e != nil {
			return nil, false, e
		}
	}
	if e = g.store.Write("registry.json", copy.Registry); e != nil {
		return nil, false, e
	}
	return copy.Registry, true, nil
}

func (g *Registry) verifyRecoveredSlot(ctx context.Context, predecessor []byte) error {
	emptySlot := func() error {
		if _, e := g.root.Lstat("current"); !errors.Is(e, os.ErrNotExist) {
			return errors.Join(ErrRegistryRecovery, e)
		}
		return nil
	}
	if len(g.state.Intent) == 0 {
		return emptySlot()
	}
	options := g.sessionOptions(g.state.Intent)
	options.Initialize = false
	session, slotErr := openSessionFor(ctx, options, sessionInspect)
	if slotErr == nil {
		return session.Close()
	}
	// The registry commits a new intent before opening the slot. An exact
	// surviving predecessor can prove this transition without creating a slot.
	before, e := decodeRegistry(predecessor)
	if e != nil || before.Authority != g.state.Authority || bytes.Equal(before.Intent, g.state.Intent) {
		return errors.Join(ErrRegistryRecovery, slotErr)
	}
	if len(before.Intent) == 0 {
		return emptySlot()
	}
	options.Intent = before.Intent
	if before.Format == RenewedRegistryFormat {
		options.Authority = before.IntentAuthority
	} else {
		options.Authority = g.options.Authority
	}
	session, e = openSessionFor(ctx, options, sessionInspect)
	if e != nil {
		return errors.Join(ErrRegistryRecovery, e)
	}
	settled := session.state.Acknowledged || len(session.state.Reclaimed) != 0 || len(session.state.Retired) != 0
	e = session.Close()
	if !settled {
		return errors.Join(ErrRegistryRecovery, e)
	}
	return e
}
