package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/storage"
)

func (r *Registry) initialState() registryState {
	return registryState{
		Format: registryFormat, Owner: r.owner, Signer: r.signer.Public().(ed25519.PublicKey),
		Enrollments: map[string][]byte{}, Domains: map[string]domainFence{}, Operations: map[string]enrollmentOperation{},
		Reports: map[string]reportPointer{}, Configurations: map[string]configPointer{}, ConfigOperations: map[string]configOperation{},
	}
}

func (r *Registry) verifyInitialState(raw []byte) error {
	expected := r.initialState()
	state, e := validateRegistry(raw, expected.Owner, expected.Signer)
	if e != nil {
		return e
	}
	expected.Revision = 1
	expected.ObservedUnix = state.ObservedUnix
	expected.Signature = state.Signature
	expected.JournalCopy = r.journalCopy
	canonical, e := json.Marshal(expected)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrConflict
	}
	return nil
}

func (r *Registry) resumeInitialization(ctx context.Context) error {
	if e := r.check(ctx); e != nil {
		return e
	}
	primary, e := r.store.Read("registry.json")
	if e == nil {
		if e = r.verifyInitialState(primary); e != nil {
			return e
		}
		if r.journalCopy {
			return r.checkRegistryJournal(primary)
		}
		return r.requireNoJournalCopy()
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if r.journalCopy {
		copy, e := r.readRegistryJournal()
		if e == nil {
			return r.resumeInitialCopy(ctx, copy)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if e = r.requireNoJournalCopy(); e != nil {
		return e
	}
	return r.save(r.initialState())
}

func (r *Registry) resumeInitialCopy(ctx context.Context, copy registryJournal) error {
	if copy.Previous != "" || r.verifyInitialState(copy.Registry) != nil {
		return ErrRegistryJournal
	}
	digest := storage.Hash(copy.Registry)
	anchor, e := r.store.Read(registryJournalAnchorName)
	if e != nil && !errors.Is(e, os.ErrNotExist) || e == nil && string(anchor) != digest {
		return ErrRegistryJournal
	}
	if err := r.check(ctx); err != nil {
		return err
	}
	if errors.Is(e, os.ErrNotExist) {
		if e = r.store.Write(registryJournalAnchorName, []byte(digest)); e != nil {
			return e
		}
	}
	return errors.Join(r.store.Write("registry.json", copy.Registry), r.check(ctx))
}
