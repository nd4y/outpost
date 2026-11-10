package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
)

const registryJournalFormat = "outpost-management-registry-copy-1"
const registryJournalCopyName = "registry-copy.json"
const registryJournalAnchorName = "registry-anchor"
const maxRegistryJournal = maxRegistry + 4096

var ErrRegistryJournal = errors.New("management registry journal requires verified repair")

type registryJournal struct {
	Format    string          `json:"format"`
	Previous  string          `json:"previous,omitempty"`
	Registry  json.RawMessage `json:"registry"`
	Signature []byte          `json:"signature,omitempty"`
}

func (r *Registry) requireNoJournalCopy() error {
	for _, name := range []string{registryJournalCopyName, registryJournalAnchorName} {
		if _, e := localfs.Stat(r.root, name); !errors.Is(e, os.ErrNotExist) {
			return errors.Join(ErrRegistryJournal, e)
		}
	}
	return nil
}

func (r *Registry) writeRegistryJournal(raw []byte, initial bool) error {
	copy := registryJournal{Format: registryJournalFormat, Registry: raw}
	if !initial {
		prior, e := r.store.Read("registry.json")
		if e != nil {
			return e
		}
		copy.Previous = storage.Hash(prior)
	}
	unsigned, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	copy.Signature = ed25519.Sign(r.signer, append([]byte(registryJournalFormat+"\x00"), unsigned...))
	signed, e := json.Marshal(copy)
	if e != nil {
		return e
	}
	if e = r.store.Write(registryJournalCopyName, signed); e != nil {
		return e
	}
	if e = r.point("management-registry-copy-durable"); e != nil {
		return e
	}
	if e = r.store.Write(registryJournalAnchorName, []byte(storage.Hash(raw))); e != nil {
		return e
	}
	return r.point("management-registry-anchor-durable")
}

func (r *Registry) readRegistryJournal() (registryJournal, error) {
	var copy registryJournal
	raw, e := r.store.Read(registryJournalCopyName)
	if e != nil {
		return copy, errors.Join(ErrRegistryJournal, e)
	}
	if canonical(raw, &copy, maxRegistryJournal) != nil || copy.Format != registryJournalFormat || copy.Previous != "" && !storage.ID(copy.Previous) {
		return copy, ErrRegistryJournal
	}
	sig := copy.Signature
	copy.Signature = nil
	unsigned, e := json.Marshal(copy)
	if e != nil || !ed25519.Verify(r.signer.Public().(ed25519.PublicKey), append([]byte(registryJournalFormat+"\x00"), unsigned...), sig) {
		return copy, ErrRegistryJournal
	}
	return copy, nil
}

func (r *Registry) checkRegistryJournal(raw []byte) error {
	copy, e := r.readRegistryJournal()
	if e != nil || !bytes.Equal(copy.Registry, raw) {
		return errors.Join(ErrRegistryJournal, e)
	}
	anchor, e := r.store.Read(registryJournalAnchorName)
	if e != nil || string(anchor) != storage.Hash(raw) {
		return errors.Join(ErrRegistryJournal, e)
	}
	return nil
}

func (r *Registry) recoverRegistryJournal(ctx context.Context) error {
	prior, e := r.store.Read("registry.json")
	missing := errors.Is(e, os.ErrNotExist)
	if e != nil && !missing {
		return errors.Join(ErrRegistryJournal, e)
	}
	copy, e := r.readRegistryJournal()
	if e != nil {
		return e
	}
	anchor, e := r.store.Read(registryJournalAnchorName)
	if e != nil {
		return errors.Join(ErrRegistryJournal, e)
	}
	next := storage.Hash(copy.Registry)
	current := bytes.Equal(prior, copy.Registry)
	if string(anchor) != next && (missing || current || string(anchor) != copy.Previous) {
		return ErrRegistryJournal
	}
	signer := r.signer.Public().(ed25519.PublicKey)
	s, e := validateRegistry(copy.Registry, r.owner, signer)
	if e != nil || !s.JournalCopy {
		return errors.Join(ErrRegistryJournal, e)
	}
	if !missing && !current {
		before, e := validateRegistry(prior, r.owner, signer)
		if e != nil || !before.JournalCopy || copy.Previous != storage.Hash(prior) || s.Revision != before.Revision+1 {
			return errors.Join(ErrRegistryJournal, e)
		}
	}
	for _, ref := range snapshotRefs(s)[1:] {
		if e := ctx.Err(); e != nil {
			return e
		}
		raw, e := snapshotRead(r.root, ref)
		if ref.optional && errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || checkSnapshotDependency(s, ref, raw) != nil {
			return errors.Join(ErrRegistryJournal, e)
		}
	}
	if e = r.check(ctx); e != nil || current {
		return e
	}
	if string(anchor) != next {
		if e = r.store.Write(registryJournalAnchorName, []byte(next)); e != nil {
			return e
		}
	}
	return errors.Join(r.store.Write("registry.json", copy.Registry), r.check(ctx))
}
