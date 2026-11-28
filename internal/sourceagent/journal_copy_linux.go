package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

const sourceJournalFormat = "outpost-source-journal-copy-1"
const sourceJournalFile = "journal.json"
const sourceStateFile = "agent.json"
const sourceJournalAnchor = "journal-anchor"
const sourceJournalAnchorPurpose = "outpost-source-journal-anchor-1\x00"
const maxSourceJournal = maxState + 4096

var journalLimits = diskbudget.Limits{Capacity: 32 << 20, Reserve: 4 << 20, Spool: 16 << 20, Telemetry: 64 << 10}

// JournalCopy is an explicit local enrollment. It must use a pre-created
// private directory on a separately bound volume root.
type JournalCopy struct {
	Volume    volume.Binding `json:"volume"`
	Directory string         `json:"directory"`
}

type sourceJournal struct {
	config JournalCopy
	root   *os.Root
	budget *diskbudget.Budget
	store  *statefile.Store
}

type journalRecord struct {
	Format    string          `json:"format"`
	Binding   string          `json:"binding"`
	Previous  string          `json:"previous,omitempty"`
	State     json.RawMessage `json:"state"`
	Signature []byte          `json:"signature,omitempty"`
}

func openSourceJournal(ctx context.Context, b Bootstrap, initialize bool) (*sourceJournal, error) {
	config := *b.JournalCopy
	if config.Volume.Scope != b.Local.Node || config.Volume.Root == b.Local.Volume.Root {
		return nil, ErrInvalid
	}
	root, err := config.Volume.Open(ctx, config.Directory, false)
	if err != nil {
		return nil, err
	}
	journal := &sourceJournal{config: config, root: root}
	fail := func(err error) (*sourceJournal, error) {
		return nil, errors.Join(err, journal.close())
	}
	primary, err := localfs.OpenRoot(b.Local.Volume.Root)
	if err != nil {
		return fail(err)
	}
	defer primary.Close()
	if err = localfs.Disjoint(ctx, primary, root); err != nil {
		return fail(err)
	}
	if initialize {
		source, err := localfs.OpenRoot(b.Tree.Path)
		if err != nil {
			return fail(err)
		}
		err = errors.Join(localfs.Disjoint(ctx, source, root), source.Close())
		if err != nil {
			return fail(err)
		}
	}
	if err = journal.guard(ctx); err != nil {
		return fail(err)
	}
	journal.budget, err = diskbudget.OpenAt(root, ctx, ".", journalLimits, initialize)
	if err != nil {
		return fail(err)
	}
	journal.store, err = statefile.OpenAt(root, "state", maxSourceJournal, initialize)
	if err != nil {
		return fail(err)
	}
	journal.store.Admit = func(name string, size int) (func(bool) error, error) {
		if err := journal.guard(context.Background()); err != nil {
			return nil, err
		}
		finish, err := journal.budget.Admission("state")(name, size)
		if err != nil {
			return nil, err
		}
		return func(done bool) error {
			return errors.Join(finish(done), journal.guard(context.Background()))
		}, nil
	}
	return journal, nil
}

func (j *sourceJournal) guard(ctx context.Context) error {
	return j.config.Volume.CheckHandle(ctx, j.config.Directory, j.root)
}

func (j *sourceJournal) close() error {
	var err error
	if j.store != nil {
		err = errors.Join(err, j.store.Close())
	}
	if j.budget != nil {
		err = errors.Join(err, j.budget.Close())
	}
	return errors.Join(err, j.root.Close())
}

func (a *Agent) readJournal() (journalRecord, error) {
	var record journalRecord
	raw, err := a.journal.store.Read(sourceJournalFile)
	if err != nil {
		return record, err
	}
	if storage.Decode(raw, &record, maxSourceJournal) != nil || record.Format != sourceJournalFormat ||
		record.Binding != a.binding || (record.Previous != "" && !storage.ID(record.Previous)) ||
		len(record.State) == 0 || len(record.State) > maxState {
		return record, ErrInvalid
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonical) {
		return record, ErrInvalid
	}
	signature := record.Signature
	record.Signature = nil
	message, err := json.Marshal(record)
	if err != nil || !ed25519.Verify(a.anchor.Trust.Writer, append([]byte(sourceJournalFormat+"\x00"), message...), signature) {
		return record, ErrInvalid
	}
	return record, nil
}

func (a *Agent) anchorMessage(digest string) []byte {
	return []byte(sourceJournalAnchorPurpose + a.binding + digest)
}

func (a *Agent) readJournalAnchor() (string, error) {
	raw, err := a.store.Read(sourceJournalAnchor)
	if err != nil {
		return "", err
	}
	const digestLength = 64
	if len(raw) != digestLength+ed25519.SignatureSize {
		return "", ErrInvalid
	}
	digest := string(raw[:digestLength])
	if !storage.ID(digest) || !ed25519.Verify(a.anchor.Trust.Writer, a.anchorMessage(digest), raw[digestLength:]) {
		return "", ErrInvalid
	}
	return digest, nil
}

func (a *Agent) writeJournalAnchor(digest string) error {
	sig := ed25519.Sign(a.writer, a.anchorMessage(digest))
	return a.store.Write(sourceJournalAnchor, append([]byte(digest), sig...))
}

func (a *Agent) publishJournalState(raw []byte) error {
	if err := a.writeJournalAnchor(storage.Hash(raw)); err != nil {
		return err
	}
	if err := a.point("source-journal-anchor-durable"); err != nil {
		return err
	}
	return a.store.Write(sourceStateFile, raw)
}

func (a *Agent) writeJournal(raw []byte, initialize bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return a.journal.store.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		local, localErr := a.store.Read(sourceStateFile)
		previous, copyErr := a.readJournal()
		anchor, anchorErr := a.readJournalAnchor()
		var parent string
		if initialize {
			if !errors.Is(localErr, os.ErrNotExist) || !errors.Is(anchorErr, os.ErrNotExist) {
				return ErrInvalid
			}
			if copyErr == nil {
				// A crash before publishing the initial runtime may leave its
				// original IDLE record. Reuse that exact binding and state.
				initial, err := a.decodeState(previous.State, false)
				if err != nil || previous.Previous != "" || initial.Phase != "IDLE" {
					return ErrInvalid
				}
				return a.publishJournalState(previous.State)
			}
			if !errors.Is(copyErr, os.ErrNotExist) {
				return copyErr
			}
		} else {
			if localErr != nil || copyErr != nil || anchorErr != nil || !bytes.Equal(local, previous.State) {
				return errors.Join(ErrInvalid, localErr, copyErr, anchorErr)
			}
			parent = storage.Hash(local)
			if anchor != parent {
				return ErrInvalid
			}
		}
		record := journalRecord{Format: sourceJournalFormat, Binding: a.binding, Previous: parent, State: raw}
		message, err := json.Marshal(record)
		if err != nil {
			return err
		}
		record.Signature = ed25519.Sign(a.writer, append([]byte(sourceJournalFormat+"\x00"), message...))
		message, err = json.Marshal(record)
		if err != nil {
			return err
		}
		if err = a.journal.store.Write(sourceJournalFile, message); err != nil {
			return err
		}
		if err = a.point("source-journal-copy-durable"); err != nil {
			return err
		}
		return a.publishJournalState(raw)
	})
}

func (a *Agent) reconcileJournal(ctx context.Context) error {
	if a.journal == nil {
		return nil
	}
	return a.journal.store.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		record, err := a.readJournal()
		if err != nil {
			return err
		}
		anchor, err := a.readJournalAnchor()
		if err != nil {
			return err
		}
		digest := storage.Hash(record.State)
		if digest != anchor && record.Previous != anchor {
			return ErrInvalid
		}
		local, localErr := a.store.Read(sourceStateFile)
		if localErr == nil && bytes.Equal(local, record.State) && digest == anchor {
			return a.journal.budget.Reconcile(ctx, journalLimits)
		}
		// A missing file or the signed immediate predecessor can be repaired.
		// A different local record is evidence and remains untouched.
		if (localErr == nil && storage.Hash(local) != record.Previous) ||
			(localErr != nil && !errors.Is(localErr, os.ErrNotExist)) {
			return errors.Join(ErrInvalid, localErr)
		}
		recovered, err := a.decodeState(record.State, true)
		if err != nil {
			return err
		}
		if recovered.Phase == "ACTIVE" {
			if recovered.RoutePreparing {
				recovered.Route = recovered.Superseded
				recovered.Superseded, recovered.RoutePreparing, recovered.RoutePlan, recovered.RouteCatalog = nil, false, "", ""
			}
			job, closeJob, err := a.openJobMode(ctx, recovered, true, nil)
			if err != nil {
				return err
			}
			_, err = job.Status(ctx)
			closeJob()
			if err != nil {
				return err
			}
		}
		if err = a.journal.budget.Reconcile(ctx, journalLimits); err != nil {
			return err
		}
		if err = a.budget.Reconcile(ctx, a.b.Limits); err != nil {
			return err
		}
		if digest != anchor {
			return a.publishJournalState(record.State)
		}
		return a.store.Write(sourceStateFile, record.State)
	})
}
