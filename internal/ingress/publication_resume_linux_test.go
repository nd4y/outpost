package ingress

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
)

func TestPublicationGrantResumesFrozenLocalCatalogWithoutPeer(t *testing.T) {
	f := setup(t)
	ctx := t.Context()
	must(t, os.WriteFile(f.input, []byte("frozen catalog ciphertext fixture"), 0600))
	v, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
	must(t, err)
	raw, roots := f.catalog(t, []string{v.Version})
	f.roots(t, roots)
	// Persist a valid historical intent and the same sealed catalog as a
	// process would leave before running the first verification batch.
	i := f.intent
	i.NotBefore, i.ExpiresUnix = f.authority.NotBefore, f.authority.NotBefore+2
	intent, err := SignIntent(i, f.options.Authority, f.options.Owner, f.writer, time.Unix(i.NotBefore, 0))
	must(t, err)
	f.session.state.Intent = intent
	must(t, f.session.save())
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil
	o := f.options
	o.Intent, o.Initialize = intent, false
	now := time.Now().Unix()
	grant := Settlement{Format: SettlementFormat, Purpose: SettlementPublish, ID: storage.Hash([]byte("publish local")),
		Authority: i.Authority, Intent: storage.Hash(intent), Operation: i.Operation, Source: i.Source,
		Ingress: i.Ingress, Tenant: i.Tenant, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch,
		Generation: storage.Hash(raw), NotBefore: now, ExpiresUnix: now + 300}
	o.publishGrant, err = SignSettlement(grant, o.Authority, o.Intent, f.control, time.Now())
	must(t, err)
	if s, err := openSessionFor(ctx, o, sessionPublish); !errors.Is(err, ErrDenied) {
		if s != nil {
			s.Close()
		}
		t.Fatal("fresh publication grant created an unsealed catalog", err)
	}
	s, err := openSessionFor(ctx, SessionOptions{Directory: o.Directory, Authority: o.Authority, Intent: o.Intent, Owner: o.Owner, Replica: o.Replica}, sessionInspect)
	must(t, err)
	s.state.Catalog = raw
	must(t, s.save())
	must(t, s.Close())
	s, err = openSessionFor(ctx, o, sessionPublish)
	must(t, err)
	defer s.Close()
	if _, _, err = s.FinishBatch(ctx, []byte("changed catalog"), 256, 256<<20); !errors.Is(err, ErrConflict) {
		t.Fatal("fresh publication grant accepted another catalog", err)
	}
	var receipt Receipt
	for {
		progress, r, err := s.FinishBatch(ctx, raw, 256, 256<<20)
		must(t, err)
		if progress.Complete {
			receipt = r
			break
		}
	}
	if receipt.PublishedWith != string(o.publishGrant) || receipt.VerifiedAt < i.ExpiresUnix {
		t.Fatal("late receipt did not preserve original authorization and time", receipt)
	}
	must(t, o.Replica.VerifyComplete(ctx, receipt.Generation))
	ack, err := s.Acknowledge(ctx, receipt, 256)
	must(t, err)
	if !ack.Clean {
		t.Fatal("acknowledgement did not finish")
	}
}
