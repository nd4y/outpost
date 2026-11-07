package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type fixture struct {
	base            string
	owner           filekit.Owner
	control, writer ed25519.PrivateKey
	authority       Authority
	intent          Intent
	options         SessionOptions
	session         *Session
	source          *filekit.Store
	input           string
	payload         []byte
}

func setup(t *testing.T) *fixture {
	return setupIDs(t, storage.Hash([]byte("source")), storage.Hash([]byte("ingress")))
}
func setupIDs(t *testing.T, sourceID, ingressID string) *fixture {
	t.Helper()
	f := &fixture{base: teststore.Root(t)}
	var e error
	f.owner, e = filekit.NewOwner()
	must(t, e)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.control = key
	writer, wkey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.writer = wkey
	maint, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	now := time.Now().Unix()
	trust := generation.Trust{Domain: f.owner.Domain, Repository: storage.Hash([]byte("repo")), Epoch: 1, Writer: writer, Maintenance: maint}
	f.authority = Authority{Format: AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: sourceID, Ingress: ingressID, Revision: 1, NotBefore: now - 10, ExpiresUnix: now + 3600, Trust: trust, MaxBytes: 32 << 20, MaxObjects: 64}
	araw, e := SignAuthority(f.authority, key)
	must(t, e)
	f.intent = Intent{Format: IntentFormat, Operation: storage.Hash([]byte("capture1")), Authority: storage.Hash(araw), Tenant: f.authority.Tenant, Profile: f.authority.Profile, Source: f.authority.Source, Ingress: f.authority.Ingress, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: now, NotBefore: now - 5, ExpiresUnix: now + 600, MaxBytes: 32 << 20, MaxObjects: 64}
	iraw, e := SignIntent(f.intent, araw, pub, wkey, time.Now())
	must(t, e)
	dir := filepath.Join(f.base, "replica")
	must(t, os.Mkdir(dir, 0700))
	r, e := generation.Open(dir, trust, true)
	must(t, e)
	t.Cleanup(func() { r.Close() })
	f.options = SessionOptions{Directory: filepath.Join(f.base, "session"), Authority: araw, Intent: iraw, Owner: pub, Replica: r, Initialize: true}
	f.session, e = OpenSession(context.Background(), f.options)
	must(t, e)
	t.Cleanup(func() {
		if f.session != nil {
			f.session.Close()
		}
	})
	f.source, e = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, true, f.session)
	must(t, e)
	t.Cleanup(func() {
		if f.source != nil {
			f.source.Close()
		}
	})
	f.payload = make([]byte, 2<<20)
	_, e = rand.Read(f.payload)
	must(t, e)
	f.input = filepath.Join(f.base, "input")
	must(t, os.WriteFile(f.input, f.payload, 0600))
	return f
}
func (f *fixture) catalog(t *testing.T, versions []string) ([]byte, map[string][]byte) {
	t.Helper()
	i := f.intent
	raw, roots, e := generation.BuildCatalog(context.Background(), f.source, versions, generation.Catalog{Format: generation.Format, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Sequence: i.Sequence, Parent: i.Parent, Policy: i.Policy, SnapshotUnix: i.SnapshotUnix}, f.writer)
	must(t, e)
	return raw, roots
}
func (f *fixture) roots(t *testing.T, roots map[string][]byte) {
	t.Helper()
	for id, b := range roots {
		_, e := f.session.Write(context.Background(), filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
}
func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil
	f.options.Initialize = false
	var e error
	f.session, e = OpenSession(context.Background(), f.options)
	must(t, e)
	f.source, e = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, f.session)
	must(t, e)
}

func TestSessionPublishesOnlyCompleteClosureAndRetriesLostReceipt(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	v, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{v.Version})
	if _, e = f.session.Finish(ctx, raw); !errors.Is(e, ErrIncomplete) {
		t.Fatal("missing roots accepted", e)
	}
	status, e := f.options.Replica.Status(ctx)
	must(t, e)
	if status.LatestComplete != "" {
		t.Fatal("premature complete")
	}
	f.roots(t, roots)
	f.session.Fault = func(stage string) error {
		if stage == "capture-replica-complete" {
			return errors.New("lost receipt")
		}
		return nil
	}
	if _, e = f.session.Finish(ctx, raw); e == nil {
		t.Fatal("fault absent")
	}
	f.reopen(t)
	receipt, e := f.session.Finish(ctx, raw)
	must(t, e)
	if receipt.Generation != storage.Hash(raw) || receipt.Operation != f.intent.Operation || receipt.NewBytes < int64(len(f.payload)) {
		t.Fatal("invalid receipt", receipt)
	}
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil
	must(t, os.RemoveAll(filepath.Join(f.base, "source-cache")))
	must(t, os.RemoveAll(filepath.Join(f.base, "session")))
	must(t, os.Remove(f.input))
	f.owner.SigningKey = nil
	out := filepath.Join(f.base, "restore")
	result, e := generation.RecoverMaterialized(ctx, filepath.Join(f.base, "replica"), receipt.Generation, f.authority.Trust, f.owner, generation.RecoverySelection{}, out)
	must(t, e)
	if result.Restored.Bytes != int64(len(f.payload)) {
		t.Fatal("restore incomplete")
	}
	body, e := os.ReadFile(filepath.Join(out, "private/data"))
	must(t, e)
	if !bytes.Equal(body, f.payload) {
		t.Fatal("bytes differ")
	}
}
func TestSessionReopenInventoriesDurableObjectsAndRefusesSecondProcessLease(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	body := []byte("ciphertext fixture")
	ref := filekit.Object{ID: storage.Hash(body), Bytes: len(body)}
	f.session.Fault = func(stage string) error {
		if stage == "capture-object-durable" {
			return errors.New("lost acknowledgement")
		}
		return nil
	}
	if _, e := f.session.Write(ctx, ref, body); e == nil {
		t.Fatal("fault absent")
	}
	options := f.options
	options.Initialize = false
	if duplicate, e := OpenSession(ctx, options); !errors.Is(e, ErrConflict) {
		if duplicate != nil {
			duplicate.Close()
		}
		t.Fatal("second session lease accepted", e)
	}
	f.reopen(t)
	created, e := f.session.Write(ctx, ref, body)
	must(t, e)
	if created || len(f.session.refs) != 1 || f.session.bytes != int64(len(body)) {
		t.Fatal("duplicate was rewritten or recounted")
	}
	read, e := f.session.Read(ctx, ref)
	must(t, e)
	if !bytes.Equal(read, body) {
		t.Fatal("accepted object lost")
	}
	if _, e = f.session.Read(ctx, filekit.Object{ID: storage.Hash([]byte("unknown")), Bytes: 1}); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("unscoped object served", e)
	}
	if _, e = f.session.Write(ctx, ref, []byte("conflicting bytes")); !errors.Is(e, ErrDenied) {
		t.Fatal("conflicting immutable object accepted", e)
	}
}
func TestSessionQuotaCorruptionAndClockRollbackDoNotPublish(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	v, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"file"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{v.Version})
	f.roots(t, roots)
	f.session.objects.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	b := []byte("blocked object")
	if _, e = f.session.Write(ctx, filekit.Object{ID: storage.Hash(b), Bytes: len(b)}, b); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("quota ignored", e)
	}
	f.session.objects.Admit = nil
	_, d, e := f.source.LoadVersion(v.Version)
	must(t, e)
	ref := d.Blocks[0].Object
	path := filepath.Join(f.base, "session/objects", ref.ID)
	original, e := os.ReadFile(path)
	must(t, e)
	damaged := bytes.Clone(original)
	damaged[0] ^= 1
	must(t, os.WriteFile(path, damaged, 0600))
	if _, e = f.session.Finish(ctx, raw); e == nil {
		t.Fatal("corruption published")
	}
	status, e := f.options.Replica.Status(ctx)
	must(t, e)
	if status.LatestComplete != "" {
		t.Fatal("bad complete marker")
	}
	f.session.state.LastObserved = time.Now().Unix() + 60
	must(t, f.session.save())
	if e = f.session.Check(ctx, ref); !errors.Is(e, ErrDenied) {
		t.Fatal("clock rollback accepted", e)
	}
}
func TestIntentCannotExpandOwnerScopeOrReuseAuthorityKeys(t *testing.T) {
	f := setup(t)
	pub := f.control.Public().(ed25519.PublicKey)
	now := time.Now()
	for _, change := range []func(*Intent){func(i *Intent) { i.Ingress = storage.Hash([]byte("other")) }, func(i *Intent) { i.Tenant = storage.Hash([]byte("other")) }, func(i *Intent) { i.Profile = storage.Hash([]byte("other")) }, func(i *Intent) { i.MaxBytes++ }, func(i *Intent) { i.ExpiresUnix = f.authority.ExpiresUnix + 1 }, func(i *Intent) { i.Policy++ }, func(i *Intent) { i.Epoch++ }} {
		i := f.intent
		change(&i)
		if _, e := SignIntent(i, f.options.Authority, pub, f.writer, now); !errors.Is(e, ErrDenied) {
			t.Fatal("writer expanded owner scope", e)
		}
	}
	a := f.authority
	a.Source = keyID(a.Trust.Writer)
	if _, e := SignAuthority(a, f.control); !errors.Is(e, ErrDenied) {
		t.Fatal("node and writer share key", e)
	}
	var raw map[string]any
	must(t, json.Unmarshal(f.options.Intent, &raw))
	raw["unknown"] = true
	b, e := json.Marshal(raw)
	must(t, e)
	if _, _, e = VerifyIntent(b, f.options.Authority, pub, now); !errors.Is(e, ErrDenied) {
		t.Fatal("unknown field accepted", e)
	}
	if _, _, e = VerifyIntent(f.options.Intent, f.options.Authority, pub, time.Unix(f.intent.ExpiresUnix, 0)); !errors.Is(e, ErrDenied) {
		t.Fatal("expired intent accepted", e)
	}
}

func TestDeltaSessionReusesPinnedBaseAndReopensUsingItsOwnCompleteGeneration(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.payload = make([]byte, 12<<20)
	_, e := rand.Read(f.payload)
	must(t, e)
	must(t, os.WriteFile(f.input, f.payload, 0600))
	first, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"data"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{first.Version})
	f.roots(t, roots)
	r1, e := f.session.Finish(ctx, raw)
	must(t, e)
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil
	f.intent.Operation = storage.Hash([]byte("capture2"))
	f.intent.Sequence = 2
	f.intent.Parent = r1.Generation
	f.intent.SnapshotUnix++
	f.options.Intent, e = SignIntent(f.intent, f.options.Authority, f.options.Owner, f.writer, time.Now())
	must(t, e)
	f.options.Directory = filepath.Join(f.base, "session2")
	f.options.Initialize = true
	f.session, e = OpenSession(ctx, f.options)
	must(t, e)
	f.source, e = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, f.session)
	must(t, e)
	changed := bytes.Clone(f.payload)
	for j := 0; j < 4096; j++ {
		changed[(6<<20)+j] ^= 0x55
	}
	must(t, os.WriteFile(f.input, changed, 0600))
	second, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{File: first.File, Previous: first.Version, Names: []string{"data"}})
	must(t, e)
	if second.NewPayloadBytes <= 0 || second.NewPayloadBytes >= first.NewPayloadBytes {
		t.Fatal("unchanged payload retransmitted", first.NewPayloadBytes, second.NewPayloadBytes)
	}
	raw, roots = f.catalog(t, []string{second.Version})
	f.roots(t, roots)
	r2, e := f.session.Finish(ctx, raw)
	must(t, e)
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil
	f.options.Initialize = false
	f.session, e = OpenSession(ctx, f.options)
	must(t, e)
	if f.session.baseID != r2.Generation {
		t.Fatal("completed session still depends on old parent")
	}
	status, e := f.options.Replica.Status(ctx)
	must(t, e)
	if _, held := status.Pins[f.session.pin("base")]; held {
		t.Fatal("completed session repinned old parent")
	}
	f.owner.SigningKey = nil
	for n, item := range []struct {
		generation string
		body       []byte
	}{{r1.Generation, f.payload}, {r2.Generation, changed}} {
		out := filepath.Join(f.base, []string{"old", "new"}[n])
		_, e := generation.RecoverMaterialized(ctx, filepath.Join(f.base, "replica"), item.generation, f.authority.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		body, e := os.ReadFile(filepath.Join(out, "data"))
		must(t, e)
		if !bytes.Equal(body, item.body) {
			t.Fatal("retained version differs")
		}
	}
}

func TestSessionFinalizationUsesBoundedDurableBatches(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	stats, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"file"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{stats.Version})
	f.roots(t, roots)
	first, receipt, e := f.session.FinishBatch(ctx, raw, 1, generation.MaxObject)
	must(t, e)
	if first.Complete || first.VerifiedObjects != 1 || receipt.Generation != "" {
		t.Fatal("premature receipt", first, receipt)
	}
	f.reopen(t)
	var final Receipt
	for n := 0; n < 10; n++ {
		batch, r, e := f.session.FinishBatch(ctx, raw, 1, generation.MaxObject)
		must(t, e)
		if batch.Complete {
			final = r
			break
		}
	}
	if final.Generation != storage.Hash(raw) || final.VerifiedAt < 1 {
		t.Fatal("missing bounded completion receipt", final)
	}
}

func TestLostReceiptPreservesActualVerificationTime(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	stats, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"file"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{stats.Version})
	f.roots(t, roots)
	f.session.Fault = func(point string) error {
		if point == "capture-replica-complete" {
			return errors.New("receipt lost")
		}
		return nil
	}
	first, _, e := f.session.FinishBatch(ctx, raw, 256, 256<<20)
	if e == nil || !first.Complete || first.VerifiedAt < 1 {
		t.Fatal("lost-receipt boundary absent", first, e)
	}
	f.reopen(t)
	time.Sleep(1100 * time.Millisecond)
	second, receipt, e := f.session.FinishBatch(ctx, raw, 256, 256<<20)
	must(t, e)
	if receipt.VerifiedAt != first.VerifiedAt || second.VerifiedAt != first.VerifiedAt || second.ReadBytes != 0 {
		t.Fatal("restart fabricated fresh verification", first, second, receipt)
	}
}
