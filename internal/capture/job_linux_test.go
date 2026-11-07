package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/source"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type provider struct {
	path, view, operation, checkpoint string
	trust                             generation.Trust
	released                          bool
	releases, opens                   int
	uncertain                         bool
}

func (p *provider) Open(ctx context.Context, view string) (*os.Root, error) {
	p.opens++
	if view != p.view || p.released {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return localfs.OpenRoot(p.path)
}
func (p *provider) Release(ctx context.Context, operation, view string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if operation != p.operation || view != p.view {
		return ErrInvalid
	}
	raw, e := os.ReadFile(p.checkpoint)
	if e != nil {
		return e
	}
	if _, e = VerifyCheckpoint(raw, p.trust); e != nil {
		return e
	}
	p.releases++
	if !p.released {
		if e = os.RemoveAll(p.path); e != nil {
			return e
		}
		p.released = true
	}
	if p.uncertain {
		p.uncertain = false
		return errors.New("lost local release reply")
	}
	return nil
}

type sink struct {
	*ingress.Session
	provider *provider
	acks     int
}

func (s *sink) Begin(ctx context.Context) error { return ctx.Err() }
func (s *sink) FinishStep(ctx context.Context, raw []byte) (generation.BatchResult, *ingress.Receipt, error) {
	progress, receipt, e := s.FinishBatch(ctx, raw, 2, 8<<20)
	if e != nil || !progress.Complete {
		return progress, nil, e
	}
	return progress, &receipt, nil
}
func (s *sink) AcknowledgeStep(ctx context.Context, receipt ingress.Receipt) (ingress.Acknowledgement, error) {
	if !s.provider.released {
		return ingress.Acknowledgement{}, ErrInvalid
	}
	s.acks++
	return s.Acknowledge(ctx, receipt, 2)
}

type fixture struct {
	base     string
	options  Options
	job      *Job
	provider *provider
	sink     *sink
	replica  *generation.Replica
	owner    filekit.Owner
	content  []byte
}

func setup(t *testing.T, minimum int) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{base: teststore.Root(t)}
	var e error
	f.owner, e = filekit.NewOwner()
	must(t, e)
	owner, ownerKey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	writer, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	maintenance, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	now := time.Now().Unix()
	trust := generation.Trust{Domain: f.owner.Domain, Repository: storage.Hash([]byte("repo")), Epoch: 1, Writer: writer, Maintenance: maintenance}
	a := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("tenant")), Profile: storage.Hash([]byte("profile")), Source: storage.Hash([]byte("source")), Ingress: storage.Hash([]byte("ingress")), Revision: 1, NotBefore: now - 10, ExpiresUnix: now + 3600, Trust: trust, MaxBytes: 32 << 20, MaxObjects: 128}
	authority, e := ingress.SignAuthority(a, ownerKey)
	must(t, e)
	intent := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash([]byte("operation")), Authority: storage.Hash(authority), Tenant: a.Tenant, Profile: a.Profile, Source: a.Source, Ingress: a.Ingress, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, Policy: 1, SnapshotUnix: now, NotBefore: now - 5, ExpiresUnix: now + 1800, MaxBytes: a.MaxBytes, MaxObjects: a.MaxObjects}
	raw, e := ingress.SignIntent(intent, authority, owner, key, time.Now())
	must(t, e)
	directory := filepath.Join(f.base, "replica")
	must(t, os.Mkdir(directory, 0700))
	f.replica, e = generation.Open(directory, trust, true)
	must(t, e)
	p := &provider{path: filepath.Join(f.base, "source"), view: storage.Hash([]byte("view")), operation: intent.Operation, checkpoint: filepath.Join(f.base, "job", "state", "checkpoint.json"), trust: trust}
	f.provider = p
	must(t, os.Mkdir(p.path, 0700))
	must(t, os.Mkdir(filepath.Join(p.path, "folder"), 0750))
	f.content = make([]byte, 256<<10)
	_, e = rand.Read(f.content)
	must(t, e)
	must(t, os.WriteFile(filepath.Join(p.path, "folder", "private.bin"), f.content, 0640))
	must(t, os.Symlink("folder/private.bin", filepath.Join(p.path, "link")))
	session, e := ingress.OpenSession(ctx, ingress.SessionOptions{Directory: filepath.Join(f.base, "ingress"), Authority: authority, Intent: raw, Owner: owner, Replica: f.replica, Initialize: true})
	must(t, e)
	f.sink = &sink{Session: session, provider: p}
	cache, e := filekit.OpenStreamingStore(filepath.Join(f.base, "cache"), f.owner, true, f.sink)
	must(t, e)
	profile := Profile{ID: a.Profile, Origin: storage.Hash([]byte("origin")), View: p.view, Consistency: "best-effort", Selection: source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: f.owner.Domain}}, Domains: map[string]bool{f.owner.Domain: true}, EntryLimit: 128}, MaxSourceBytes: 32 << 20, MinimumCopies: minimum, CopyTargets: []string{a.Ingress}}
	if minimum == 2 {
		profile.CopyTargets = append(profile.CopyTargets, storage.Hash([]byte("second")))
	}
	f.options = Options{Directory: filepath.Join(f.base, "job"), Initialize: true, Profile: profile, Authority: authority, Intent: raw, Owner: owner, Data: f.owner, Writer: key, Provider: p, Sink: f.sink, Cache: cache}
	if minimum == 2 {
		f.options.Copies = func(context.Context, string) ([]CopyReceipt, error) { return nil, nil }
	}
	f.job, e = Open(ctx, f.options)
	must(t, e)
	t.Cleanup(func() {
		if f.job != nil {
			f.job.Close()
		}
		cache.Close()
		f.sink.Close()
		f.replica.Close()
	})
	return f
}
func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	must(t, f.job.Close())
	f.job = nil
	o := f.options
	o.Initialize = false
	var e error
	f.job, e = Open(context.Background(), o)
	must(t, e)
}
func (f *fixture) restore(t *testing.T) {
	t.Helper()
	s, e := f.job.Status(context.Background())
	must(t, e)
	if s.Phase != "COMPLETE" {
		t.Fatal("not complete", s.Phase)
	}
	raw, e := os.ReadFile(f.provider.checkpoint)
	must(t, e)
	checkpoint, e := VerifyCheckpoint(raw, f.replica.Trust())
	must(t, e)
	if checkpoint.Generation != s.Generation || len(checkpoint.Copies) < f.options.Profile.MinimumCopies {
		t.Fatal("wrong checkpoint")
	}
	if bytes.Contains(raw, []byte("private.bin")) {
		t.Fatal("plaintext path in checkpoint")
	}
	destination := filepath.Join(f.base, "restored")
	_, e = generation.RecoverMaterialized(context.Background(), filepath.Join(f.base, "replica"), s.Generation, f.replica.Trust(), f.owner, generation.RecoverySelection{}, destination)
	must(t, e)
	data, e := os.ReadFile(filepath.Join(destination, "folder", "private.bin"))
	must(t, e)
	if !bytes.Equal(data, f.content) {
		t.Fatal("different restored bytes")
	}
	target, e := os.Readlink(filepath.Join(destination, "link"))
	must(t, e)
	if target != "folder/private.bin" {
		t.Fatal("wrong link")
	}
}
func TestSourceJobResumesAtEveryReleaseAndPublicationBoundary(t *testing.T) {
	for _, point := range []string{"source-file-durable", "source-catalog-durable", "source-receipt-durable", "source-checkpoint-durable", "source-release-intent-durable", "source-provider-released", "source-released-durable", "source-acknowledged"} {
		t.Run(point, func(t *testing.T) {
			f := setup(t, 1)
			interrupted := errors.New("injected interruption")
			f.job.Fault = func(name string) error {
				if name == point {
					return interrupted
				}
				return nil
			}
			if e := f.job.Run(context.Background()); !errors.Is(e, interrupted) {
				t.Fatal("missing boundary", point, e)
			}
			f.reopen(t)
			opens := f.provider.opens
			must(t, f.job.Run(context.Background()))
			if phasePoint := point; phasePoint != "source-file-durable" && f.provider.opens != opens {
				t.Fatal("reopened source after seal", point)
			}
			if f.provider.releases < 1 || f.sink.acks < 1 {
				t.Fatal("release/ack absent")
			}
			f.restore(t)
		})
	}
}
func TestSourceJobUncertainReleaseRetriesWithoutSourceOrEarlyAck(t *testing.T) {
	f := setup(t, 1)
	f.provider.uncertain = true
	if e := f.job.Run(context.Background()); e == nil {
		t.Fatal("lost release reply accepted")
	}
	s, e := f.job.Status(context.Background())
	must(t, e)
	if s.Phase != "RELEASING" || !f.provider.released || f.sink.acks != 0 {
		t.Fatal("wrong release boundary", s.Phase)
	}
	f.reopen(t)
	opens := f.provider.opens
	must(t, f.job.Run(context.Background()))
	if f.provider.opens != opens || f.provider.releases != 2 {
		t.Fatal("recaptured or failed to retry release")
	}
	f.restore(t)
}
func TestSourceJobWaitsForTwoActualCompleteCopies(t *testing.T) {
	f := setup(t, 2)
	ctx := context.Background()
	if e := f.job.Run(ctx); !errors.Is(e, ErrCopies) {
		t.Fatal("did not wait", e)
	}
	s, e := f.job.Status(ctx)
	must(t, e)
	if s.Phase != "WAITING_COPIES" || f.provider.releases != 0 || f.sink.acks != 0 {
		t.Fatal("released early")
	}
	dir := filepath.Join(f.base, "second")
	must(t, os.Mkdir(dir, 0700))
	second, e := generation.Open(dir, f.replica.Trust(), true)
	must(t, e)
	defer second.Close()
	raw, e := os.ReadFile(filepath.Join(f.base, "job", "state", "catalog.json"))
	must(t, e)
	id, e := second.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) { return f.replica.ReadObject(ctx, s.Generation, ref) })
	must(t, e)
	must(t, second.VerifyComplete(ctx, id))
	f.options.Copies = func(ctx context.Context, id string) ([]CopyReceipt, error) {
		if e := second.VerifyComplete(ctx, id); e != nil {
			return nil, e
		}
		return []CopyReceipt{{Target: f.options.Profile.CopyTargets[1], Generation: id, Verification: "ciphertext-readback", ObservedUnix: time.Now().Unix()}}, nil
	}
	f.reopen(t)
	opens := f.provider.opens
	must(t, f.job.Run(ctx))
	if f.provider.opens != opens {
		t.Fatal("reread source while waiting copies")
	}
	f.restore(t)
}
func TestSourceJobRefusesChangedViewAndCorruptCheckpointBeforeRelease(t *testing.T) {
	t.Run("changed source", func(t *testing.T) {
		f := setup(t, 1)
		must(t, os.WriteFile(filepath.Join(f.provider.path, "new"), []byte("change"), 0600))
		if e := f.job.Run(context.Background()); !errors.Is(e, source.ErrChanged) {
			t.Fatal("changed plan accepted", e)
		}
		if f.provider.releases != 0 || f.sink.acks != 0 {
			t.Fatal("released incomplete source")
		}
	})
	t.Run("corrupt checkpoint", func(t *testing.T) {
		f := setup(t, 1)
		stop := errors.New("stop")
		f.job.Fault = func(name string) error {
			if name == "source-checkpoint-durable" {
				return stop
			}
			return nil
		}
		if e := f.job.Run(context.Background()); !errors.Is(e, stop) {
			t.Fatal(e)
		}
		raw, e := os.ReadFile(f.provider.checkpoint)
		must(t, e)
		var c Checkpoint
		must(t, json.Unmarshal(raw, &c))
		c.Sequence++
		raw, e = json.Marshal(c)
		must(t, e)
		must(t, os.WriteFile(f.provider.checkpoint, raw, 0600))
		must(t, f.job.Close())
		f.job = nil
		o := f.options
		o.Initialize = false
		if j, e := Open(context.Background(), o); e == nil {
			j.Close()
			t.Fatal("corrupt checkpoint accepted")
		}
		if f.provider.releases != 0 || f.sink.acks != 0 {
			t.Fatal("released with corrupt checkpoint")
		}
	})
}
