// Package sourceagent composes the private source provider, encrypted capture,
// authenticated ingress and volume admission into one restartable executable.
package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

const Format = "outpost-source-agent-1"
const maxState = 2 << 20

var ErrInvalid = errors.New("source agent configuration or state invalid")
var ErrUnsupported = errors.New("source profile requires an unavailable capability")

// Bootstrap is private local configuration. Shared control documents cannot
// select source paths, keys or installed provider implementations.
type Bootstrap struct {
	Format          string              `json:"format"`
	Local           worker.Bootstrap    `json:"local"`
	Profile         capture.Profile     `json:"profile"`
	Tree            capture.TreeBinding `json:"tree"`
	DataKeyFile     string              `json:"dataKeyFile"`
	WriterKeyFile   string              `json:"writerKeyFile"`
	AuthorityFile   string              `json:"authorityFile"`
	ObservationFile string              `json:"observationFile,omitempty"`
	Endpoint        string              `json:"endpoint"`
	Limits          diskbudget.Limits   `json:"limits"`
	Prepared        *PreparedSource     `json:"prepared,omitempty"`
	Companion       *CompanionIngress   `json:"companionIngress,omitempty"`
}

func Load(path string) (Bootstrap, error) {
	var b Bootstrap
	raw, e := worker.ReadPrivate(path, 65536)
	if e != nil {
		return b, e
	}
	if worker.DecodeInput(raw, &b, 65536) != nil {
		return b, ErrInvalid
	}
	return b, nil
}

type state struct {
	Format                   string            `json:"format"`
	Binding                  string            `json:"binding"`
	Phase                    string            `json:"phase"`
	ObservedUnix             int64             `json:"observedUnix"`
	Sequence                 uint64            `json:"sequence"`
	Generation               string            `json:"generation,omitempty"`
	Intent                   []byte            `json:"intent,omitempty"`
	Previous                 map[string]string `json:"previous"`
	Checkpoint               []byte            `json:"checkpoint,omitempty"`
	Signature                []byte            `json:"signature,omitempty"`
	Authority                []byte            `json:"authority,omitempty"`
	Observation              []byte            `json:"observation,omitempty"`
	IntentAuthority          []byte            `json:"intentAuthority,omitempty"`
	CompanionAuthority       []byte            `json:"companionAuthority,omitempty"`
	IntentCompanionAuthority []byte            `json:"intentCompanionAuthority,omitempty"`
	LegacyDigest             string            `json:"legacyDigest,omitempty"`
	Retirement               string            `json:"retirement,omitempty"`
}

type Status struct {
	Format            string          `json:"format"`
	Profile           string          `json:"profile"`
	Phase             string          `json:"phase"`
	Operation         string          `json:"operation,omitempty"`
	Sequence          uint64          `json:"sequence"`
	Generation        string          `json:"generation,omitempty"`
	Job               *capture.State  `json:"job,omitempty"`
	AuthorityRevision uint64          `json:"authorityRevision,omitempty"`
	Prepared          *PreparedStatus `json:"prepared,omitempty"`
	Pending           *PendingStatus  `json:"pending,omitempty"`
}

// PendingStatus describes the local intent fence and the applicable recovery path.
type PendingStatus struct {
	IntentExpiresUnix int64  `json:"intentExpiresUnix"`
	Action            string `json:"action"`
}

type Agent struct {
	b                  Bootstrap
	runtimeDirectory   string
	root               *os.Root
	budget             *diskbudget.Budget
	store, lease       *statefile.Store
	owner              filekit.Owner
	writer             ed25519.PrivateKey
	authority          []byte
	observation        []byte
	initialObservation []byte
	grant              ingress.Authority
	companion          ingress.Authority
	companionAuthority []byte
	anchor             ingress.Authority
	cert               tls.Certificate
	roots              *x509.CertPool
	binding            string
	poisoned           atomic.Bool
	// Fault is only a local test hook, never remote configuration.
	Fault func(string) error
}

func Open(ctx context.Context, b Bootstrap, initialize bool) (*Agent, error) {
	return open(ctx, b, initialize, false)
}

func open(ctx context.Context, b Bootstrap, initialize, scheduleOnly bool) (*Agent, error) {
	if initialize {
		return initializeAgent(ctx, b, nil)
	}
	return openAt(ctx, b, false, scheduleOnly, b.Local.Directory, nil)
}

func openAt(ctx context.Context, b Bootstrap, initialize, scheduleOnly bool, directory string, fault func(string) error) (*Agent, error) {
	if (b.Format != Format && b.Format != PreparedAgentFormat) || b.Local.Format != worker.BootstrapFormat || b.Local.Volume.Scope != b.Local.Node || len(b.Local.Owner) != 32 || b.Local.ControlEndpoint != "" || b.Local.Listen != "" || len(b.Local.Credentials) != 0 || b.Profile.View != "" || b.Profile.Origin != b.Tree.Origin {
		return nil, ErrInvalid
	}
	// Never downgrade requested consistency or an unconfigured copy policy.
	bestEffort := b.Format == Format && b.Prepared == nil && b.Profile.Consistency == "best-effort"
	if (!bestEffort && !preparedBootstrap(b)) || b.Profile.MinimumCopies < 1 || b.Profile.MinimumCopies > 2 || b.Profile.MinimumCopies == 2 && b.ObservationFile == "" {
		return nil, ErrUnsupported
	}
	if b.Profile.ReleasePolicy != "" && (b.Profile.ReleasePolicy != capture.TwoHolderCoverage || b.Companion == nil) {
		return nil, ErrUnsupported
	}
	if b.Prepared != nil {
		p := *b.Prepared
		p.Trust.Producer = bytes.Clone(p.Trust.Producer)
		b.Prepared = &p
	}
	a := &Agent{b: b, runtimeDirectory: directory, Fault: fault}
	var e error
	a.authority, e = worker.ReadPrivate(b.AuthorityFile, ingress.MaxDocument)
	if e != nil {
		return nil, e
	}
	a.grant, e = ingress.VerifyAuthorityDocument(a.authority, b.Local.Owner)
	if e != nil {
		return nil, e
	}
	if a.grant.Source != b.Local.Node || a.grant.Profile != b.Profile.ID {
		return nil, ErrInvalid
	}
	a.anchor = a.grant
	if e = a.loadCompanion(); e != nil {
		return nil, e
	}
	if b.ObservationFile != "" {
		if b.Profile.MinimumCopies != 2 {
			return nil, ErrInvalid
		}
		a.observation, e = worker.ReadPrivate(b.ObservationFile, observation.MaxDocument)
		if e != nil {
			return nil, e
		}
		g, e := observation.VerifyGrant(a.observation, b.Local.Owner)
		if e != nil || g.Reader != b.Local.Node || g.Collector != a.grant.Ingress || !observation.SameTrust(g.Trust, a.grant.Trust) || g.Target(g.Collector) {
			return nil, ErrInvalid
		}
		if b.Companion != nil && !g.Target(a.companion.Ingress) {
			return nil, ErrInvalid
		}
		for _, target := range g.Targets {
			found := false
			for _, id := range b.Profile.CopyTargets {
				if id == target {
					found = true
				}
			}
			if !found {
				return nil, ErrInvalid
			}
		}
	}
	a.owner, e = filekit.ReadOwner(b.DataKeyFile)
	if e != nil {
		return nil, e
	}
	if a.owner.Domain != a.grant.Trust.Domain || len(a.owner.SigningKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	raw, e := worker.ReadPrivate(b.WriterKeyFile, 4096)
	if e != nil {
		return nil, e
	}
	var key struct {
		PrivateKey ed25519.PrivateKey `json:"privateKey"`
	}
	if worker.DecodeInput(raw, &key, 4096) != nil || len(key.PrivateKey) != ed25519.PrivateKeySize || !bytes.Equal(key.PrivateKey.Public().(ed25519.PublicKey), a.grant.Trust.Writer) {
		return nil, ErrInvalid
	}
	a.writer = key.PrivateKey
	a.cert, a.roots, e = b.Local.TLS()
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(a.cert.Certificate[0])
	if e != nil || peer.Identity(leaf) != b.Local.Node {
		return nil, ErrInvalid
	}
	a.initialObservation = bytes.Clone(a.observation)
	identity, _ := json.Marshal(struct {
		Bootstrap          Bootstrap
		Authority          []byte
		Observation        []byte `json:",omitempty"`
		Data               filekit.Owner
		CompanionAuthority []byte `json:",omitempty"`
	}{b, a.authority, a.observation, a.owner, a.companionAuthority})
	a.binding = storage.Hash(identity)
	if initialize {
		// The parent must already exist. Checking it by held identities rejects
		// runtime creation anywhere inside the source, even through an alias.
		source, e := localfs.OpenRoot(b.Tree.Path)
		if e != nil {
			return nil, e
		}
		parent, e := localfs.OpenRoot(filepath.Dir(b.Local.Directory))
		if e != nil {
			source.Close()
			return nil, e
		}
		contains, e := localfs.Contains(ctx, source, parent)
		parent.Close()
		if e == nil && !contains && b.Prepared != nil {
			raw, err := worker.ReadPrivate(b.Prepared.ManifestFile, capture.MaxPreparedExport)
			if err == nil {
				var view *os.Root
				view, _, err = capture.OpenPreparedExport(ctx, source, raw, b.Prepared.Trust, time.Now())
				if view != nil {
					view.Close()
				}
			}
			e = err
		}
		source.Close()
		if e != nil {
			return nil, e
		}
		if contains {
			return nil, ErrInvalid
		}
	}
	a.root, e = b.Local.Volume.Open(ctx, directory, initialize)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Agent, error) { a.Close(); return nil, e }
	if initialize {
		if e = a.point("source-install-directory-created"); e != nil {
			return fail(e)
		}
	}
	a.lease, e = statefile.OpenAt(a.root, "lease", 4096, initialize)
	if e != nil {
		return fail(e)
	}
	a.budget, e = diskbudget.OpenAt(a.root, ctx, ".", b.Limits, initialize)
	if e != nil {
		return fail(e)
	}
	a.store, e = statefile.OpenAt(a.root, "state", maxState, initialize)
	if e != nil {
		return fail(e)
	}
	a.store.Admit = a.admission("state")
	if initialize {
		if e = a.point("source-install-stores-created"); e != nil {
			return fail(e)
		}
	}
	if scheduleOnly {
		// Atomic signed state can be inspected without the long capture lease.
		// Reconciliation is reserved for the normal execution open path.
		e = a.store.WithLock(ctx, func() error {
			if e := a.guard(ctx); e != nil {
				return e
			}
			_, e := a.loadAdopt()
			return e
		})
		if e != nil {
			return fail(e)
		}
		return a, nil
	}
	e = a.lease.WithLock(ctx, func() error {
		if initialize {
			if _, e := a.store.Read("agent.json"); !errors.Is(e, os.ErrNotExist) {
				return ErrInvalid
			}
			return a.save(state{Format: Format, Binding: a.binding, Phase: "IDLE", Previous: map[string]string{}})
		}
		if _, e := a.loadAdopt(); e != nil {
			return e
		}
		return a.budget.Reconcile(ctx, b.Limits)
	})
	if e != nil {
		return fail(e)
	}
	return a, nil
}

func (a *Agent) Close() error {
	var e error
	for _, s := range []*statefile.Store{a.store, a.lease} {
		if s != nil {
			e = errors.Join(e, s.Close())
		}
	}
	if a.budget != nil {
		e = errors.Join(e, a.budget.Close())
	}
	if a.root != nil {
		e = errors.Join(e, a.root.Close())
	}
	return e
}
func (a *Agent) guard(ctx context.Context) error {
	if a.poisoned.Load() {
		return ErrInvalid
	}
	return a.b.Local.Volume.CheckHandle(ctx, a.runtimeDirectory, a.root)
}
func (a *Agent) point(name string) error {
	if a.Fault != nil {
		return a.Fault(name)
	}
	return nil
}
func (a *Agent) admission(prefix string) statefile.Admission {
	return func(name string, size int) (func(bool) error, error) {
		if e := a.guard(context.Background()); e != nil {
			return nil, e
		}
		finish, e := a.budget.Admission(prefix)(name, size)
		if e != nil {
			return nil, e
		}
		return func(done bool) error { return errors.Join(finish(done), a.guard(context.Background())) }, nil
	}
}
func (a *Agent) save(s state) error {
	if time.Now().Unix() < s.ObservedUnix {
		return ErrInvalid
	}
	s.ObservedUnix = time.Now().Unix()
	s.Signature = nil
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	s.Signature = ed25519.Sign(a.writer, append([]byte(s.Format+"\x00"), raw...))
	raw, e = json.Marshal(s)
	if e != nil {
		return e
	}
	if e = a.store.Write("agent.json", raw); e != nil {
		a.poisoned.Store(true)
	}
	return e
}
func (a *Agent) load() (state, error) {
	return a.loadScope(false)
}
func (a *Agent) loadAdopt() (state, error) { return a.loadScope(true) }
func (a *Agent) loadScope(adopt bool) (state, error) {
	var s state
	raw, e := a.store.Read("agent.json")
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, maxState) != nil || (s.Format != Format && s.Format != renewedFormat) || s.Binding != a.binding || s.ObservedUnix < 1 || s.ObservedUnix > time.Now().Unix() || s.Previous == nil || len(s.Previous) > generation.MaxKits {
		return s, ErrInvalid
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(raw, canonical) {
		return s, ErrInvalid
	}
	signature := s.Signature
	s.Signature = nil
	payload, _ := json.Marshal(s)
	s.Signature = signature
	if !ed25519.Verify(a.anchor.Trust.Writer, append([]byte(s.Format+"\x00"), payload...), signature) {
		return s, ErrInvalid
	}
	current, e := a.stateScope(s, adopt)
	if e != nil {
		return s, e
	}
	for f, v := range s.Previous {
		if !storage.ID(f) || !storage.ID(v) {
			return s, ErrInvalid
		}
	}
	if s.Phase != "IDLE" && s.Phase != "PREPARING" && s.Phase != "ACTIVE" && s.Phase != "COMPLETE" && s.Phase != "ABANDONED" ||
		s.Phase != "ABANDONED" && s.Retirement != "" {
		return s, ErrInvalid
	}
	if s.Sequence == 0 && (s.Generation != "" || len(s.Previous) != 0 || len(s.Checkpoint) != 0) || s.Sequence > 0 && !storage.ID(s.Generation) {
		return s, ErrInvalid
	}
	if s.Sequence > 0 {
		c, e := capture.VerifyCheckpoint(s.Checkpoint, a.grant.Trust)
		if e != nil || c.Sequence != s.Sequence || c.Generation != s.Generation || c.Profile != a.b.Profile.ID {
			return s, ErrInvalid
		}
	}
	if s.Phase != "IDLE" {
		i, e := a.stateIntent(s)
		if e != nil {
			return s, e
		}
		if s.Phase == "COMPLETE" {
			if i.Sequence != s.Sequence {
				return s, ErrInvalid
			}
		} else if i.Sequence != s.Sequence+1 || i.Parent != s.Generation {
			return s, ErrInvalid
		}
		if s.Phase == "ABANDONED" {
			record, err := a.readUnstartedArchive(s, i, s.Retirement)
			if err != nil || record.RecordedUnix > s.ObservedUnix {
				return s, ErrInvalid
			}
		}
	} else if len(s.Intent) != 0 || s.Sequence != 0 {
		return s, ErrInvalid
	}
	if adopt && s.Format == renewedFormat {
		a.authority = bytes.Clone(s.Authority)
		a.companionAuthority = bytes.Clone(s.CompanionAuthority)
		a.observation = bytes.Clone(s.Observation)
		a.grant = current
	}
	return s, nil
}
func (a *Agent) intent(raw []byte, current bool) (ingress.Intent, error) {
	var i ingress.Intent
	if storage.Decode(raw, &i, ingress.MaxDocument) != nil {
		return i, ErrInvalid
	}
	now := time.Now()
	if !current {
		now = time.Unix(i.NotBefore, 0)
	}
	i, _, e := ingress.VerifyIntent(raw, a.authority, a.b.Local.Owner, now)
	return i, e
}

// Prepare fences the exact signed operation before creating any provider/job
// state. A crash may resume only that intent; a different intent is refused.
func (a *Agent) Prepare(ctx context.Context, raw []byte) error {
	return a.lease.WithLock(ctx, func() error { return a.prepare(ctx, raw) })
}

// Next signs a fresh operation from the durable head. Repeated requests while
// one operation is pending resume it, rather than creating another generation.
func (a *Agent) Next(ctx context.Context) error {
	return a.lease.WithLock(ctx, func() error { return a.next(ctx) })
}
func (a *Agent) next(ctx context.Context) error {
	if e := a.guard(ctx); e != nil {
		return e
	}
	s, e := a.load()
	if e != nil {
		return e
	}
	if s.Phase == "ACTIVE" || s.Phase == "PREPARING" {
		return a.prepare(ctx, s.Intent)
	}
	if s.Sequence == ^uint64(0) {
		return ErrInvalid
	}
	var prepared capture.PreparedExport
	var manifest []byte
	if a.b.Prepared != nil {
		prepared, manifest, e = a.selectPrepared(ctx, s)
		if e != nil {
			return e
		}
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return e
	}
	now := time.Now().Unix()
	g := a.grant
	i := ingress.Intent{Format: ingress.IntentFormat, Operation: storage.Hash(nonce[:]), Authority: storage.Hash(a.authority), Tenant: g.Tenant, Profile: g.Profile, Source: g.Source, Ingress: g.Ingress, Domain: g.Trust.Domain, Repository: g.Trust.Repository, Epoch: g.Trust.Epoch, Sequence: s.Sequence + 1, Parent: s.Generation, Policy: g.Revision, SnapshotUnix: now, NotBefore: now, ExpiresUnix: g.ExpiresUnix, MaxBytes: g.MaxBytes, MaxObjects: g.MaxObjects}
	if manifest != nil {
		i.Operation = storage.Hash(manifest)
		i.SnapshotUnix = prepared.SnapshotUnix
	}
	raw, e := ingress.SignIntent(i, a.authority, a.b.Local.Owner, a.writer, time.Now())
	if e != nil {
		return e
	}
	if manifest != nil {
		if e = a.freezePrepared(ctx, manifest, raw); e != nil {
			return e
		}
	}
	return a.prepare(ctx, raw)
}
func (a *Agent) prepare(ctx context.Context, raw []byte) error {
	if e := a.guard(ctx); e != nil {
		return e
	}
	s, e := a.load()
	if e != nil {
		return e
	}
	if s.Phase == "PREPARING" || s.Phase == "ACTIVE" {
		if !bytes.Equal(s.Intent, raw) {
			return ingress.ErrConflict
		}
	} else {
		i, e := a.intent(raw, true)
		if e != nil {
			return e
		}
		if s.Sequence == ^uint64(0) || i.Sequence != s.Sequence+1 || i.Parent != s.Generation {
			return ingress.ErrConflict
		}
		if a.b.Prepared != nil {
			m, _, e := a.readPrepared(ctx, i.Operation)
			if e != nil {
				return e
			}
			if m.SnapshotUnix != i.SnapshotUnix {
				return ErrInvalid
			}
			if e = a.checkPreparedAdvance(ctx, s, m, i.Operation); e != nil {
				return e
			}
		}
		s.Phase, s.Intent = "PREPARING", bytes.Clone(raw)
		s.Retirement = ""
		if s.Format == renewedFormat {
			s.IntentAuthority = bytes.Clone(a.authority)
			s.IntentCompanionAuthority = bytes.Clone(a.companionAuthority)
		}
		if e = a.save(s); e != nil {
			return e
		}
		if e = a.point("source-agent-intent-durable"); e != nil {
			return e
		}
	}
	job, close, e := a.openJob(ctx, s)
	if e != nil {
		return e
	}
	defer close()
	if _, e = job.Status(ctx); e != nil {
		return e
	}
	// Preparing the local job does not contact the receiver. Leave the intent
	// eligible for unstarted retirement until the execution fence is durable.
	return nil
}

func (a *Agent) openJob(ctx context.Context, s state) (*capture.Job, func(), error) {
	return a.openJobMode(ctx, s, false, nil)
}
func (a *Agent) openJobMode(ctx context.Context, s state, inspect bool, settlement []byte) (*capture.Job, func(), error) {
	if s.Phase == "PREPARING" && (inspect || len(settlement) != 0) {
		return nil, nil, ErrInvalid
	}
	i, e := a.stateIntent(s)
	if e != nil {
		return nil, nil, e
	}
	limits := peer.Limits{Concurrency: 1, Timeout: 30 * time.Second, Attempts: 1}
	authority := a.intentAuthority(s)
	var client *ingress.Client
	cleanup := inspect || len(settlement) != 0
	if len(settlement) != 0 {
		client, e = ingress.NewSettlementClient(a.b.Endpoint, authority, s.Intent, settlement, a.b.Local.Owner, a.cert, a.roots, limits)
	} else if inspect {
		client, e = ingress.NewCleanupClient(a.b.Endpoint, authority, s.Intent, a.b.Local.Owner, a.cert, a.roots, limits)
	} else {
		client, e = ingress.NewClient(a.b.Endpoint, authority, s.Intent, a.b.Local.Owner, a.cert, a.roots, limits)
		if e != nil && s.Phase != "PREPARING" {
			client, e = ingress.NewCleanupClient(a.b.Endpoint, authority, s.Intent, a.b.Local.Owner, a.cert, a.roots, limits)
			cleanup = true
		}
	}
	if e != nil {
		return nil, nil, e
	}
	initialize := s.Phase == "PREPARING"
	prefix := path.Join("operations", i.Operation)
	provider, e := a.openProvider(ctx, prefix, i, initialize)
	if e != nil {
		client.Close()
		return nil, nil, e
	}
	var sink capture.Sink = client
	closeSink := client.Close
	if a.b.Companion != nil {
		companionAuthority := a.companionAuthority
		if s.Format == renewedFormat {
			companionAuthority = s.IntentCompanionAuthority
		}
		group, err := a.openParallelSink(i, prefix, companionAuthority, client, limits, initialize, cleanup)
		if err != nil {
			provider.Close()
			client.Close()
			return nil, nil, err
		}
		sink, closeSink = group, group.Close
	}
	cache, e := filekit.OpenStreamingStoreAt(a.root, "cache", a.owner, initialize, sink)
	if e != nil {
		provider.Close()
		closeSink()
		return nil, nil, e
	}
	cache.Admit = a.admission("cache")
	p := a.b.Profile
	p.View = i.Operation
	previous := s.Previous
	// COMPLETE has advanced the current lineage. The finished job remains bound
	// to its original predecessor map in its signed per-operation input.
	inputs, e := statefile.OpenAt(a.root, prefix+"/input", maxState, initialize)
	if e != nil {
		cache.Close()
		provider.Close()
		closeSink()
		return nil, nil, e
	}
	inputs.Admit = a.admission(prefix + "/input")
	e = inputs.WithLock(ctx, func() error {
		raw, e := inputs.Read("previous.json")
		if errors.Is(e, os.ErrNotExist) && initialize {
			raw, _ = json.Marshal(previous)
			return inputs.Write("previous.json", raw)
		}
		if e != nil {
			return e
		}
		var stored map[string]string
		if storage.Decode(raw, &stored, maxState) != nil {
			return ErrInvalid
		}
		if s.Phase != "COMPLETE" {
			expected, _ := json.Marshal(previous)
			if !bytes.Equal(expected, raw) {
				return ErrInvalid
			}
		}
		previous = stored
		return nil
	})
	inputs.Close()
	if e != nil {
		cache.Close()
		provider.Close()
		closeSink()
		return nil, nil, e
	}
	var copies func(context.Context, string) ([]capture.CopyReceipt, error)
	if len(a.observation) > 0 {
		copies = a.copies
	}
	job, e := capture.Open(ctx, capture.Options{Parent: a.root, Directory: prefix + "/job", Initialize: initialize, ReadOnly: inspect, Settlement: settlement, Profile: p, Authority: authority, Intent: s.Intent, Owner: a.b.Local.Owner, Data: a.owner, Writer: a.writer, Provider: provider, Sink: sink, Cache: cache, Previous: previous, Copies: copies, Guard: a.guard, Admission: func(p string) statefile.Admission { return a.admission(prefix + "/job/" + p) }})
	if e != nil {
		cache.Close()
		provider.Close()
		closeSink()
		return nil, nil, e
	}
	job.Fault = a.Fault
	return job, func() { job.Close(); cache.Close(); provider.Close(); closeSink() }, nil
}

func (a *Agent) Run(ctx context.Context) error {
	return a.lease.WithLock(ctx, func() error { return a.run(ctx) })
}
func (a *Agent) run(ctx context.Context) error {
	return a.runSettlement(ctx, nil)
}
func (a *Agent) runSettlement(ctx context.Context, grant []byte) error {
	if e := a.guard(ctx); e != nil {
		return e
	}
	s, e := a.load()
	if e != nil {
		return e
	}
	if s.Phase == "IDLE" || s.Phase == "ABANDONED" {
		return ErrInvalid
	}
	if s.Phase == "COMPLETE" {
		return nil
	}
	ctx, cancel := context.WithCancelCause(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if e := a.guard(ctx); e != nil {
					cancel(e)
					return
				}
			}
		}
	}()
	defer func() { cancel(nil); <-joined }()
	job, close, e := a.openJobMode(ctx, s, false, grant)
	if e != nil {
		return e
	}
	defer close()
	if s.Phase == "PREPARING" {
		if e = a.guard(ctx); e != nil {
			return e
		}
		if _, e = a.intent(s.Intent, true); e != nil {
			return e
		}
		s.Phase = "ACTIVE"
		if e = a.save(s); e != nil {
			return e
		}
		if e = a.point("source-agent-active-durable"); e != nil {
			return e
		}
	}
	if e = job.Run(ctx); e != nil {
		return errors.Join(e, context.Cause(ctx))
	}
	checkpoint, heads, e := job.Export(ctx)
	if e != nil {
		return e
	}
	c, e := capture.VerifyCheckpoint(checkpoint, a.grant.Trust)
	if e != nil {
		return e
	}
	s.Phase, s.Sequence, s.Generation, s.Previous, s.Checkpoint = "COMPLETE", c.Sequence, c.Generation, heads, checkpoint
	if e = a.point("source-agent-before-head"); e != nil {
		return e
	}
	if len(grant) != 0 {
		if e = a.guard(ctx); e != nil {
			return e
		}
		if _, e = ingress.VerifySettlement(grant, a.intentAuthority(s), s.Intent, a.b.Local.Owner, time.Now()); e != nil {
			return e
		}
	}
	return a.save(s)
}

func (a *Agent) Status(ctx context.Context) (Status, error) {
	var out Status
	e := a.lease.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		out = Status{Format: s.Format, Profile: a.b.Profile.ID, Phase: s.Phase, Sequence: s.Sequence, Generation: s.Generation}
		if s.Format == renewedFormat {
			out.AuthorityRevision = a.grant.Revision
		}
		if len(s.Intent) != 0 {
			i, e := a.stateIntent(s)
			if e != nil {
				return e
			}
			out.Operation = i.Operation
			if s.Phase == "PREPARING" || s.Phase == "ACTIVE" {
				action := "RESUME"
				if time.Now().Unix() >= i.ExpiresUnix {
					action = "RECONCILE_RECEIVER"
					if s.Phase == "PREPARING" {
						action = "RETIRE_UNSTARTED"
					}
				}
				out.Pending = &PendingStatus{IntentExpiresUnix: i.ExpiresUnix, Action: action}
			}
			if a.b.Prepared != nil {
				m, _, e := a.readPrepared(ctx, i.Operation)
				if e != nil {
					return e
				}
				out.Prepared = &PreparedStatus{Method: m.Method, ProducerSequence: m.Sequence, SnapshotUnix: m.SnapshotUnix, CompletedUnix: m.CompletedUnix, Attestation: "producer-signed"}
			}
		}
		if s.Phase == "ACTIVE" {
			job, close, e := a.openJobMode(ctx, s, true, nil)
			if e != nil {
				return e
			}
			defer close()
			j, e := job.Status(ctx)
			if e != nil {
				return e
			}
			out.Job = &j
		}
		return nil
	})
	return out, e
}
func (a *Agent) Checkpoint(ctx context.Context) ([]byte, error) {
	var raw []byte
	e := a.lease.WithLock(ctx, func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		if s.Sequence == 0 {
			return capture.ErrCopies
		}
		raw = bytes.Clone(s.Checkpoint)
		return nil
	})
	return raw, e
}
