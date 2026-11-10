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
	ActiveFailover  bool                `json:"activeFailover,omitempty"`
	Reserve         *CompanionIngress   `json:"reserveIngress,omitempty"`
	Standby         bool                `json:"standby,omitempty"`
	Companion       *CompanionIngress   `json:"companionIngress,omitempty"`
	JournalCopy     *JournalCopy        `json:"journalCopy,omitempty"`
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
	Format                   string                            `json:"format"`
	Binding                  string                            `json:"binding"`
	Phase                    string                            `json:"phase"`
	ObservedUnix             int64                             `json:"observedUnix"`
	Sequence                 uint64                            `json:"sequence"`
	Generation               string                            `json:"generation,omitempty"`
	Intent                   []byte                            `json:"intent,omitempty"`
	Previous                 map[string]string                 `json:"previous"`
	Checkpoint               []byte                            `json:"checkpoint,omitempty"`
	Signature                []byte                            `json:"signature,omitempty"`
	Authority                []byte                            `json:"authority,omitempty"`
	Observation              []byte                            `json:"observation,omitempty"`
	IntentAuthority          []byte                            `json:"intentAuthority,omitempty"`
	CompanionAuthority       []byte                            `json:"companionAuthority,omitempty"`
	IntentCompanionAuthority []byte                            `json:"intentCompanionAuthority,omitempty"`
	ReserveAuthority         []byte                            `json:"reserveAuthority,omitempty"`
	IntentReserveAuthority   []byte                            `json:"intentReserveAuthority,omitempty"`
	Route                    []string                          `json:"route,omitempty"`
	Superseded               []string                          `json:"superseded,omitempty"`
	RoutePreparing           bool                              `json:"routePreparing,omitempty"`
	RoutePlan                string                            `json:"routePlan,omitempty"`
	RouteCatalog             string                            `json:"routeCatalog,omitempty"`
	Reclaims                 map[string]ingress.ReclaimRequest `json:"reclaims,omitempty"`
	ReclaimRecorded          bool                              `json:"reclaimRecorded,omitempty"`
	LegacyDigest             string                            `json:"legacyDigest,omitempty"`
	RetirementKind           string                            `json:"retirementKind,omitempty"`
	Retirement               string                            `json:"retirement,omitempty"`
}

type Status struct {
	Format            string          `json:"format"`
	Profile           string          `json:"profile"`
	Phase             string          `json:"phase"`
	Receivers         []string        `json:"receivers,omitempty"`
	Superseded        []string        `json:"supersededReceivers,omitempty"`
	PendingReclaims   []string        `json:"pendingReclaims,omitempty"`
	Receiver          string          `json:"receiver,omitempty"`
	Operation         string          `json:"operation,omitempty"`
	Sequence          uint64          `json:"sequence"`
	Generation        string          `json:"generation,omitempty"`
	Job               *capture.State  `json:"job,omitempty"`
	AuthorityRevision uint64          `json:"authorityRevision,omitempty"`
	Prepared          *PreparedStatus `json:"prepared,omitempty"`
	Pending           *PendingStatus  `json:"pending,omitempty"`
	Milestones        *Milestones     `json:"milestones,omitempty"`
}

type Milestones struct {
	SnapshotUnix             int64              `json:"snapshotUnix"`
	ProviderReleaseUnix      int64              `json:"providerReleaseUnix,omitempty"`
	FirstReplicaVerifiedUnix int64              `json:"firstReplicaVerifiedUnix,omitempty"`
	Replicas                 []ReplicaMilestone `json:"replicas,omitempty"`
}

type ReplicaMilestone struct {
	Target       string `json:"target"`
	VerifiedUnix int64  `json:"verifiedUnix"`
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
	journal            *sourceJournal
	owner              filekit.Owner
	writer             ed25519.PrivateKey
	authority          []byte
	observation        []byte
	initialObservation []byte
	grant              ingress.Authority
	companion          ingress.Authority
	companionAuthority []byte
	reserve            ingress.Authority
	reserveAuthority   []byte
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
	if (!bestEffort && !preparedBootstrap(b)) || b.Profile.MinimumCopies < 1 || b.Profile.MinimumCopies > 2 || b.Profile.MinimumCopies == 2 && b.ObservationFile == "" && b.Reserve == nil {
		return nil, ErrUnsupported
	}
	switch b.Profile.ReleasePolicy {
	case "":
	case capture.TwoHolderCoverage, capture.PairedSplitCoverage:
		if b.Companion == nil {
			return nil, ErrUnsupported
		}
	default:
		return nil, ErrUnsupported
	}
	if b.Prepared != nil {
		p := *b.Prepared
		p.Trust.Producer = bytes.Clone(p.Trust.Producer)
		b.Prepared = &p
	}
	if b.JournalCopy != nil {
		copy := *b.JournalCopy
		b.JournalCopy = &copy
	}
	if b.Standby && (b.Companion == nil || b.Profile.MinimumCopies != 1 || b.Profile.ReleasePolicy != "" || b.ObservationFile != "") {
		return nil, ErrUnsupported
	}
	if b.Reserve != nil && (b.Standby || b.Companion == nil || b.Profile.MinimumCopies != 2 || b.ObservationFile != "") ||
		b.ActiveFailover && !b.Standby && b.Reserve == nil {
		return nil, ErrUnsupported
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
	if e = a.loadReserve(); e != nil {
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
		ReserveAuthority   []byte `json:",omitempty"`
	}{b, a.authority, a.observation, a.owner, a.companionAuthority, a.reserveAuthority})
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
	if b.JournalCopy != nil {
		a.journal, e = openSourceJournal(ctx, b, initialize)
		if e != nil {
			return fail(e)
		}
	}
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
			if _, e := a.store.Read(sourceStateFile); !errors.Is(e, os.ErrNotExist) {
				return ErrInvalid
			}
			return a.commitState(state{Format: Format, Binding: a.binding, Phase: "IDLE", Previous: map[string]string{}}, true)
		}
		if e := a.reconcileJournal(ctx); e != nil {
			return e
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
	if a.journal != nil {
		e = errors.Join(e, a.journal.close())
	}
	return e
}
func (a *Agent) guard(ctx context.Context) error {
	if a.poisoned.Load() {
		return ErrInvalid
	}
	if e := a.b.Local.Volume.CheckHandle(ctx, a.runtimeDirectory, a.root); e != nil {
		return e
	}
	if a.journal != nil {
		return a.journal.guard(ctx)
	}
	return nil
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
	return a.commitState(s, false)
}

func (a *Agent) commitState(s state, initialize bool) error {
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
	if a.journal == nil {
		e = a.store.Write(sourceStateFile, raw)
	} else {
		e = a.writeJournal(raw, initialize)
	}
	if e != nil {
		a.poisoned.Store(true)
	}
	return e
}
func (a *Agent) load() (state, error) {
	return a.loadScope(false)
}
func (a *Agent) loadAdopt() (state, error) { return a.loadScope(true) }
func (a *Agent) loadScope(adopt bool) (state, error) {
	raw, e := a.store.Read(sourceStateFile)
	if e != nil {
		return state{}, e
	}
	return a.decodeState(raw, adopt)
}

func (a *Agent) decodeState(raw []byte, adopt bool) (state, error) {
	var s state
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
	if e = a.validateReclaims(s); e != nil {
		return s, e
	}
	for f, v := range s.Previous {
		if !storage.ID(f) || !storage.ID(v) {
			return s, ErrInvalid
		}
	}
	if s.Phase != "IDLE" && s.Phase != "PREPARING" && s.Phase != "ACTIVE" && s.Phase != "COMPLETE" && s.Phase != "ABANDONED" ||
		s.Phase != "ABANDONED" && (s.Retirement != "" || s.RetirementKind != "") {
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
		if e = a.validateRoute(s, i); e != nil {
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
			switch s.RetirementKind {
			case "":
				record, err := a.readUnstartedArchive(s, i, s.Retirement)
				if err != nil || record.RecordedUnix > s.ObservedUnix {
					return s, ErrInvalid
				}
			case ingress.SettlementRetire, ingress.SettlementRetireUnsealed:
				record, err := a.readActiveRetirement(s, i, s.Retirement)
				if err != nil || record.RecordedUnix > s.ObservedUnix {
					return s, ErrInvalid
				}
			default:
				return s, ErrInvalid
			}
		}
	} else if len(s.Intent) != 0 || s.Sequence != 0 || len(s.Route)+len(s.Superseded) != 0 || s.RoutePreparing || s.RoutePlan != "" || s.RouteCatalog != "" {
		return s, ErrInvalid
	}
	if adopt && s.Format == renewedFormat {
		a.authority = bytes.Clone(s.Authority)
		a.companionAuthority = bytes.Clone(s.CompanionAuthority)
		a.reserveAuthority = bytes.Clone(s.ReserveAuthority)
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
	authority := a.authority
	if a.standbySelected(i.Ingress) {
		authority = a.companionAuthority
	}
	i, _, e := ingress.VerifyIntent(raw, authority, a.b.Local.Owner, now)
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
	if s.Phase == "COMPLETE" {
		if e = a.reconcileReclaims(ctx, &s); e != nil {
			return e
		}
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
	if a.b.Standby {
		raw, e = a.selectReceiver(ctx, i, raw)
		if e != nil {
			return e
		}
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
		s.Route, s.Superseded, s.RoutePreparing, s.RoutePlan, s.RouteCatalog = nil, nil, false, "", ""
		if a.routed() {
			s.Route = []string{i.Ingress}
			if a.b.Reserve != nil {
				s.Route = append(s.Route, a.companion.Ingress)
			}
		}
		s.Retirement, s.RetirementKind, s.ReclaimRecorded = "", "", false
		if s.Format == renewedFormat {
			s.IntentAuthority = bytes.Clone(a.authority)
			s.IntentCompanionAuthority = bytes.Clone(a.companionAuthority)
			s.IntentReserveAuthority = bytes.Clone(a.reserveAuthority)
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
func (a *Agent) openJobMode(ctx context.Context, s state, inspect bool, settlement []byte, companionSettlement ...[]byte) (*capture.Job, func(), error) {
	if s.Phase == "PREPARING" && (inspect || len(settlement) != 0) {
		return nil, nil, ErrInvalid
	}
	i, e := a.stateIntent(s)
	if e != nil {
		return nil, nil, e
	}
	limits := peer.Limits{Concurrency: 1, Timeout: 30 * time.Second, Attempts: 1}
	authority, intentRaw, endpoint := a.intentAuthority(s), s.Intent, a.receiverEndpoint(i.Ingress)
	if a.routed() {
		route, err := a.routeReceiver(s, i, s.Route[0])
		if err != nil {
			return nil, nil, err
		}
		i, authority, intentRaw, endpoint = route.intent, route.authority, route.raw, route.endpoint
	}
	var sealed *capture.SealedTransfer
	if s.RoutePreparing && s.RouteCatalog != "" && !inspect {
		prior := s
		prior.Route = s.Superseded
		prior.Superseded, prior.RoutePreparing, prior.RoutePlan, prior.RouteCatalog = nil, false, "", ""
		job, closeJob, err := a.openJobMode(ctx, prior, true, nil)
		if err != nil {
			return nil, nil, err
		}
		sealed, err = job.SealedTransfer(ctx)
		closeJob()
		if err != nil || sealed == nil {
			return nil, nil, errors.Join(ErrInvalid, err)
		}
	}
	var client *ingress.Client
	cleanup := inspect || len(settlement) != 0
	if len(settlement) != 0 {
		client, e = ingress.NewSettlementClient(endpoint, authority, intentRaw, settlement, a.b.Local.Owner, a.cert, a.roots, limits)
	} else if inspect {
		client, e = ingress.NewCleanupClient(endpoint, authority, intentRaw, a.b.Local.Owner, a.cert, a.roots, limits)
	} else {
		client, e = ingress.NewClient(endpoint, authority, intentRaw, a.b.Local.Owner, a.cert, a.roots, limits)
		if e != nil && s.Phase != "PREPARING" {
			client, e = ingress.NewCleanupClient(endpoint, authority, intentRaw, a.b.Local.Owner, a.cert, a.roots, limits)
			cleanup = true
		}
	}
	if e != nil {
		return nil, nil, e
	}
	initialize := s.Phase == "PREPARING" || s.RoutePreparing && !inspect
	operationPrefix := path.Join("operations", i.Operation)
	prefix := operationPrefix
	if a.routed() {
		prefix = path.Join(operationPrefix, "route-"+routeScope(i.Operation, s.Route))
	} else if a.b.Standby {
		prefix = path.Join(operationPrefix, "receiver-"+i.Ingress)
	}
	provider, e := a.openProvider(ctx, operationPrefix, i, initialize && s.RouteCatalog == "")
	if e != nil {
		client.Close()
		return nil, nil, e
	}
	var sink capture.Sink = client
	closeSink := client.Close
	if a.b.Companion != nil && !a.b.Standby {
		companionAuthority := a.companionAuthority
		if s.Format == renewedFormat {
			companionAuthority = s.IntentCompanionAuthority
		}
		var grant []byte
		if len(companionSettlement) != 0 {
			grant = companionSettlement[0]
		}
		companionID, companionEndpoint := a.companion.Ingress, a.b.Companion.Endpoint
		if a.b.Reserve != nil {
			route, err := a.routeReceiver(s, i, s.Route[1])
			if err != nil {
				provider.Close()
				client.Close()
				return nil, nil, err
			}
			companionID, companionEndpoint, companionAuthority = route.intent.Ingress, route.endpoint, route.authority
		}
		group, err := a.openParallelSink(i, prefix, companionID, companionEndpoint, companionAuthority, client, limits, initialize, cleanup, grant)
		if err != nil {
			provider.Close()
			client.Close()
			return nil, nil, err
		}
		group.recoverRoute = len(s.Superseded) != 0 && !cleanup
		group.replaying = group.replaying || group.recoverRoute
		if s.RouteCatalog != "" {
			group.split = false
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
	if a.b.Reserve != nil {
		p.CopyTargets = s.Route
	}
	var progress, priorProgress string
	if a.routed() {
		progress = routeScope(i.Operation, s.Route)
		if len(s.Superseded) != 0 {
			priorProgress = routeScope(i.Operation, s.Superseded)
		}
	}
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
	if group, ok := sink.(*parallelSink); ok && (group.settling || a.b.Reserve != nil) {
		copies = group.settlementCopies
	} else if len(a.observation) > 0 {
		copies = a.copies
	}
	job, e := capture.Open(ctx, capture.Options{Parent: a.root, Directory: prefix + "/job", Initialize: initialize, ReadOnly: inspect, Settlement: settlement, Profile: p, Authority: authority, Intent: intentRaw, Owner: a.b.Local.Owner, Data: a.owner, Writer: a.writer, Provider: provider, Sink: sink, Cache: cache, Previous: previous, ProgressScope: progress, PreviousProgress: priorProgress, RoutePlan: s.RoutePlan, InheritedCatalog: s.RouteCatalog, Sealed: sealed, Copies: copies, Guard: a.guard, Admission: func(p string) statefile.Admission { return a.admission(prefix + "/job/" + p) }})
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
func (a *Agent) runSettlement(ctx context.Context, grant []byte, companion ...[]byte) error {
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
		return a.reconcileReclaims(ctx, &s)
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
	if a.b.Standby && !a.routed() && s.Phase == "PREPARING" {
		i, err := a.stateIntent(s)
		if err != nil {
			return err
		}
		selected, err := a.selectReceiver(ctx, i, s.Intent)
		if err != nil {
			return err
		}
		if !bytes.Equal(selected, s.Intent) {
			s.Intent = selected
			if err = a.save(s); err != nil {
				return err
			}
			if err = a.point("source-agent-standby-route-durable"); err != nil {
				return err
			}
		}
	}
	checkpoint, heads, e := a.executeCapture(ctx, &s, grant, companion)
	if e != nil {
		return errors.Join(e, context.Cause(ctx))
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
		_, authority, raw, _, e := a.settlementReceiver(s, "")
		if e != nil {
			return e
		}
		if _, e = ingress.VerifySettlement(grant, authority, raw, a.b.Local.Owner, time.Now()); e != nil {
			return e
		}
	}
	if _, e = a.queueReclaim(&s); e != nil {
		return e
	}
	if e = a.save(s); e != nil {
		return e
	}
	return a.reconcileReclaims(ctx, &s)
}

func (a *Agent) fenceCapture(ctx context.Context, s *state) error {
	if s.Phase == "PREPARING" {
		if e := a.guard(ctx); e != nil {
			return e
		}
		if _, e := a.intent(s.Intent, true); e != nil {
			return e
		}
		s.Phase = "ACTIVE"
		if e := a.save(*s); e != nil {
			return e
		}
		return a.point("source-agent-active-durable")
	}
	if s.RoutePreparing {
		s.RoutePreparing = false
		return a.save(*s)
	}
	return nil
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
		out = Status{Format: s.Format, Profile: a.b.Profile.ID, Phase: s.Phase, Sequence: s.Sequence, Generation: s.Generation, PendingReclaims: reclaimTargets(s)}
		if s.Format == renewedFormat {
			out.AuthorityRevision = a.grant.Revision
		}
		if len(s.Intent) != 0 {
			i, e := a.stateIntent(s)
			if e != nil {
				return e
			}
			out.Operation = i.Operation
			out.Receiver = i.Ingress
			if a.routed() {
				out.Receiver, out.Receivers, out.Superseded = s.Route[0], s.Route, s.Superseded
			}
			if s.Phase == "PREPARING" || s.Phase == "ACTIVE" {
				action := "RESUME"
				if time.Now().Unix() >= i.ExpiresUnix {
					action = "RECONCILE_RECEIVER"
					if s.Phase == "PREPARING" {
						action = "RETIRE_UNSTARTED"
					}
				}
				if s.RoutePreparing && action == "RESUME" {
					action = "PREPARE_RECEIVER_ROUTE"
				}
				out.Pending = &PendingStatus{IntentExpiresUnix: i.ExpiresUnix, Action: action}
			}
			if s.Phase == "ACTIVE" || s.Phase == "COMPLETE" {
				out.Milestones = &Milestones{SnapshotUnix: i.SnapshotUnix}
				released := capture.ProviderReleaseObservedUnix(a.root, i.Operation, path.Join("operations", i.Operation, "provider"))
				if released >= i.SnapshotUnix {
					out.Milestones.ProviderReleaseUnix = released
				}
			}
			if s.Phase == "COMPLETE" {
				checkpoint, e := capture.VerifyCheckpoint(s.Checkpoint, a.grant.Trust)
				if e != nil {
					return e
				}
				out.Milestones.addReplicas(checkpoint.Copies)
			}
			if a.b.Prepared != nil {
				m, _, e := a.readPrepared(ctx, i.Operation)
				if e != nil {
					return e
				}
				out.Prepared = &PreparedStatus{Method: m.Method, ProducerSequence: m.Sequence, SnapshotUnix: m.SnapshotUnix, CompletedUnix: m.CompletedUnix, Attestation: "producer-signed"}
			}
		}
		if s.Phase == "ACTIVE" && !s.RoutePreparing {
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
			out.Milestones.addReplicas(j.Copies)
		}
		return nil
	})
	return out, e
}

func (m *Milestones) addReplicas(copies []capture.CopyReceipt) {
	for _, copy := range copies {
		m.Replicas = append(m.Replicas, ReplicaMilestone{Target: copy.Target, VerifiedUnix: copy.ObservedUnix})
		if m.FirstReplicaVerifiedUnix == 0 || copy.ObservedUnix < m.FirstReplicaVerifiedUnix {
			m.FirstReplicaVerifiedUnix = copy.ObservedUnix
		}
	}
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
