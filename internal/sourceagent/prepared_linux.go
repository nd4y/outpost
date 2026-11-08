package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

const PreparedAgentFormat = "outpost-source-agent-prepared-1"

var ErrPreparedUnchanged = errors.New("prepared export has not advanced")

// PreparedSource binds a private producer pointer and attestation policy.
// Pointer changes select only future operations; pending work uses its frozen
// signed manifest. Native producer execution and retention are independent.
type PreparedSource struct {
	Trust        capture.PreparedTrust `json:"trust"`
	ManifestFile string                `json:"manifestFile"`
}
type PreparedStatus struct {
	Method           string `json:"method"`
	ProducerSequence uint64 `json:"producerSequence"`
	SnapshotUnix     int64  `json:"snapshotUnix"`
	CompletedUnix    int64  `json:"completedUnix"`
	Attestation      string `json:"attestation"`
}

// CreatePreparedManifest is a producer-side read/sign operation. It does not
// open source runtime, data keys, control credentials, applications or a network.
func CreatePreparedManifest(ctx context.Context, b Bootstrap, c capture.PreparedClaim, key ed25519.PrivateKey) ([]byte, error) {
	if !preparedBootstrap(b) || b.Tree.Format != capture.TreeFormat || b.Tree.Origin != b.Profile.Origin {
		return nil, ErrUnsupported
	}
	root, e := localfs.OpenRoot(b.Tree.Path)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	current, e := volume.InspectRoot(ctx, root)
	expected := b.Tree.Observed
	if e != nil || current.Filesystem != expected.Filesystem || current.FSID != expected.FSID || current.RootInode != expected.RootInode {
		return nil, ErrInvalid
	}
	return capture.CreatePreparedExport(ctx, root, b.Prepared.Trust, c, key, time.Now())
}

func preparedBootstrap(b Bootstrap) bool {
	p := b.Prepared
	return b.Format == PreparedAgentFormat && p != nil && b.Profile.Consistency == p.Trust.Consistency() && p.Trust.Validate() == nil && p.Trust.Profile == b.Profile.ID && p.Trust.Origin == b.Profile.Origin && p.Trust.MaxBytes <= b.Profile.MaxSourceBytes && filepath.IsAbs(p.ManifestFile) && filepath.Clean(p.ManifestFile) == p.ManifestFile && len(p.ManifestFile) <= 4095
}
func (a *Agent) preparedStore(initialize bool) (*statefile.Store, error) {
	s, e := statefile.OpenAt(a.root, "prepared-views", capture.MaxPreparedExport, initialize)
	if e != nil {
		return nil, e
	}
	s.Admit = a.admission("prepared-views")
	return s, nil
}
func (a *Agent) readPrepared(ctx context.Context, operation string) (capture.PreparedExport, []byte, error) {
	var m capture.PreparedExport
	if a.b.Prepared == nil || !storage.ID(operation) {
		return m, nil, ErrInvalid
	}
	store, e := a.preparedStore(false)
	if e != nil {
		return m, nil, e
	}
	defer store.Close()
	var raw []byte
	e = store.WithLock(ctx, func() error { var e error; raw, e = store.Read(operation + ".json"); return e })
	if e != nil {
		return m, nil, e
	}
	if storage.Hash(raw) != operation {
		return m, nil, ErrInvalid
	}
	m, e = capture.VerifyPreparedExport(raw, a.b.Prepared.Trust, time.Now())
	return m, raw, e
}
func (a *Agent) checkPreparedAdvance(ctx context.Context, s state, m capture.PreparedExport, operation string) error {
	if s.Sequence == 0 && s.Phase != "ABANDONED" {
		return nil
	}
	i, e := a.stateIntent(s)
	if e != nil {
		return e
	}
	previous, _, e := a.readPrepared(ctx, i.Operation)
	if e != nil {
		return e
	}
	if i.Operation == operation {
		return ErrPreparedUnchanged
	}
	if m.Sequence <= previous.Sequence || m.SnapshotUnix < previous.SnapshotUnix || m.CompletedUnix < previous.CompletedUnix {
		return ErrInvalid
	}
	return nil
}
func (a *Agent) selectPrepared(ctx context.Context, s state) (capture.PreparedExport, []byte, error) {
	var m capture.PreparedExport
	raw, e := worker.ReadPrivate(a.b.Prepared.ManifestFile, capture.MaxPreparedExport)
	if e != nil {
		return m, nil, e
	}
	m, e = capture.VerifyPreparedExport(raw, a.b.Prepared.Trust, time.Now())
	if e != nil {
		return m, nil, e
	}
	if e = a.checkPreparedAdvance(ctx, s, m, storage.Hash(raw)); e != nil {
		return m, nil, e
	}
	return m, raw, nil
}
func (a *Agent) freezePrepared(ctx context.Context, manifest, intent []byte) error {
	i, _, e := ingress.VerifyIntent(intent, a.authority, a.b.Local.Owner, time.Now())
	if e != nil {
		return e
	}
	m, e := capture.VerifyPreparedExport(manifest, a.b.Prepared.Trust, time.Now())
	if e != nil {
		return e
	}
	if i.Operation != storage.Hash(manifest) || i.SnapshotUnix != m.SnapshotUnix {
		return ErrInvalid
	}
	guard := func() error {
		if e := a.guard(ctx); e != nil {
			return e
		}
		_, _, e := ingress.VerifyIntent(intent, a.authority, a.b.Local.Owner, time.Now())
		return e
	}
	if e = guard(); e != nil {
		return e
	}
	store, e := a.preparedStore(true)
	if e != nil {
		return e
	}
	defer store.Close()
	admit := a.admission("prepared-views")
	store.Admit = func(name string, size int) (func(bool) error, error) {
		if e := guard(); e != nil {
			return nil, e
		}
		finish, e := admit(name, size)
		if e != nil {
			return nil, e
		}
		return func(written bool) error { return errors.Join(finish(written), guard()) }, nil
	}
	e = store.WithLock(ctx, func() error {
		if e := guard(); e != nil {
			return e
		}
		previous, e := store.Read(i.Operation + ".json")
		if errors.Is(e, os.ErrNotExist) {
			return store.Write(i.Operation+".json", manifest)
		}
		if e != nil {
			return e
		}
		if !bytes.Equal(previous, manifest) {
			return ErrInvalid
		}
		return nil
	})
	if e != nil {
		return e
	}
	if e = guard(); e != nil {
		return e
	}
	return a.point("source-prepared-view-frozen")
}

type installedProvider interface {
	capture.Provider
	Close() error
}

func (a *Agent) openProvider(ctx context.Context, prefix string, i ingress.Intent, initialize bool) (installedProvider, error) {
	if a.b.Prepared == nil {
		return capture.OpenTreeProvider(ctx, a.root, prefix+"/provider", i.Operation, i.Operation, a.b.Tree, initialize, a.admission(prefix+"/provider"), a.guard)
	}
	m, raw, e := a.readPrepared(ctx, i.Operation)
	if e != nil {
		return nil, e
	}
	if m.SnapshotUnix != i.SnapshotUnix {
		return nil, ErrInvalid
	}
	return capture.OpenPreparedProvider(ctx, capture.PreparedProviderOptions{Parent: a.root, Directory: prefix + "/provider", Operation: i.Operation, Tree: a.b.Tree, Trust: a.b.Prepared.Trust, Manifest: raw, Initialize: initialize, Admission: a.admission(prefix + "/provider"), Guard: a.guard, Fault: a.Fault})
}
