package sourceagent

import (
	"bytes"
	"context"
	"path/filepath"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

const RecoveryExportFormat = "outpost-source-recovery-export-1"

// RecoveryExportProfile is private owner configuration. A shared worker plan
// cannot choose a destination for plaintext recovery secrets.
type RecoveryExportProfile struct {
	Format             string         `json:"format"`
	Volume             volume.Binding `json:"volume"`
	Directory          string         `json:"directory"`
	ToolsDirectory     string         `json:"toolsDirectory"`
	ToolManifestSHA256 string         `json:"toolManifestSHA256"`
}

func LoadRecoveryExport(path string) (RecoveryExportProfile, error) {
	var p RecoveryExportProfile
	raw, e := worker.ReadPrivate(path, 16384)
	if e != nil {
		return p, e
	}
	if worker.DecodeInput(raw, &p, 16384) != nil {
		return p, ErrInvalid
	}
	return p, nil
}

// ExportRecovery snapshots only decryption material, public trust and the last
// completed checkpoint while holding the execution lease. Copying tools does
// not keep the source loop locked. The result never claims a newer checkpoint
// or current storage health merely because the package was exported now.
func (a *Agent) ExportRecovery(ctx context.Context, p RecoveryExportProfile, revision, output string) (recoverybundle.Receipt, error) {
	var out recoverybundle.Receipt
	if p.Format != RecoveryExportFormat || p.Volume.Scope != a.b.Local.Node || !filepath.IsAbs(output) || filepath.Clean(output) != output || filepath.Dir(output) != p.Directory {
		return out, ErrInvalid
	}
	owner, e := p.Volume.Open(ctx, p.Directory, false)
	if e != nil {
		return out, e
	}
	defer owner.Close()
	ownerRoot, e := localfs.OpenRoot(p.Volume.Root)
	if e != nil {
		return out, e
	}
	defer ownerRoot.Close()
	guard := func(ctx context.Context) error {
		if e := p.Volume.CheckHandle(ctx, p.Directory, owner); e != nil {
			return e
		}
		if e := a.guard(ctx); e != nil {
			return e
		}
		runtime, e := localfs.OpenRoot(a.b.Local.Volume.Root)
		if e != nil {
			return e
		}
		defer runtime.Close()
		if e = localfs.Disjoint(ctx, ownerRoot, runtime); e != nil {
			return recoverybundle.ErrDenied
		}
		tree, e := localfs.OpenRoot(a.b.Tree.Path)
		if e != nil {
			return e
		}
		defer tree.Close()
		observed, e := volume.InspectRoot(ctx, tree)
		if e != nil || observed != a.b.Tree.Observed {
			return recoverybundle.ErrDenied
		}
		if e = localfs.Disjoint(ctx, ownerRoot, tree); e != nil {
			return recoverybundle.ErrDenied
		}
		return nil
	}
	if e = guard(ctx); e != nil {
		return out, e
	}
	var material recoverybundle.Material
	e = a.lease.WithLock(ctx, func() error {
		if e := guard(ctx); e != nil {
			return e
		}
		s, e := a.load()
		if e != nil {
			return e
		}
		material.Owner, e = a.owner.RecoveryMaterial()
		if e != nil {
			return e
		}
		material.Trust = a.grant.Trust
		material.Trust.Writer = bytes.Clone(material.Trust.Writer)
		material.Trust.Maintenance = bytes.Clone(material.Trust.Maintenance)
		material.Checkpoint = bytes.Clone(s.Checkpoint)
		return nil
	})
	if e != nil {
		return out, e
	}
	return recoverybundle.Export(ctx, material, recoverybundle.Options{ToolsDirectory: p.ToolsDirectory, ManifestSHA256: p.ToolManifestSHA256, Revision: revision, Guard: guard, Fault: a.Fault}, output)
}
