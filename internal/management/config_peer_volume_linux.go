package management

import (
	"context"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const PeerVolumePreviewFormat = "outpost-management-preview-with-peer-volume-1"

type PeerVolumeRequest struct {
	Mutation      SignedMutation `json:"mutation"`
	PeerOperation string         `json:"peerOperation"`
	Catalog       []byte         `json:"catalog"`
}

// DeclaredPeerVolume sizes one exact catalog before destination reuse.
type DeclaredPeerVolume struct {
	Operation         string `json:"operationId"`
	Domain            string `json:"domain"`
	Generation        string `json:"generation"`
	From              string `json:"from"`
	To                string `json:"to"`
	Mode              string `json:"mode"`
	UniqueObjectBytes int64  `json:"uniqueObjectBytes"`
	UniqueObjects     int    `json:"uniqueObjects"`
	CatalogBytes      int    `json:"catalogBytes"`
}

type PeerVolumePreview struct {
	Format        string                 `json:"format"`
	Preview       Preview                `json:"preview"`
	UploadVolumes []DeclaredUploadVolume `json:"uploadVolumes"`
	PeerVolume    DeclaredPeerVolume     `json:"peerVolume"`
}

type configPreviewDetails struct {
	uploadVolumes []DeclaredUploadVolume
	peer          *PeerVolumeRequest
	peerVolume    DeclaredPeerVolume
}

type peerVolumeAdmission struct {
	volume      DeclaredPeerVolume
	trust       generation.Trust
	revision    uint64
	expiresUnix int64
}

func (r *Registry) admitPeerVolume(ctx context.Context, state registryState, tenant string, cfg control.Config, request *PeerVolumeRequest, now time.Time) (peerVolumeAdmission, error) {
	if !storage.ID(request.PeerOperation) || len(request.Catalog) == 0 || len(request.Catalog) > generation.MaxCatalog {
		return peerVolumeAdmission{}, ErrInvalid
	}
	for _, job := range cfg.Jobs {
		if job.Operation != request.PeerOperation {
			continue
		}
		if (job.Kind != "push" && job.Kind != "pull") || job.Repair != "" {
			return peerVolumeAdmission{}, ErrDenied
		}
		domain, ok := cfg.DomainByID(job.Domain)
		if !ok {
			return peerVolumeAdmission{}, ErrDenied
		}
		from, to := job.Executor, job.Peer
		if job.Kind == "pull" {
			from, to = to, from
		}
		expires := cfg.ExpiresUnix
		// The signed candidate already binds job and edge. Recheck both
		// endpoint enrollments for the exact repository epoch and tenant.
		for _, node := range []string{from, to} {
			enrollment, err := VerifyEnrollment(state.Enrollments[node], r.owner)
			admission, admitted := enrollment.Domain(job.Domain)
			if err != nil || !admitted || enrollment.Tenant != tenant || !enrollment.Active(now) ||
				admission.Repository != domain.Trust.Repository || admission.Epoch != domain.Trust.Epoch {
				return peerVolumeAdmission{}, ErrDenied
			}
			expires = min(expires, enrollment.ExpiresUnix)
			pending, err := r.pendingEnrollment(ctx, state, node)
			if err != nil {
				return peerVolumeAdmission{}, err
			}
			if pending {
				return peerVolumeAdmission{}, ErrConflict
			}
		}
		return peerVolumeAdmission{
			volume: DeclaredPeerVolume{Operation: job.Operation, Domain: job.Domain, Generation: job.Generation,
				From: from, To: to, Mode: job.Kind},
			trust: domain.Trust, revision: state.Revision, expiresUnix: expires,
		}, nil
	}
	return peerVolumeAdmission{}, ErrDenied
}

func (r *Registry) peerVolume(ctx context.Context, admitted peerVolumeAdmission, catalog []byte) (DeclaredPeerVolume, error) {
	if err := ctx.Err(); err != nil {
		return DeclaredPeerVolume{}, err
	}
	if storage.Hash(catalog) != admitted.volume.Generation {
		return DeclaredPeerVolume{}, ErrDenied
	}
	objects, err := generation.Dependencies(catalog, admitted.trust)
	if err != nil {
		return DeclaredPeerVolume{}, ErrDenied
	}
	out := admitted.volume
	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return DeclaredPeerVolume{}, err
		}
		size := int64(object.Bytes)
		if size <= 0 || size > MaxSafeInteger-out.UniqueObjectBytes {
			return DeclaredPeerVolume{}, ErrInvalid
		}
		out.UniqueObjectBytes += size
	}
	out.UniqueObjects, out.CatalogBytes = len(objects), len(catalog)
	if err := r.checkRetentionRevision(ctx, admitted.revision); err != nil {
		return DeclaredPeerVolume{}, err
	}
	if time.Now().Unix() >= admitted.expiresUnix {
		return DeclaredPeerVolume{}, ErrDenied
	}
	return out, nil
}
