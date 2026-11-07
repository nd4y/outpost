package control

import (
	"bytes"
	"encoding/json"

	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

func (c Config) UploadDelegation(id string) ([]byte, upload.Delegation, bool) {
	for _, raw := range c.Uploads {
		if storage.Hash(raw) != id {
			continue
		}
		var g upload.Delegation
		if storage.Decode(raw, &g, upload.MaxDelegation) != nil {
			return nil, g, false
		}
		d, ok := c.DomainByID(g.Trust.Domain)
		if !ok {
			return nil, g, false
		}
		g, e := upload.VerifyDelegation(raw, upload.Authority{Generation: d.Trust, Planner: d.Planner})
		return raw, g, e == nil
	}
	return nil, upload.Delegation{}, false
}
func (c Config) validateUploads() error {
	if len(c.Uploads) > 128 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, raw := range c.Uploads {
		_, g, ok := c.UploadDelegation(storage.Hash(raw))
		if !ok {
			return ErrDenied
		}
		d, ok := c.DomainByID(g.Trust.Domain)
		if !ok {
			return ErrDenied
		}
		target, ok := c.TargetByID(g.Profile.ID())
		if !ok || target.Profile != g.Profile || g.StartMillis > c.NotBefore*1000 || g.ExpiresUnix < c.ExpiresUnix {
			return ErrDenied
		}
		pair := g.Trust.Domain + "/" + g.Profile.ID()
		if seen[pair] {
			return ErrDenied
		}
		seen[pair] = true
		self := false
		for _, executor := range g.Workers {
			n, ok := c.NodeByID(executor.ID)
			holder := false
			for _, id := range d.Placement.Holders {
				if id == executor.ID {
					holder = true
				}
			}
			if !ok || !holder || n.Class != executor.Class || !d.Placement.PermitsCloud(executor.ID, g.Profile.ID()) {
				return ErrDenied
			}
			if executor.ID == c.Node {
				self = true
			}
		}
		if !self {
			return ErrDenied
		}
	}
	return nil
}
func UploadJob(raw []byte, g upload.Delegation, id, node string) Job {
	return Job{Operation: upload.DelegatedOperation(raw, id), Executor: node, Kind: "upload", Domain: g.Trust.Domain, Generation: id, Target: g.Profile.ID(), Delegation: storage.Hash(raw)}
}
func (c Config) AutonomousUpload(j Job) bool {
	if !storage.ID(j.Generation) || !storage.ID(j.Delegation) {
		return false
	}
	raw, g, ok := c.UploadDelegation(j.Delegation)
	if !ok {
		return false
	}
	expected, _ := json.Marshal(UploadJob(raw, g, j.Generation, c.Node))
	actual, _ := json.Marshal(j)
	return bytes.Equal(expected, actual)
}
