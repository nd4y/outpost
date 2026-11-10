package control

import (
	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
)

// MaintenancePermit binds separate deletion authority to the exact command.
// A service/operator grant cannot mint deletion permission or reuse another
// operation's permit. No private maintenance or data key reaches the worker.
func (c Config) MaintenancePermit(request command.Request) (generation.Permit, error) {
	var out generation.Permit
	d, ok := c.DomainByID(request.Domain)
	if !ok || request.Kind != "maintenance" {
		return out, ErrDenied
	}
	out, e := generation.VerifyPermit(request.MaintenancePermit, d.Trust)
	if e != nil || out.Operation != request.Operation {
		return out, ErrDenied
	}
	if w := out.Window; w != nil && (w.Node != c.Node || w.StartUnix >= request.ExpiresUnix || w.StartUnix >= c.ExpiresUnix) {
		return out, ErrDenied
	}
	return out, nil
}
