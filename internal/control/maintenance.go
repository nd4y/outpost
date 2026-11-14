package control

import (
	"slices"

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
	if d.RetirementMinimumCopies > 0 && len(out.Retire) > 0 &&
		(out.Coverage == nil || out.Coverage.MinimumCopies < d.RetirementMinimumCopies) {
		return out, ErrDenied
	}
	if out.Coverage != nil {
		if d.RetirementMinimumCopies == 0 || !c.trustedHolder(d, c.Node) {
			return out, ErrDenied
		}
		for _, w := range out.Coverage.Witnesses {
			if !c.trustedHolder(d, w.Node) {
				return out, ErrDenied
			}
		}
	}
	return out, nil
}

// RetentionProtection binds a signed grant to the current trusted recipient.
func (c Config) RetentionProtection(request command.Request) (generation.RetentionProtection, error) {
	var out generation.RetentionProtection
	d, ok := c.DomainByID(request.Domain)
	if !ok || request.Kind != "retention" || !c.trustedHolder(d, c.Node) {
		return out, ErrDenied
	}
	out, err := generation.VerifyRetentionProtection(request.RetentionGrant, d.Trust, c.Node)
	if err != nil || out.Operation == request.Operation || out.NotBefore >= request.ExpiresUnix || out.NotBefore >= c.ExpiresUnix {
		return out, ErrDenied
	}
	return out, nil
}

func (c Config) trustedHolder(d Domain, id string) bool {
	n, ok := c.NodeByID(id)
	return ok && n.Class == "trusted" && slices.Contains(d.Placement.Holders, id)
}
