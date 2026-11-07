package control

import (
	"bytes"
	"crypto/ed25519"
	"time"

	"github.com/nd4y/outpost/internal/command"
)

func (c Config) validateCommands(owner ed25519.PublicKey) error {
	if len(c.Commands) > 128 {
		return ErrDenied
	}
	seen := map[string]bool{}
	for _, raw := range c.Commands {
		a, e := command.VerifyAuthority(raw, owner)
		if e != nil {
			return ErrDenied
		}
		d, ok := c.DomainByID(a.Domain)
		node, found := c.NodeByID(c.Node)
		binding := command.Identity(a.Service) + "/" + a.Domain
		if !ok || !found || a.Node != c.Node || a.Repository != d.Trust.Repository || a.WriterEpoch != d.Trust.Epoch || a.NotBefore >= c.ExpiresUnix || a.ExpiresUnix <= c.NotBefore || seen[binding] || a.Allows("restore") && node.Class != "trusted" {
			return ErrDenied
		}
		seen[binding] = true
	}
	return nil
}

// CommandAuthority only selects an exact grant from an already owner-verified
// configuration. A detached valid signature does not authorize execution.
func (c Config) CommandAuthority(raw []byte, owner ed25519.PublicKey, now time.Time) (command.Authority, error) {
	var out command.Authority
	if e := c.Active(now); e != nil {
		return out, e
	}
	if c.validateCommands(owner) != nil {
		return out, ErrDenied
	}
	for _, admitted := range c.Commands {
		if !bytes.Equal(admitted, raw) {
			continue
		}
		a, e := command.VerifyAuthority(admitted, owner)
		if e != nil {
			return out, e
		}
		if e = a.Active(now); e != nil {
			return out, e
		}
		return a, nil
	}
	return out, ErrDenied
}
