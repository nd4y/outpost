package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
)

// SettlementAdmission is separate from Ingress: its original signed documents
// identify retained history, while its fresh owner grant and enclosing current
// policy admit only completed-receipt retrieval and acknowledgement.
type SettlementAdmission struct {
	Authority json.RawMessage `json:"authority"`
	Intent    json.RawMessage `json:"intent"`
	Grant     json.RawMessage `json:"grant"`
}

func (c Config) validateSettlements(owner ed25519.PublicKey, bindings map[string]bool) error {
	seen := map[string]bool{}
	for _, item := range c.Settlements {
		a, e := ingress.VerifyAuthorityDocument(item.Authority, owner)
		if e != nil {
			return ErrDenied
		}
		g, e := ingress.VerifySettlement(item.Grant, item.Authority, item.Intent, owner, time.Unix(c.NotBefore, 0))
		if e != nil || c.Node != g.Ingress || a.Revision > c.Revision || g.NotBefore > c.NotBefore || g.ExpiresUnix < c.ExpiresUnix || seen[g.ID] {
			return ErrDenied
		}
		d, ok := c.DomainByID(g.Domain)
		if !ok {
			return ErrDenied
		}
		x, _ := json.Marshal(d.Trust)
		y, _ := json.Marshal(a.Trust)
		source, found := c.NodeByID(g.Source)
		if !bytes.Equal(x, y) || !found || source.Class != "trusted" || !d.Placement.PermitsNode(g.Ingress) || !d.Placement.HasEdge(g.Source, g.Ingress, "push") {
			return ErrDenied
		}
		holder := false
		for _, id := range d.Placement.Holders {
			holder = holder || id == g.Ingress
		}
		binding := g.Domain + "/" + g.Ingress
		if !holder || bindings[binding] {
			return ErrDenied
		}
		bindings[binding] = true
		seen[g.ID] = true
	}
	return nil
}
