package control

import (
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

type compiledRoute struct {
	rule Replication
	id   string
}
type compiledUpload struct {
	domain, target string
	repair         bool
	start, expires int64
}

// Autonomy is an immutable lookup for one already verified configuration.
// Compilation does not replace owner signature or placement verification.
type Autonomy struct {
	node    string
	routes  map[string]compiledRoute
	uploads map[string]compiledUpload
}

func routeKey(domain, mode, executor, peer string) string {
	return domain + "/" + mode + "/" + executor + "/" + peer
}
func (c Config) CompileAutonomy() (*Autonomy, error) {
	a := &Autonomy{node: c.Node, routes: map[string]compiledRoute{}, uploads: map[string]compiledUpload{}}
	for _, r := range c.Replication {
		d, ok := c.DomainByID(r.Domain)
		if !ok {
			return nil, ErrDenied
		}
		key := routeKey(r.Domain, r.Mode, r.Executor(), r.Peer())
		if _, ok := a.routes[key]; ok {
			return nil, ErrDenied
		}
		a.routes[key] = compiledRoute{r, r.ID(d.Trust)}
	}
	for _, raw := range c.Uploads {
		var g upload.Delegation
		if storage.Decode(raw, &g, upload.MaxDelegation) != nil {
			return nil, ErrDenied
		}
		d, ok := c.DomainByID(g.Trust.Domain)
		if !ok {
			return nil, ErrDenied
		}
		g, e := upload.VerifyDelegation(raw, upload.Authority{Generation: d.Trust, Planner: d.Planner})
		if e != nil {
			return nil, e
		}
		id := storage.Hash(raw)
		if _, ok := a.uploads[id]; ok {
			return nil, ErrDenied
		}
		a.uploads[id] = compiledUpload{g.Trust.Domain, g.Profile.ID(), d.ExternalRepairMissing && g.AllowMissingRepair, g.StartMillis / 1000, g.ExpiresUnix}
	}
	return a, nil
}
func (a *Autonomy) Permits(j Job) bool {
	if a == nil || !storage.ID(j.Generation) || len(j.Plan) != 0 {
		return false
	}
	if j.Kind == "upload" {
		g, ok := a.uploads[j.Delegation]
		if !ok || j.Repair != "" || j.Executor != a.node || j.Peer != "" || j.PeerRevision != 0 || j.Domain != g.domain || j.Target != g.target {
			return false
		}
		if j.MissingRepair != nil {
			return g.repair && j.MissingRepair.Valid(g.start, g.expires) &&
				j.Operation == upload.RepairOperation(j.Delegation, j.Generation, *j.MissingRepair)
		}
		return j.Operation == storage.Hash([]byte(j.Delegation+"/"+j.Generation))
	}
	if j.Delegation != "" || j.Target != "" || j.MissingRepair != nil {
		return false
	}
	r, ok := a.routes[routeKey(j.Domain, j.Kind, j.Executor, j.Peer)]
	expected := storage.Hash([]byte(r.id + "/" + j.Generation))
	if j.Repair != "" {
		if !r.rule.Repair || !storage.ID(j.Repair) {
			return false
		}
		expected = storage.Hash([]byte(r.id + "/" + j.Generation + "/repair/" + j.Repair))
	}
	return ok && j.PeerRevision == r.rule.PeerRevision && j.Operation == expected
}
