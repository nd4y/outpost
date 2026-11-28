package generation

const RetentionPermitFormat = "outpost-maintenance-permit-3"
const MaxRetirementMinimumCopies = 8
const maxRetentionWitnesses = 64

// RetentionCoverage binds proof of complete, pinned copies to each retirement
// candidate. A bound hold remains in force until this operation is closed.
type RetentionCoverage struct {
	MinimumCopies int                          `json:"minimumCopies"`
	Witnesses     []RetentionProtectionReceipt `json:"witnesses"`
}

func (p Permit) validRetentionCoverage() bool {
	c := p.Coverage
	if c == nil || c.MinimumCopies < 1 || c.MinimumCopies > MaxRetirementMinimumCopies ||
		len(p.Retire) == 0 || len(c.Witnesses) < len(p.Retire)*c.MinimumCopies || len(c.Witnesses) > maxRetentionWitnesses {
		return false
	}
	binding := RetirementBinding{Node: p.Window.Node, Operation: p.Operation}
	counts := make(map[string]int, len(p.Retire))
	for _, id := range p.Retire {
		counts[id] = 0
	}
	type copyID struct{ node, generation string }
	seen := make(map[copyID]bool, len(c.Witnesses))
	for _, w := range c.Witnesses {
		id := copyID{w.Node, w.Generation}
		if _, retiring := counts[w.Generation]; !retiring || seen[id] || w.State != "HELD" ||
			w.Domain != p.Domain || w.Repository != p.Repository || w.Epoch != p.Epoch ||
			w.Retirement == nil || *w.Retirement != binding || !w.valid() {
			return false
		}
		seen[id] = true
		counts[w.Generation]++
	}
	for _, count := range counts {
		if count < c.MinimumCopies {
			return false
		}
	}
	return true
}
