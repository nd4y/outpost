package sourceagent

import (
	"math"
	"sync"
	"time"
)

// ingressDistribution allocates initial ciphertext bytes within one capture
// attempt. The weights affect neither placement nor the peer's required copy.
type ingressDistribution struct {
	mu      sync.Mutex
	rate    [2]float64
	balance int64
	pending [2]int
}

const minIngressSample = 256 << 10

func (d *ingressDistribution) reserve(size int) (holder int, debit int64) {
	return d.reservePreferred(size, -1)
}

// Prefer the stable owner for small or sequential equal-rate split writes.
// A concurrent large write can use the idle peer while that owner is occupied;
// the caller must still deliver the exact object to its required stable owner.
func (d *ingressDistribution) reservePreferred(size, preferred int) (holder int, debit int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if preferred >= 0 && size >= minIngressSample {
		defer func() { d.pending[holder]++ }()
	}

	weight := [2]int64{1, 1}
	if d.rate[0] > 0 && d.rate[1] > 0 {
		for i := range weight {
			weight[i] = max(1, int64(math.Round(min(4, d.rate[i]/d.rate[1-i]))))
		}
	}
	if preferred >= 0 && (size < minIngressSample || weight[0] == weight[1]) {
		holder = preferred
		if size >= minIngressSample && d.pending[holder] > 0 && d.pending[1-holder] == 0 {
			holder = 1 - holder
		}
		return holder, 0
	}
	// Reserving bytes before the HEAD checks keeps concurrent packs from
	// making the same decision against an unchanged balance.
	debit = int64(size) * weight[1]
	if d.balance > 0 {
		holder, debit = 1, -int64(size)*weight[0]
	}
	d.balance += debit
	return holder, debit
}

// A split reservation covers the whole accepted write and required handoff.
// Pair this with reservePreferred on every return, including failed requests.
func (d *ingressDistribution) completePreferred(holder, size int) {
	if size < minIngressSample {
		return
	}
	d.mu.Lock()
	d.pending[holder]--
	d.mu.Unlock()
}

func (d *ingressDistribution) refund(debit int64) {
	d.mu.Lock()
	d.balance -= debit
	d.mu.Unlock()
}

// Measure only sufficiently large, durably accepted PUTs. The time spent
// pulling the second copy and small fixed-overhead metadata are excluded.
func (d *ingressDistribution) observe(holder, size int, elapsed time.Duration) {
	if size < minIngressSample || elapsed <= 0 {
		return
	}
	sample := float64(size) / elapsed.Seconds()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rate[holder] == 0 {
		d.rate[holder] = sample
	} else {
		d.rate[holder] = (3*d.rate[holder] + sample) / 4
	}
}
