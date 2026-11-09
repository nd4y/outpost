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
}

const minIngressSample = 256 << 10

func (d *ingressDistribution) reserve(size int) (holder int, debit int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	weight := [2]int64{1, 1}
	if d.rate[0] > 0 && d.rate[1] > 0 {
		for i := range weight {
			weight[i] = max(1, int64(math.Round(min(4, d.rate[i]/d.rate[1-i]))))
		}
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
