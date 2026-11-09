package sourceagent

import (
	"testing"
	"time"
)

func TestPairedIngressAdaptsInitialCiphertextBytes(t *testing.T) {
	const mib = 1 << 20
	var d ingressDistribution
	first, debit := d.reserve(mib)
	d.refund(debit)
	retry, _ := d.reserve(mib)
	d.observe(0, mib, time.Second)
	second, _ := d.reserve(mib)
	if first != 0 || retry != first || second != 1 {
		t.Fatal("warm-up or skipped transfer changed initial allocation", first, retry, second)
	}

	d.observe(1, mib, 3*time.Second)
	var delivered [2]int64
	for i := range 200 {
		size := (1 + i%4) * mib
		holder, _ := d.reserve(size)
		delivered[holder] += int64(size)
	}
	difference := delivered[0] - 3*delivered[1]
	if difference < -12*mib || difference > 4*mib {
		t.Fatal("initial bytes do not follow the measured rate ratio", delivered)
	}

	for range 16 {
		d.observe(0, mib, 30*time.Second)
		d.observe(1, mib, time.Second)
		d.observe(0, minIngressSample-1, time.Nanosecond)
	}
	var sends [2]int
	for range 100 {
		holder, _ := d.reserve(mib)
		sends[holder]++
	}
	if sends[0] < 18 || sends[0] > 22 {
		t.Fatal("allocation did not follow the new faster holder within its cap", sends)
	}
}
