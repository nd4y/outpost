package main

import "testing"

func TestFixtureAdmissionRejectsUnboundedSizes(t *testing.T) {
	for _, mib := range []int{-1, 0, 31, 33, 4095, 4097, 102400, 1 << 30} {
		if _, err := selectFixture(mib); err == nil {
			t.Fatalf("accepted unbounded profile %d", mib)
		}
	}
	small, err := selectFixture(32)
	if err != nil {
		t.Fatal(err)
	}
	large, err := selectFixture(4096)
	if err != nil {
		t.Fatal(err)
	}
	if large.corpus != 4<<30 || large.patch != 8<<20 || small.corpus != 32<<20 || large.timeout <= small.timeout {
		t.Fatal("invalid profile limits")
	}
}
