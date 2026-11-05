package main

import (
	"errors"
	"time"
)

// Only two bounded synthetic profiles are supported. This is not an arbitrary
// file backup interface. Each invocation selects the same profile for its kit.
type fixtureProfile struct {
	corpus  int64
	patch   int
	timeout time.Duration
}

func selectFixture(mib int) (fixtureProfile, error) {
	switch mib {
	case 32:
		return fixtureProfile{32 << 20, 32 << 10, 5 * time.Minute}, nil
	case 4096:
		return fixtureProfile{4 << 30, 8 << 20, 30 * time.Minute}, nil
	default:
		return fixtureProfile{}, errors.New("fixture-mib must be 32 or 4096")
	}
}

var activeFixture = fixtureProfile{32 << 20, 32 << 10, 5 * time.Minute}
