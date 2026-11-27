package worker

import (
	"errors"
	"testing"

	"github.com/nd4y/outpost/internal/peer"
)

func TestBootstrapPeerBodyBudgetsAreIndependentAndOptional(t *testing.T) {
	var b Bootstrap
	limits, err := b.peerBodyBudgets()
	must(t, err)
	if limits.Receive != nil || limits.Send != nil {
		t.Fatal("omitted body limits installed an allowance")
	}
	b.PeerReceiveBodyBytesPerSecond = peer.MinBodyBytesPerSecond
	limits, err = b.peerBodyBudgets()
	must(t, err)
	if limits.Receive == nil || limits.Send != nil {
		t.Fatal("receive-only configuration also changed send")
	}
	b.PeerSendBodyBytesPerSecond = 1 << 30
	limits, err = b.peerBodyBudgets()
	must(t, err)
	if limits.Receive == nil || limits.Send == nil || limits.Receive == limits.Send {
		t.Fatal("configured directions do not have independent allowances")
	}
	for _, invalid := range []Bootstrap{
		{PeerReceiveBodyBytesPerSecond: -1},
		{PeerReceiveBodyBytesPerSecond: 64 << 10},
		{PeerSendBodyBytesPerSecond: peer.MinBodyBytesPerSecond - 1},
		{PeerSendBodyBytesPerSecond: 1<<30 + 1},
	} {
		if _, err = invalid.peerBodyBudgets(); !errors.Is(err, ErrDenied) {
			t.Fatalf("accepted an invalid peer body rate: %v", err)
		}
	}
}
