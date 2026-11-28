package ingress

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func TestReceiptRecoveryCapabilityCannotBecomeSettlementOrRenewIntent(t *testing.T) {
	f := shortSettlementRegistry(t)
	now := time.Now()
	ordinary := grantFor(t, f, storage.Hash([]byte("selected generation")))
	s, e := VerifySettlement(ordinary, f.options.Authority, f.fixture.options.Intent, f.options.Owner, now)
	must(t, e)
	r := ReceiptRecovery(s)
	r.Format, r.Signature = ReceiptRecoveryFormat, nil
	signed, e := SignReceiptRecovery(r, f.options.Authority, f.fixture.options.Intent, f.control, now)
	must(t, e)
	if _, e = VerifyReceiptRecovery(signed, f.options.Authority, f.fixture.options.Intent, f.options.Owner, now); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifySettlement(signed, f.options.Authority, f.fixture.options.Intent, f.options.Owner, now); e == nil {
		t.Fatal("recovery capability became settlement")
	}
	if _, e = VerifyReceiptRecovery(ordinary, f.options.Authority, f.fixture.options.Intent, f.options.Owner, now); e == nil {
		t.Fatal("settlement became local recovery authority")
	}
	var changed ReceiptRecovery
	must(t, json.Unmarshal(signed, &changed))
	changed.Format = SettlementFormat
	forged, e := json.Marshal(changed)
	must(t, e)
	if _, e = VerifySettlement(forged, f.options.Authority, f.fixture.options.Intent, f.options.Owner, now); e == nil {
		t.Fatal("format substitution crossed signature domain")
	}
	changed = ReceiptRecovery(s)
	changed.Format = ReceiptRecoveryFormat
	forged, e = json.Marshal(changed)
	must(t, e)
	if _, e = VerifyReceiptRecovery(forged, f.options.Authority, f.fixture.options.Intent, f.options.Owner, now); e == nil {
		t.Fatal("old signature accepted under recovery prefix")
	}
	if _, e = VerifyReceiptRecovery(signed, f.options.Authority, f.fixture.options.Intent, f.options.Owner, time.Unix(r.ExpiresUnix, 0)); e == nil {
		t.Fatal("expired recovery authority accepted")
	}
	changed = r
	changed.Generation = storage.Hash([]byte("substituted generation"))
	changed.Signature = bytes.Clone(s.Signature)
	forged, e = json.Marshal(changed)
	must(t, e)
	if _, e = VerifyReceiptRecovery(forged, f.options.Authority, f.fixture.options.Intent, f.options.Owner, now); e == nil {
		t.Fatal("generation substitution accepted")
	}
	if _, _, e = VerifyIntent(f.fixture.options.Intent, f.options.Authority, f.options.Owner, time.Unix(f.authority.ExpiresUnix, 0)); e == nil {
		t.Fatal("original write intent renewed")
	}
}
