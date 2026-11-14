package ingress

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExpiredIntentCleanupOverHTTPSAfterRegistryRestart(t *testing.T) {
	f := registryNetwork(t)
	shortExpiryPayload(t, f)
	ctx := context.Background()
	f.intent.ExpiresUnix = time.Now().Unix() + expiryFixtureLifetimeSeconds
	raw, e := SignIntent(f.intent, f.options.Authority, f.options.Owner, f.writer, time.Now())
	must(t, e)
	f.options.Authority = f.fixture.options.Authority
	f.fixture.options.Intent = raw
	f.client.intent, f.client.intentRaw = f.intent, raw
	receipt, _, _ := f.complete(t)
	time.Sleep(time.Until(time.Unix(f.intent.ExpiresUnix, 0)) + 20*time.Millisecond)
	if e = f.client.Begin(ctx); !errors.Is(e, ErrDenied) {
		t.Fatal("expired intent admitted", e)
	}
	f.reopen(t)
	cleanup, e := NewCleanupClient(f.server.URL, f.options.Authority, raw, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, e)
	defer cleanup.Close()
	if e = cleanup.Begin(ctx); !errors.Is(e, ErrDenied) {
		t.Fatal("cleanup client admitted data", e)
	}
	wrong := receipt
	wrong.VerifiedAt--
	if _, e = cleanup.AcknowledgeStep(ctx, wrong); e == nil {
		t.Fatal("wrong receipt accepted")
	}
	ack, e := cleanup.AcknowledgeStep(ctx, receipt)
	must(t, e)
	if !ack.Clean || ack.Receipt != receipt {
		t.Fatal("cleanup did not complete", ack)
	}
	f.reopen(t)
	ack, e = cleanup.AcknowledgeStep(ctx, receipt)
	must(t, e)
	if !ack.Clean || ack.Receipt != receipt {
		t.Fatal("cleanup replay changed receipt", ack)
	}
	must(t, f.options.Replica.VerifyComplete(ctx, receipt.Generation))
}
