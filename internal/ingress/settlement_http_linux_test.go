package ingress

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
)

func shortSettlementRegistry(t *testing.T) *registryFixture {
	t.Helper()
	f := registryNetwork(t)
	shortExpiryPayload(t, f)
	must(t, f.source.Close())
	f.source = nil
	f.client.Close()
	must(t, f.registry.Close())
	f.registry = nil
	// Fixture construction, before any operation is admitted. The completed
	// historical slot below is always reopened at this same directory.
	f.authority.ExpiresUnix = time.Now().Unix() + expiryFixtureLifetimeSeconds
	authority, e := SignAuthority(f.authority, f.control)
	must(t, e)
	f.intent.Authority = storage.Hash(authority)
	f.intent.ExpiresUnix = f.authority.ExpiresUnix
	intent, e := SignIntent(f.intent, authority, f.options.Owner, f.writer, time.Now())
	must(t, e)
	f.fixture.options.Authority = authority
	f.fixture.options.Intent = intent
	f.options.Authority = authority
	f.options.Directory = filepath.Join(f.base, "settlement-registry")
	f.registry, e = OpenRegistry(context.Background(), f.options)
	must(t, e)
	f.client, e = NewClient(f.server.URL, authority, intent, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, e)
	t.Cleanup(f.client.Close)
	f.source, e = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, f.client)
	must(t, e)
	return f
}

// This is preparation headroom for a test grant, not a product TTL or request
// timeout. Each expiry scenario waits for the actual signed deadline before
// exercising the historical operation and proving payload access is refused.
const expiryFixtureLifetimeSeconds = 30

// Expiry tests exercise a real nonempty encrypted file and durable publication
// without also benchmarking multi-MiB encryption under -race. Prepare it before
// starting the test grant; large-file behavior has its own acceptance profile.
func shortExpiryPayload(t *testing.T, f *registryFixture) {
	t.Helper()
	f.payload = f.payload[:32<<10]
	must(t, os.WriteFile(f.input, f.payload, 0600))
}

func grantFor(t *testing.T, f *registryFixture, generation string) []byte {
	t.Helper()
	i := f.intent
	g := Settlement{Format: SettlementFormat, ID: storage.Hash([]byte("settlement-request")), Authority: i.Authority, Intent: storage.Hash(f.fixture.options.Intent), Operation: i.Operation, Source: i.Source, Ingress: i.Ingress, Tenant: i.Tenant, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Generation: generation, NotBefore: time.Now().Unix() - 1, ExpiresUnix: time.Now().Unix() + 300}
	raw, e := SignSettlement(g, f.options.Authority, f.fixture.options.Intent, f.control, time.Now())
	must(t, e)
	return raw
}

func provisionSettlement(t *testing.T, f *registryFixture, grant []byte) *Client {
	t.Helper()
	must(t, f.registry.Close())
	f.registry = nil
	f.options.Initialize = false
	f.options.Settlement = grant
	f.options.SettlementIntent = f.fixture.options.Intent
	var e error
	f.registry, e = OpenRegistry(context.Background(), f.options)
	must(t, e)
	c, e := NewSettlementClient(f.server.URL, f.options.Authority, f.fixture.options.Intent, grant, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, e)
	t.Cleanup(c.Close)
	return c
}

func TestSettlementHTTPSReopensExpiredAuthorityAndKeepsOriginalReceipt(t *testing.T) {
	f := shortSettlementRegistry(t)
	ctx := context.Background()
	receipt, _, _ := f.complete(t)
	grant := grantFor(t, f, receipt.Generation)
	time.Sleep(time.Until(time.Unix(f.authority.ExpiresUnix, 0)) + 20*time.Millisecond)
	if _, e := NewClient(f.server.URL, f.options.Authority, f.fixture.options.Intent, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits); !errors.Is(e, ErrDenied) {
		t.Fatal("expired payload client", e)
	}
	must(t, f.registry.Close())
	f.registry = nil
	f.options.Initialize = false
	if g, e := OpenRegistry(ctx, f.options); e == nil {
		g.Close()
		t.Fatal("expired registry opened without fresh purpose")
	}
	// Provision directly after the negative reopen, retaining exactly the old
	// registry and generation. No replacement slot or new receiver is created.
	f.options.Settlement = grant
	f.options.SettlementIntent = f.fixture.options.Intent
	var e error
	f.registry, e = OpenRegistry(ctx, f.options)
	must(t, e)
	c, e := NewSettlementClient(f.server.URL, f.options.Authority, f.fixture.options.Intent, grant, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, e)
	defer c.Close()
	got, e := c.SettlementReceipt(ctx)
	must(t, e)
	if got != receipt {
		t.Fatal("receipt or original verification time changed")
	}
	if e = c.Begin(ctx); !errors.Is(e, ErrDenied) {
		t.Fatal("settlement allowed Begin", e)
	}
	if _, _, _, e = c.request(ctx, http.MethodPut, "catalog", nil, []byte("payload"), 4096); !errors.Is(e, ErrDenied) {
		t.Fatal("settlement allowed catalog", e)
	}
	// Bypass the client's purpose check to prove the receiver also refuses it.
	u := *c.endpoint
	u.Path = route(c.intent) + "/catalog"
	request, e := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), http.NoBody)
	must(t, e)
	request.Header.Set("Outpost-Authority", c.intent.Authority)
	request.Header.Set("Outpost-Settlement", storage.Hash(grant))
	response, e := c.http.Do(request)
	must(t, e)
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("receiver admitted payload", response.StatusCode)
	}
	wrong := receipt
	wrong.VerifiedAt--
	if _, e = c.AcknowledgeStep(ctx, wrong); !errors.Is(e, ErrDenied) {
		t.Fatal("changed receipt acknowledged", e)
	}
	ack, e := c.AcknowledgeStep(ctx, receipt)
	must(t, e)
	if !ack.Clean || ack.Receipt != receipt {
		t.Fatal("wrong cleanup result")
	}
	f.reopen(t)
	got, e = c.SettlementReceipt(ctx)
	must(t, e)
	if got != receipt {
		t.Fatal("restart changed original receipt")
	}
	ack, e = c.AcknowledgeStep(ctx, receipt)
	must(t, e)
	if !ack.Clean || ack.Receipt != receipt {
		t.Fatal("cleanup replay changed result")
	}
	must(t, f.options.Replica.VerifyComplete(ctx, receipt.Generation))
}

func TestSettlementHTTPSNeverCreatesReceiptOrHistoricalSlot(t *testing.T) {
	f := registryNetwork(t)
	ctx := context.Background()
	must(t, f.client.Begin(ctx))
	grant := grantFor(t, f, storage.Hash([]byte("unpublished-generation")))
	bad := f.options
	bad.Directory = filepath.Join(f.base, "must-not-create")
	bad.Settlement = grant
	bad.SettlementIntent = f.fixture.options.Intent
	if g, e := OpenRegistry(ctx, bad); !errors.Is(e, ErrDenied) {
		if g != nil {
			g.Close()
		}
		t.Fatal("historical initialize accepted", e)
	}
	if _, e := os.Stat(bad.Directory); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("created historical slot", e)
	}
	c := provisionSettlement(t, f, grant)
	if _, e := c.SettlementReceipt(ctx); e == nil {
		t.Fatal("unpublished receipt invented")
	}
	if f.registry.session != nil && f.registry.session.state.Complete {
		t.Fatal("unpublished session promoted")
	}
	if _, e := c.AcknowledgeStep(ctx, Receipt{Operation: f.intent.Operation, Generation: storage.Hash([]byte("unpublished-generation"))}); e == nil {
		t.Fatal("unknown publication acknowledged")
	}
}

func TestSettlementHTTPSRequiresProvisionedExactGrantAndCurrentOwner(t *testing.T) {
	f := registryNetwork(t)
	ctx := context.Background()
	receipt, _, _ := f.complete(t)
	grant := grantFor(t, f, receipt.Generation)
	c := provisionSettlement(t, f, grant)
	other := grantFor(t, f, storage.Hash([]byte("wrong-generation")))
	wrong, e := NewSettlementClient(f.server.URL, f.options.Authority, f.fixture.options.Intent, other, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, e)
	defer wrong.Close()
	if _, e = wrong.SettlementReceipt(ctx); !errors.Is(e, ErrDenied) {
		t.Fatal("unprovisioned grant accepted", e)
	}
	got, e := c.SettlementReceipt(ctx)
	must(t, e)
	if got != receipt {
		t.Fatal("denial changed receipt")
	}
	if _, e = VerifySettlement(grant, f.options.Authority, f.fixture.options.Intent, ed25519.PublicKey(make([]byte, 32)), time.Now()); !errors.Is(e, ErrDenied) {
		t.Fatal("untrusted current owner", e)
	}
	bad := f.options
	bad.SettlementIntent = append([]byte(nil), bad.SettlementIntent...)
	bad.SettlementIntent[len(bad.SettlementIntent)-3] ^= 1
	if g, e := OpenRegistry(ctx, bad); !errors.Is(e, ErrDenied) {
		if g != nil {
			g.Close()
		}
		t.Fatal("changed historical slot accepted", e)
	}
}
