package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
)

func TestManagementConfigurationRelayRequiresRecipientAndScope(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "authorized"
		if foreign {
			name = "foreign-tenant"
		}
		t.Run(name, func(t *testing.T) {
			h := newHTTPFixtureWithRelay(t, true)
			f := h.f
			ctx := context.Background()
			if foreign {
				f.e.Tenant = id("foreign-tenant")
				f.p.Scopes = []Scope{{f.e.Tenant, id("domain")}}
			}
			f.enroll(t)
			c := configFixture(t, f)
			input := configurationMutation(t, f, c, "relay-config", 0)
			preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
			must(t, e)
			input.PreviewDigest = preview.CandidateDigest
			_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
			must(t, e)
			tlsConfig := h.viewer.Transport.(*http.Transport).TLSClientConfig
			key := tlsConfig.Certificates[0].PrivateKey.(ed25519.PrivateKey)
			fetcher, e := control.NewFetcher(h.server.URL, identity(f.options.Signer.Public().(ed25519.PublicKey)), identity(key.Public().(ed25519.PublicKey)), tlsConfig.Certificates[0], tlsConfig.RootCAs, time.Second)
			must(t, e)
			defer fetcher.Close()
			raw, e := fetcher.FetchFor(ctx, f.e.Node)
			if foreign {
				if e == nil {
					t.Fatal("relay grant widened tenant scope")
				}
				return
			}
			must(t, e)
			if !bytes.Equal(raw, input.Document) {
				t.Fatal("relay changed owner signature")
			}
			if _, e = fetcher.FetchFor(ctx, id("ungranted-recipient")); e == nil {
				t.Fatal("relay fetched unknown recipient")
			}
		})
	}
}
