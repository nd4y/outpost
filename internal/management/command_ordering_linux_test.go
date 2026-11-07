package management

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
)

func TestManagementCommandControlPriorityPaginatesWithoutSkippingOlderWork(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	_, input, node := commandFixture(t, f)
	ctx := context.Background()
	original := input
	work := input
	work.Kind = "scrub"
	work.Generation = id("generation")
	work.Operation = id("work-first")
	_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, work)
	must(t, e)
	input.Operation = id("control-later")
	_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	work.Operation = id("work-last")
	_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, work)
	must(t, e)
	original.Kind = "resume"
	original.Operation = id("control-last")
	_, e = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, original)
	must(t, e)
	cfg := h.node.Transport.(*http.Transport).TLSClientConfig
	client, e := NewReportClient(h.server.URL, identity(f.options.Signer.Public().(ed25519.PublicKey)), f.e.Node, cfg.Certificates[0], cfg.RootCAs, time.Second)
	must(t, e)
	defer client.Close()
	cursor := ""
	want := []string{id("control-later"), id("control-last"), id("work-first"), id("work-last")}
	for _, operation := range want {
		page, e := client.Commands(ctx, f.e, f.options.Owner, 1, cursor)
		must(t, e)
		if page.Format != "outpost-management-commands-2" || len(page.Commands) != 1 {
			t.Fatal(page)
		}
		env, _, e := command.VerifyEnvelope(page.Commands[0].Document, f.options.Owner)
		must(t, e)
		if env.Request.Operation != operation || page.NextCursor == "" {
			t.Fatal("wrong order", env.Request.Operation, operation)
		}
		cursor = page.NextCursor
	}
	page, e := client.Commands(ctx, f.e, f.options.Owner, 1, cursor)
	must(t, e)
	if len(page.Commands) != 0 {
		t.Fatal("duplicate page")
	}
	all, e := client.Commands(ctx, f.e, f.options.Owner, 32, "")
	must(t, e)
	if len(all.Commands) != 4 {
		t.Fatal("missing command")
	}
	// A signed cursor issued by the old ordering cannot silently change meaning.
	old := f.r.writeCursor(all.Revision, "0", cursorBinding(node, h.base()+"/commands"))
	if _, e = f.r.CommandPage(ctx, node, f.e.Tenant, f.e.Node, 1, old, h.base()+"/commands"); !errors.Is(e, ErrConflict) {
		t.Fatal("old cursor accepted", e)
	}
}
