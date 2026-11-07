package management

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
)

func TestManagementCommandHTTPSAdmissionPagingAckAndReservedLane(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	_, input, _ := commandFixture(t, f)
	ctx := context.Background()
	service := h.handler.(*httpService)
	// Inventory/report congestion must not consume the reserved control lane.
	for i := 0; i < cap(service.slots); i++ {
		service.slots <- struct{}{}
	}
	service.large <- struct{}{}
	status, raw := h.request(t, h.owner, "POST", h.base()+"/commands", input)
	<-service.large
	for i := 0; i < cap(service.slots); i++ {
		<-service.slots
	}
	if status != 202 {
		t.Fatalf("admission %d %s", status, raw)
	}
	var admitted Receipt
	must(t, json.Unmarshal(raw, &admitted))
	if admitted.State != "ADMITTED" {
		t.Fatal(admitted)
	}
	status, _ = h.request(t, h.viewer, "POST", h.base()+"/commands", input)
	if status != 403 {
		t.Fatal("viewer admitted", status)
	}
	cfg := h.node.Transport.(*http.Transport).TLSClientConfig
	client, e := NewReportClient(h.server.URL, identity(f.options.Signer.Public().(ed25519.PublicKey)), f.e.Node, cfg.Certificates[0], cfg.RootCAs, time.Second)
	must(t, e)
	defer client.Close()
	page, e := client.Commands(ctx, f.e, f.options.Owner, 1, "")
	must(t, e)
	if len(page.Commands) != 1 || page.NextCursor == "" {
		t.Fatal(page)
	}
	next, e := client.Commands(ctx, f.e, f.options.Owner, 1, page.NextCursor)
	must(t, e)
	if len(next.Commands) != 0 {
		t.Fatal("paging duplicate")
	}
	status, _ = h.request(t, h.owner, "GET", h.base()+"/commands", nil)
	if status != 403 {
		t.Fatal("operator read node queue", status)
	}
	status, _ = h.request(t, h.node, "GET", h.base()+"/commands?limit=33", nil)
	if status != 400 {
		t.Fatal("command limit", status)
	}
	ack := commandAck(t, f, page.Commands[0].Document)
	receipt, e := client.AcknowledgeCommand(ctx, f.e, f.options.Owner, page.Commands[0].Document, ack)
	must(t, e)
	if receipt.State != "COMPLETE" {
		t.Fatal(receipt)
	}
	if _, e = client.Commands(ctx, f.e, f.options.Owner, 1, page.NextCursor); !errors.Is(e, ErrConflict) {
		t.Fatal("stale queue cursor", e)
	}
	status, _ = h.request(t, h.owner, "POST", h.base()+"/commands", input)
	if status != 200 {
		t.Fatal("replay completion status", status)
	}
}

func TestManagementCommandClientRejectsSubstitutedEnvelopeAndFalseReceipt(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	_, input, node := commandFixture(t, f)
	ctx := context.Background()
	_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, input)
	must(t, e)
	page, e := f.r.CommandPage(ctx, node, f.e.Tenant, f.e.Node, 1, "", h.base()+"/commands")
	must(t, e)
	ack := commandAck(t, f, page.Commands[0].Document)
	for _, kind := range []string{"sequence", "signature", "receipt", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "redirect" {
					http.Redirect(w, r, h.server.URL+r.URL.Path, 307)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if kind == "receipt" {
					json.NewEncoder(w).Encode(Receipt{Format: "outpost-management-receipt-1", Operation: input.Operation, State: "COMPLETE"})
					return
				}
				bad := page
				bad.Commands = append([]QueuedCommand(nil), page.Commands...)
				if kind == "sequence" {
					bad.Commands[0].Sequence++
				} else {
					var env command.Envelope
					json.Unmarshal(bad.Commands[0].Document, &env)
					env.Signature[0] ^= 1
					bad.Commands[0].Document, _ = json.Marshal(env)
				}
				json.NewEncoder(w).Encode(bad)
			}))
			server.TLS = h.server.TLS.Clone()
			server.StartTLS()
			defer server.Close()
			cfg := h.node.Transport.(*http.Transport).TLSClientConfig
			client, e := NewReportClient(server.URL, identity(f.options.Signer.Public().(ed25519.PublicKey)), f.e.Node, cfg.Certificates[0], cfg.RootCAs, time.Second)
			must(t, e)
			defer client.Close()
			if kind == "receipt" {
				_, e = client.AcknowledgeCommand(ctx, f.e, f.options.Owner, page.Commands[0].Document, ack)
			} else {
				_, e = client.Commands(ctx, f.e, f.options.Owner, 1, "")
			}
			if e == nil {
				t.Fatal("false response accepted")
			}
		})
	}
}

func TestManagementCommandPageBoundsAggregatePayload(t *testing.T) {
	f := newFixture(t)
	_, input, node := commandFixture(t, f)
	ctx := context.Background()
	input.Kind = "maintenance"
	input.Reason = "OWNER_MAINTENANCE"
	input.MaintenancePermit = make([]byte, 1<<20)
	for _, name := range []string{"a", "b", "c", "d"} {
		input.Operation = id(name)
		_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, input)
		must(t, e)
	}
	page, e := f.r.CommandPage(ctx, node, f.e.Tenant, f.e.Node, 32, "", "commands")
	must(t, e)
	raw, e := json.Marshal(page)
	must(t, e)
	if len(page.Commands) == 0 || len(page.Commands) >= 4 || len(raw) > MaxCommandPage {
		t.Fatal("unbounded aggregate response", len(page.Commands), len(raw))
	}
	next, e := f.r.CommandPage(ctx, node, f.e.Tenant, f.e.Node, 32, page.NextCursor, "commands")
	must(t, e)
	if len(next.Commands)+len(page.Commands) != 4 {
		t.Fatal("page truncation lost commands")
	}
}
