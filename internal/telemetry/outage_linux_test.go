package telemetry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func TestTelemetryTCPOutageReopenAndSameTargetRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const diagnostic = "private-source-name.bin https://credential.invalid/token backup-fragment"
	var reject atomic.Bool
	var requests atomic.Int32
	bodies := make(chan []byte, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/logs" || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("authenticated telemetry request contract changed")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxFrame+1))
		if err != nil || len(body) > MaxFrame {
			t.Error("invalid telemetry request body", err)
		}
		select {
		case bodies <- body:
		default:
			t.Error("unexpected duplicate request")
		}
		count := "0"
		if reject.Load() {
			count = "1"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"partialSuccess": map[string]string{"rejectedLogRecords": count, "errorMessage": diagnostic}}); err != nil {
			t.Error(err)
		}
	})
	server, client, certificate, _ := tlsFixture(t, handler)
	endpoint, address, tlsConfig := server.URL, server.Listener.Addr().String(), server.TLS.Clone()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	o.Signer = certificate.PrivateKey.(ed25519.PrivateKey)
	o.Target = peer.Identity(server.Certificate())
	o.Binding = storage.Hash([]byte(endpoint))
	o.MaxItems, o.MaxBytes = 1, 8192
	q := fixtureOpen(t, o)
	if err := q.Enqueue(ctx, 1, fixtureRecord()); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(o.Directory, "queue.json")
	maximumObservedJournalBytes := 0
	inspect := func(box *Outbox) (Status, []byte, journal) {
		t.Helper()
		status, err := box.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		var saved journal
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		if len(raw) > o.MaxBytes || status.Bytes > o.MaxBytes || len(saved.Frames) > o.MaxItems {
			t.Fatal("queue exceeded its original admitted bounds", status)
		}
		maximumObservedJournalBytes = max(maximumObservedJournalBytes, len(raw))
		encoded, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		check := func(value []byte) {
			for _, private := range []string{diagnostic, "private-source-name.bin", "credential.invalid", o.Directory, endpoint} {
				if bytes.Contains(value, []byte(private)) {
					t.Fatal("private source or remote diagnostic persisted or exported")
				}
			}
		}
		check(raw)
		check(encoded)
		for _, frame := range saved.Frames {
			for _, message := range frame.Messages {
				check(message.Body)
			}
		}
		return status, raw, saved
	}
	before, _, saved := inspect(q)
	if before.Cursor != 1 || before.Pending != 1 || len(saved.Frames) != 1 || len(saved.Frames[0].Messages) != 1 {
		t.Fatal("record was not durably admitted", before)
	}
	expectedBody := bytes.Clone(saved.Frames[0].Messages[0].Body)
	// A closed listener is a real transport outage, rather than an HTTP503 or
	// a sender stub. Preserve the selected endpoint and TLS identity for return.
	server.Close()
	client.Close()
	failed, err := q.Deliver(ctx, client)
	if err != nil || failed.Cursor != 1 || failed.Pending != 1 || failed.Accepted != 0 || failed.Attempts != 1 || failed.NotBefore == 0 || failed.Blocked != "" || failed.Digest != before.Digest || requests.Load() != 0 {
		t.Fatal("transport outage lost or falsely acknowledged accepted work", failed, err)
	}
	_, durable, _ := inspect(q)
	q.Close()
	o.Initialize = false
	reopened := fixtureOpen(t, o)
	after, reopenedRaw, _ := inspect(reopened)
	if after != failed || !bytes.Equal(durable, reopenedRaw) {
		t.Fatal("reopen changed persisted outage, cursor, request or retry deadline", failed, after)
	}
	returned := httptest.NewUnstartedServer(handler)
	returned.Listener.Close()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	returned.Listener, returned.TLS = listener, tlsConfig
	returned.StartTLS()
	t.Cleanup(returned.Close)
	if returned.URL != endpoint {
		t.Fatal("recovery substituted the admitted sink")
	}
	// Only the test's existing retry clock helper makes the retained request due.
	// Persistence above is checked before this; no wall-clock backoff is claimed.
	due(t, reopened)
	accepted, err := reopened.Deliver(ctx, client)
	if err != nil || accepted.Cursor != 1 || accepted.Pending != 0 || accepted.Accepted != 1 || accepted.Warnings != 1 || requests.Load() != 1 {
		t.Fatal("same authenticated sink did not accept the retained request", accepted, err)
	}
	if !bytes.Equal(<-bodies, expectedBody) {
		t.Fatal("outage/reopen changed the acknowledged immutable request")
	}
	inspect(reopened)
	// A remote rejection also persists only its typed disposition. Arbitrary
	// diagnostic text must not enter the queue or operator status after restart.
	reject.Store(true)
	if err := reopened.Enqueue(ctx, 2, fixtureRecord()); err != nil {
		t.Fatal(err)
	}
	blocked, err := reopened.Deliver(ctx, client)
	if err != nil || blocked.Blocked != "PARTIAL_REJECTION" || blocked.Cursor != 2 || blocked.Pending != 1 || blocked.Accepted != 1 || blocked.Warnings != 1 || requests.Load() != 2 {
		t.Fatal("remote rejection changed accepted history", blocked, err)
	}
	inspect(reopened)
	reopened.Close()
	final := fixtureOpen(t, o)
	last, _, _ := inspect(final)
	if last != blocked {
		t.Fatal("reopen lost the typed rejection or accepted history", last, blocked)
	}
	t.Logf("TELEMETRY_TCP_OUTAGE_PASS requests=%d reopens=2 cursor=%d accepted=%d pending=%d warning=%d rejected=%d maxObservedJournalBytes=%d maxBytes=%d sameTarget=true sameRequest=true remoteDiagnosticsExcluded=true", requests.Load(), last.Cursor, last.Accepted, last.Pending, last.Warnings, last.Rejected, maximumObservedJournalBytes, o.MaxBytes)
}
