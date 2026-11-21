package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (brokenBody) Close() error             { return nil }
func TestTelemetryPermanentStatusCannotBecomeRetryOnBrokenBody(t *testing.T) {
	base, _ := url.Parse("https://fixture.invalid")
	messages, _ := Encode(storage.Hash([]byte("node")), storage.Hash([]byte("domain")), fixtureRecord())
	for _, status := range []int{400, 403, 500} {
		client := &Client{base: base, http: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: brokenBody{}, Header: http.Header{}}, nil
		})}}
		out := client.Send(context.Background(), messages[0])
		if out.State != "BLOCKED" || out.Code != "PERMANENT_REJECTION" {
			t.Fatal(status, out)
		}
	}
	if retryAfter("999999999999999999999999999999999", time.Now()) != 24*time.Hour {
		t.Fatal("overflow caused rapid retry")
	}
}
