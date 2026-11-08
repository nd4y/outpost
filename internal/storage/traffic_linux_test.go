package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/nd4y/outpost/internal/teststore"
)

func TestHTTPMeterCountsRetriesAndDoesNotMixOperations(t *testing.T) {
	var lost atomic.Bool
	s := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: Hash([]byte("transfer-meter")), AfterWrite: func(w http.ResponseWriter, r *http.Request, _, _ string, _ []byte) bool {
		if r.Method == http.MethodPut && lost.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	}})
	b := backend(t, s)
	ctx, meter := WithHTTPMeter(context.Background(), b.Profile())
	data := bytes.Repeat([]byte{14}, 8192)
	key := "part-" + Hash(data)
	if err := b.Put(ctx, key, data); err != nil {
		t.Fatal(err)
	}
	otherCtx, other := WithHTTPMeter(context.Background(), b.Profile())
	if _, err := b.Get(otherCtx, key); err != nil {
		t.Fatal(err)
	}
	n := int64(len(data))
	got := meter.Snapshot()
	if got.Requests != 3 || got.PutRequests != 2 || got.GetRequests != 1 || got.RequestBytes != 2*n || got.ObjectRequestBytes != 2*n || got.RepeatedRequestBytes != n || got.ResponseBytes != n || got.ObjectResponseBytes != n {
		t.Fatal("wrong observed retry or body counts", got)
	}
	if second := other.Snapshot(); second.Requests != 1 || second.RequestBytes != 0 || second.ResponseBytes != n {
		t.Fatal("unrelated operation changed counters", second)
	}
}

func TestHTTPMeterDistinguishesWebDAVStagingAndFinalReadback(t *testing.T) {
	s := teststore.New(t, teststore.Options{Kind: "webdav", MoveOnly: true, Namespace: Hash([]byte("move-meter"))})
	b, options := moveBackend(t, s)
	budget, err := NewHTTPBodyBudget(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	b, err = b.WithHTTPBodyBudget(budget)
	if err != nil {
		t.Fatal(err)
	}
	book := openMoveTest(t, options)
	defer book.Close()
	ctx := WithWriteAttempts(context.Background(), book)
	if err := b.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	ctx, meter := WithHTTPMeter(ctx, b.Profile())
	data := bytes.Repeat([]byte{7}, 8192)
	key := "part-" + Hash(data)
	if err := b.Put(ctx, key, data); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, key); err != nil {
		t.Fatal(err)
	}
	n := int64(len(data))
	got := meter.Snapshot()
	if got.Requests != 6 || got.GetRequests != 4 || got.PutRequests != 1 || got.MoveRequests != 1 || got.RequestBytes != n || got.ObjectRequestBytes != n || got.RepeatedRequestBytes != 0 || got.ResponseBytes != 3*n || got.StagingResponseBytes != n || got.ObjectResponseBytes != 2*n {
		t.Fatal("staging and final readback counts were confused", got)
	}
}

type meterRoundTripFunc func(*http.Request) (*http.Response, error)

func (f meterRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPMeterMeasuresPartialReadsAndTransportBodyReplays(t *testing.T) {
	s := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: Hash([]byte("partial-meter"))})
	b := backend(t, s)
	budget, err := NewHTTPBodyBudget(64 << 10)
	if err != nil {
		t.Fatal(err)
	}
	b, err = b.WithHTTPBodyBudget(budget)
	if err != nil {
		t.Fatal(err)
	}
	b.profile.Attempts = 1
	b.client.Transport = meterRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if _, err := io.ReadFull(r.Body, make([]byte, 2)); err != nil {
			return nil, err
		}
		if err := r.Body.Close(); err != nil {
			return nil, err
		}
		body, err := r.GetBody()
		if err != nil {
			return nil, err
		}
		defer body.Close()
		if _, err = io.ReadFull(body, make([]byte, 3)); err != nil {
			return nil, err
		}
		return nil, errors.New("synthetic transport interruption")
	})
	ctx, meter := WithHTTPMeter(context.Background(), b.Profile())
	data := bytes.Repeat([]byte{4}, 8192)
	if _, _, err := b.request(ctx, http.MethodPut, "part-"+Hash(data), data); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expected transport failure", err)
	}
	got := meter.Snapshot()
	if got.Incomplete || got.Requests != 1 || got.RequestBytes != 5 || got.ObjectRequestBytes != 5 || got.RepeatedRequestBytes != 2 || got.ResponseBytes != 0 {
		t.Fatal("unconsumed bytes counted as transferred", got)
	}
}
