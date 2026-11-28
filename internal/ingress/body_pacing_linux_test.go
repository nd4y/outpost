package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func TestIngressSharedBodyBudgetPacesReadbackAndHonorsCancellation(t *testing.T) {
	first, second := network(t, nil), network(t, nil)
	ctx := t.Context()
	const rate = 1 << 20
	budget, err := storage.NewHTTPBodyBudget(rate)
	must(t, err)
	first.client.SetPayloadBudget(budget)
	second.client.SetPayloadBudget(budget)
	payload := bytes.Repeat([]byte{0x33}, 256<<10)
	ref := filekit.Object{ID: storage.Hash(payload), Bytes: len(payload)}
	result := make(chan error, 2)
	start := time.Now()
	for _, f := range []*httpFixture{first, second} {
		go func() {
			_, err := f.client.Write(ctx, ref, payload)
			result <- err
		}()
	}
	for range 2 {
		must(t, <-result)
	}
	// Two PUTs followed by their verified GETs share the 1 MiB/s allowance.
	// Allow headroom for the first immediately available read quantum.
	if time.Since(start) < 850*time.Millisecond {
		t.Fatal("concurrent receivers did not share PUT and readback pacing")
	}
	for _, f := range []*httpFixture{first, second} {
		if f.client.UploadedBytes.Load() != int64(len(payload)) || f.client.ReadbackBytes.Load() < int64(len(payload)) {
			t.Fatal("pacing changed completed payload counters")
		}
	}

	slow, err := storage.NewHTTPBodyBudget(64 << 10)
	must(t, err)
	first.client.SetPayloadBudget(slow)
	firstRead := make([]byte, 32<<10)
	_, err = slow.PaceResponse(ctx, bytes.NewReader(firstRead)).Read(firstRead)
	must(t, err)
	metadataCtx, cancelMetadata := context.WithTimeout(ctx, 250*time.Millisecond)
	err = first.client.Check(metadataCtx, ref)
	cancelMetadata()
	must(t, err)
	readCtx, cancelRead := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = first.client.Read(readCtx, ref)
	cancelRead()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("body pacing ignored the cancelled attempt: %v", err)
	}
	originalTimeout := first.client.http.Timeout
	first.client.http.Timeout = 100 * time.Millisecond
	_, err = first.client.Read(ctx, ref)
	first.client.http.Timeout = originalTimeout
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("body pacing ignored the HTTP request deadline: %v", err)
	}
	first.client.SetPayloadBudget(budget)
	got, err := first.client.Read(ctx, ref)
	must(t, err)
	if !bytes.Equal(got, payload) {
		t.Fatal("readback retry changed the accepted object")
	}
}

func TestIngressMinimumBodyRateFitsTwoNearMaximumTLSReadbacks(t *testing.T) {
	const rate = peer.MinBodyBytesPerSecond
	const rpcTimeout = 30 * time.Second
	limits := peer.Limits{Concurrency: 1, Timeout: rpcTimeout, Attempts: 1}
	first := networkWithLimits(t, nil, limits)
	second := networkWithLimits(t, nil, limits)
	budget, err := storage.NewHTTPBodyBudget(rate)
	must(t, err)
	payload := bytes.Repeat([]byte{0x59}, filekit.MaxObject-(256<<10))
	ref := filekit.Object{ID: storage.Hash(payload), Bytes: len(payload)}
	for _, fixture := range []*httpFixture{first, second} {
		_, err := fixture.session.Write(t.Context(), ref, payload)
		must(t, err)
		fixture.client.SetPayloadBudget(budget)
	}
	ctx, cancel := context.WithTimeout(t.Context(), rpcTimeout)
	defer cancel()
	start := time.Now()
	results := make(chan error, 2)
	for _, fixture := range []*httpFixture{first, second} {
		go func() {
			got, err := fixture.client.Read(ctx, ref)
			if err == nil && (!bytes.Equal(got, payload) || fixture.client.ReadbackBytes.Load() != int64(len(payload))) {
				err = fmt.Errorf("near-maximum TLS readback returned %d unverified bytes", len(got))
			}
			results <- err
		}()
	}
	must(t, errors.Join(<-results, <-results))
	// Both replies share the minimum 1 MiB/s allowance and should take about
	// 15.5s of pacing before any additional TLS or filesystem overhead.
	if elapsed := time.Since(start); elapsed < 15*time.Second {
		t.Fatalf("two near-maximum replies bypassed the shared allowance: %s", elapsed)
	}
}
