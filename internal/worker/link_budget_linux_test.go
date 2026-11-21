package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestBootstrapLinkBudgetPacesSharedS3AndWebDAVBodyTraffic(t *testing.T) {
	f := newFixture(t)
	b := boundBootstrapFixture(t, f)
	servers := []*teststore.Server{
		teststore.New(t, teststore.Options{Kind: "s3", Namespace: storage.Hash([]byte("link-s3"))}),
		teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte("link-dav"))}),
		teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte("other-link"))}),
	}
	profiles := externalBudgetFixture(t, f, &b, servers...)
	targets := []string{profiles[0].ID(), profiles[1].ID()}
	b.ExternalRequestBudgets = []ExternalRequestBudget{
		{Targets: targets, Concurrency: 2, RequestsPerSecond: 1000},
		{Targets: []string{profiles[2].ID()}, Concurrency: 1, RequestsPerSecond: 1000},
	}
	b.ExternalLinkBudgets = []ExternalLinkBudget{{Targets: targets, BodyBytesPerSecond: 128 << 10}}
	if _, _, err := b.Open(true); !errors.Is(err, ErrDenied) {
		t.Fatal("incomplete link partition reached runtime admission", err)
	}
	b.ExternalLinkBudgets = append(b.ExternalLinkBudgets, ExternalLinkBudget{Targets: []string{profiles[2].ID()}, BodyBytesPerSecond: 1 << 30})
	groups, err := b.bodyBudgets()
	must(t, err)
	if groups[targets[0]] != groups[targets[1]] || groups[targets[0]] == groups[profiles[2].ID()] {
		t.Fatal("link partitions did not share and isolate the expected budgets")
	}
	clients := openExternalBudgetClients(t, f, b, profiles)
	data := bytes.Repeat([]byte{0x39}, 64<<10)
	key := "part-" + storage.Hash(data)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type result struct {
		index   int
		elapsed time.Duration
		counts  storage.HTTPBodyCounts
		err     error
	}
	done := make(chan result, len(clients))
	started := time.Now()
	for i, client := range clients {
		go func() {
			scoped, meter := storage.WithHTTPMeter(ctx, profiles[i])
			err := client.Put(scoped, key, data)
			done <- result{i, time.Since(started), meter.Snapshot(), err}
		}()
	}
	var shared time.Duration
	for range clients {
		r := <-done
		must(t, r.err)
		if r.index < 2 {
			shared = max(shared, r.elapsed)
		}
		n := int64(len(data))
		if r.counts.RequestBytes != n || r.counts.ResponseBytes != n || r.counts.Requests != 2 {
			t.Fatal("body pacing changed measured data", r)
		}
		got, err := os.ReadFile(servers[r.index].Path(key))
		must(t, err)
		if !bytes.Equal(got, data) {
			t.Fatal("paced upload changed stored bytes", r.index)
		}
	}
	// Two 64 KiB PUTs and readbacks consume 256 KiB from the same allowance.
	// The initial quantum and outstanding readers can make completion early.
	if shared < 1400*time.Millisecond {
		t.Fatal("shared link exceeded its configured allowance", shared)
	}
	t.Logf("two protocols shared 256 KiB of HTTP bodies in %s", shared)
}
