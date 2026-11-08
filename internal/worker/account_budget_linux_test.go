package worker

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestBootstrapAccountBudgetRejectsInvalidPartitions(t *testing.T) {
	f := newFixture(t)
	b := boundBootstrapFixture(t, f)
	one := storage.Hash([]byte("one"))
	two := storage.Hash([]byte("two"))
	b.Credentials = map[string]string{one: filepath.Join(f.base, "first.json"), two: filepath.Join(f.base, "second.json")}
	path := filepath.Join(f.base, "worker.json")
	write := func(b Bootstrap) {
		t.Helper()
		raw, err := json.Marshal(b)
		must(t, err)
		must(t, os.WriteFile(path, raw, 0600))
	}
	write(b)
	legacy, err := LoadBootstrap(path)
	must(t, err)
	if legacy.ExternalRequestBudgets != nil {
		t.Fatal("omitted budgets changed bootstrap semantics")
	}
	for name, budgets := range map[string][]ExternalRequestBudget{
		"partial": {{Targets: []string{one}, Concurrency: 1, RequestsPerSecond: 1}},
		"duplicate": {
			{Targets: []string{one}, Concurrency: 1, RequestsPerSecond: 1},
			{Targets: []string{one, two}, Concurrency: 1, RequestsPerSecond: 1},
		},
		"unknown": {{Targets: []string{one, storage.Hash([]byte("unknown"))}, Concurrency: 1, RequestsPerSecond: 1}},
		"zero":    {{Targets: []string{one, two}, Concurrency: 0, RequestsPerSecond: 1}},
		"over":    {{Targets: []string{one, two}, Concurrency: 1, RequestsPerSecond: 1001}},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := b
			candidate.ExternalRequestBudgets = budgets
			write(candidate)
			if _, err := LoadBootstrap(path); !errors.Is(err, ErrDenied) {
				t.Fatal("invalid account partition decoded", err)
			}
			if _, _, err := candidate.Open(true); !errors.Is(err, ErrDenied) {
				t.Fatal("invalid partition bypassed load validation", err)
			}
		})
	}
	if _, err = os.Stat(b.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid bootstrap created runtime", err)
	}
}

func TestBootstrapAccountBudgetSharesSlotsRateAndBackoff(t *testing.T) {
	f := newFixture(t)
	b := boundBootstrapFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	first := teststore.New(t, teststore.Options{Kind: "s3", Namespace: storage.Hash([]byte("first-namespace")),
		Before: func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
			switch key {
			case "hold":
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return true
				}
			case "throttle":
				w.Header().Set("Retry-After", "5")
				w.WriteHeader(http.StatusTooManyRequests)
				return true
			}
			return false
		}})
	second := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte("second-namespace"))})
	other := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: storage.Hash([]byte("other-namespace"))})
	b.StorageCAFile = filepath.Join(f.base, "storage-ca.pem")
	credential := filepath.Join(f.base, "external-credential.json")
	credentialData, err := json.Marshal(map[string]any{"access": "test-worker", "secret": "ephemeral-test-secret", "expiresUnix": time.Now().Add(time.Minute).Unix()})
	must(t, err)
	must(t, os.WriteFile(credential, credentialData, 0600))
	var roots []byte
	var profiles []storage.Profile
	b.Credentials = map[string]string{}
	for _, server := range []*teststore.Server{first, second, other} {
		roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.HTTP.Certificate().Raw})...)
		p := storage.Profile{Kind: server.Options.Kind, Endpoint: server.Endpoint(), Namespace: server.Options.Namespace, MaxObjectBytes: 64 << 10, Concurrency: 2, RequestsPerSecond: 1000, Attempts: 1, TimeoutMillis: 4000, CredentialScope: "namespace", NoDelete: true}
		if p.Kind == "s3" {
			p.Region = server.Options.Region
		}
		b.Credentials[p.ID()] = credential
		profiles = append(profiles, p)
	}
	must(t, os.WriteFile(b.StorageCAFile, roots, 0600))
	b.ExternalRequestBudgets = []ExternalRequestBudget{
		{Targets: []string{profiles[0].ID(), profiles[1].ID()}, Concurrency: 1, RequestsPerSecond: 1},
		{Targets: []string{profiles[2].ID()}, Concurrency: 2, RequestsPerSecond: 1000},
	}
	raw, err := json.Marshal(b)
	must(t, err)
	path := filepath.Join(f.base, "worker.json")
	must(t, os.WriteFile(path, raw, 0600))
	b, err = LoadBootstrap(path)
	must(t, err)
	w, closeWorker, err := b.Open(true)
	must(t, err)
	defer closeWorker()
	var clients []*storage.Backend
	for _, p := range profiles {
		client, err := w.resolve(ctx, p)
		must(t, err)
		defer client.Close()
		gate, err := storage.NewRequestGate(p)
		must(t, err)
		client, err = client.WithRequestGate(gate)
		must(t, err)
		clients = append(clients, client)
	}
	done := make(chan error, 1)
	go func() { _, err := clients[0].Get(ctx, "hold"); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first authenticated request did not reach storage")
	}
	assertWaiting := func() {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		defer stop()
		if _, err := clients[1].Get(bounded, "missing"); !errors.Is(err, context.DeadlineExceeded) || second.Snapshot().Requests != 0 {
			t.Fatal("shared account allowed another target through", err)
		}
	}
	assertOtherProgress := func() {
		t.Helper()
		before := other.Snapshot().Requests
		if _, err := clients[2].Get(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) || other.Snapshot().Requests != before+1 {
			t.Fatal("another account stalled", err)
		}
	}
	assertWaiting()
	assertOtherProgress()
	close(release)
	if err = <-done; !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("first request did not finish", err)
	}
	assertWaiting()
	if _, err := clients[0].Get(ctx, "throttle"); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatal("throttle was not observed", err)
	}
	if delay := time.Until(clients[1].NextRequest()); delay < 3*time.Second {
		t.Fatal("throttle did not reach sibling namespace", delay)
	}
	assertWaiting()
	assertOtherProgress()
}
