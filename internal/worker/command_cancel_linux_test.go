package worker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerCommandRunCancellationPreservesIndependentGuardFailure(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			f := newFixture(t)
			w := f.nodes[0]
			started := make(chan struct{})
			failure := errors.New("independent volume write failure")
			w.guard = func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				err := fmt.Errorf("volume admission: %w", ctx.Err())
				if mixed {
					return errors.Join(err, failure)
				}
				return errors.Join(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- w.Run(ctx) }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("guard not entered")
			}
			cancel()
			select {
			case err := <-done:
				if mixed && !errors.Is(err, failure) || !mixed && err != nil {
					t.Fatal("incorrect stop classification", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stop not joined")
			}
			w.guard = nil
		})
	}
}

func TestWorkerCommandPollCancellationPreservesIndependentGuardFailure(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			f := newFixture(t)
			w := f.nodes[0]
			f.cfg.Nodes = f.cfg.Nodes[:1]
			f.domain.Placement.Holders = []string{w.node}
			f.domain.Placement.Edges = nil
			f.config(t, 0, nil)
			_, target := f.ca.node(t)
			profile := CommandProfile{Format: CommandProfileFormat, Endpoint: "https://127.0.0.1:1", Identity: target, EnrollmentFile: filepath.Join(f.base, "enrollment.json"), PollSeconds: 5, RetrySeconds: 5, AttemptSeconds: 1}
			client, err := management.NewReportClient(profile.Endpoint, target, w.node, w.cert, w.roots, time.Second)
			must(t, err)
			defer client.Close()
			d := f.domain.Trust
			raw, err := management.SignEnrollment(management.Enrollment{Format: management.EnrollmentFormat, Tenant: storage.Hash([]byte("poll-cancel-tenant")), Node: w.node, PublicKey: w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey), Class: "trusted", Revision: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, Domains: []management.DomainAdmission{{Domain: d.Domain, Repository: d.Repository, Epoch: d.Epoch}}}, f.owner)
			must(t, err)
			started := make(chan struct{})
			failure := errors.New("independent polling volume failure")
			w.guard = func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				err := fmt.Errorf("poll admission: %w", ctx.Err())
				if mixed {
					return errors.Join(err, failure)
				}
				return errors.Join(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- w.RunCommands(ctx, profile, raw, client) }()
			select {
			case <-started:
			case err := <-done:
				t.Fatal("poll exited before guard", err)
			case <-time.After(3 * time.Second):
				t.Fatal("poll guard not entered")
			}
			cancel()
			select {
			case err := <-done:
				if mixed && !errors.Is(err, failure) || !mixed && err != nil {
					t.Fatal("incorrect poll stop classification", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("poll stop not joined")
			}
			w.guard = nil
		})
	}
}
