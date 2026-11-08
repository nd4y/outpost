package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestExternalAuditRefusesForeignScopeAndCanceledReads(t *testing.T) {
	trust := generation.Trust{Domain: Hash([]byte("audit-domain")), Repository: Hash([]byte("audit-repository")), Epoch: 1}
	server := teststore.New(t, teststore.Options{Kind: "webdav", Namespace: Hash([]byte(trust.Domain + "/" + trust.Repository))})
	b := backend(t, server)
	id := Hash([]byte("audit-checkpoint"))
	foreign := trust
	foreign.Domain = Hash([]byte("foreign"))
	if report, err := b.AuditGeneration(context.Background(), id, foreign); !errors.Is(err, ErrDenied) || report.Format != "" {
		t.Fatal("unauthorized audit produced evidence", report, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := b.AuditGeneration(ctx, id, trust)
	if !errors.Is(err, context.Canceled) || report.State != "CANCELED" || report.ExpectedObjects != nil ||
		report.VerifiedObjects != 0 || report.FailureStage != "CATALOG" || server.Snapshot().Requests != 0 {
		t.Fatal("canceled audit claimed or read data", report, err)
	}
}
