package telemetry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
)

func TestTelemetryOwnerScopeRevocationRenewalAndNoReplay(t *testing.T) {
	ctx := context.Background()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
	o.Owner = owner.Public().(ed25519.PublicKey)
	pub := o.Signer.Public().(ed25519.PublicKey)
	spki, _ := x509.MarshalPKIXPublicKey(pub)
	grant := management.Enrollment{Format: management.EnrollmentFormat, Tenant: storage.Hash([]byte("tenant")), Node: storage.Hash(spki), PublicKey: pub, Class: "trusted", Revision: 1, NotBefore: time.Now().Add(-time.Minute).Unix(), ExpiresUnix: time.Now().Add(time.Hour).Unix(), Domains: []management.DomainAdmission{{Domain: o.Domain, Repository: storage.Hash([]byte("repository")), Epoch: 1}}}
	raw, e := management.SignEnrollment(grant, owner)
	if e != nil {
		t.Fatal(e)
	}
	o.Enrollment = raw
	q := fixtureOpen(t, o)
	if e = q.Enqueue(ctx, 1, fixtureRecord()); e != nil {
		t.Fatal(e)
	}
	// Revocation between durable attempt and actual send is rechecked.
	grant.Revision = 2
	grant.Revoked = true
	revoked, _ := management.SignEnrollment(grant, owner)
	q.Fault = func(p string) error {
		if p == "before-send" {
			return q.Renew(ctx, revoked)
		}
		return nil
	}
	_, e = q.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { t.Fatal("revoked scope exported"); return Outcome{} }))
	if !errors.Is(e, management.ErrDenied) {
		t.Fatal(e)
	}
	o.Initialize = false
	o.Enrollment = nil
	q2 := fixtureOpen(t, o)
	s, e := q2.Status(ctx)
	if e != nil || s.EnrollmentActive || s.EnrollmentRevision != 2 || s.Pending != 1 {
		t.Fatal(s, e)
	}
	if e = q2.Renew(ctx, raw); !errors.Is(e, ErrConflict) {
		t.Fatal("old grant replay", e)
	}
	grant.Revision = 3
	grant.Revoked = false
	renewed, _ := management.SignEnrollment(grant, owner)
	if e = q2.Renew(ctx, renewed); e != nil {
		t.Fatal(e)
	}
	due(t, q2)
	s, e = q2.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { return Outcome{State: "ACCEPTED", Warning: true} }))
	if e != nil || s.Accepted != 1 || s.Warnings != 1 {
		t.Fatal(s, e)
	}
	grant.Revision = 4
	grant.Domains[0].Repository = storage.Hash([]byte("different"))
	different, _ := management.SignEnrollment(grant, owner)
	if e = q2.Renew(ctx, different); !errors.Is(e, ErrConflict) {
		t.Fatal("scope rebound", e)
	}
}
func TestTelemetryQuietEventsHeartbeatAndRejectedSample(t *testing.T) {
	ctx := context.Background()
	o := fixtureOptions(filepath.Join(t.TempDir(), "queue"))
	o.MaxItems = 1
	q := fixtureOpen(t, o)
	r := fixtureRecord()
	value := int64(0)
	r.Metrics = []Metric{{Name: "jobs_running", Value: &value}}
	emitted, e := q.Observe(ctx, r, time.Hour)
	if e != nil || !emitted {
		t.Fatal(emitted, e)
	}
	o.Initialize = false
	q2 := fixtureOpen(t, o)
	r.ObservedUnix++
	emitted, e = q2.Observe(ctx, r, time.Hour)
	if e != nil || emitted {
		t.Fatal("unchanged restart produced duplicate log", emitted, e)
	}
	r.Events[0].State = "UNAVAILABLE"
	emitted, e = q2.Observe(ctx, r, time.Hour)
	if !errors.Is(e, ErrCapacity) || emitted {
		t.Fatal(emitted, e)
	}
	for range 2 {
		if _, e = q2.Deliver(ctx, sendFunc(func(context.Context, Message) Outcome { return Outcome{State: "ACCEPTED"} })); e != nil {
			t.Fatal(e)
		}
	}
	emitted, e = q2.Observe(ctx, r, time.Hour)
	if e != nil || !emitted {
		t.Fatal("rejected transition was suppressed", emitted, e)
	}
	s, _ := q2.Status(ctx)
	if s.Cursor != 2 || s.Signal != "logs" {
		t.Fatal(s)
	}
}
