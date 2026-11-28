package command

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

type fixture struct {
	owner, service, node ed25519.PrivateKey
	authority            Authority
	envelope             Envelope
	raw                  []byte
	now                  time.Time
}

func id(v string) string { return storage.Hash([]byte(v)) }
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := func() ed25519.PrivateKey { _, k, e := ed25519.GenerateKey(rand.Reader); must(t, e); return k }
	f := &fixture{owner: key(), service: key(), node: key(), now: time.Now()}
	f.authority = Authority{Format: AuthorityFormat, Service: f.service.Public().(ed25519.PublicKey), Node: Identity(f.node.Public().(ed25519.PublicKey)), Tenant: id("tenant"), Domain: id("domain"), Repository: id("repository"), WriterEpoch: 1, AuthorityEpoch: 1, Kinds: []string{"pause", "resume", "retry", "scrub", "restore", "maintenance"}, NotBefore: f.now.Unix() - 60, ExpiresUnix: f.now.Unix() + 3600}
	grant, e := SignAuthority(f.authority, f.owner)
	must(t, e)
	f.envelope = Envelope{Format: EnvelopeFormat, Actor: id("operator"), Service: Identity(f.authority.Service), Node: f.authority.Node, Sequence: 1, ConfigurationDigest: id("policy"), AdmittedUnix: f.now.Unix() - 5, Request: Request{Operation: id("operation"), Reason: "OPERATOR_REQUEST", Tenant: f.authority.Tenant, Domain: f.authority.Domain, Kind: "pause", ExpectedRevision: 7, Authority: grant, ExpiresUnix: f.now.Unix() + 120}}
	f.raw, e = SignEnvelope(f.envelope, f.owner.Public().(ed25519.PublicKey), f.service)
	must(t, e)
	return f
}
func TestCommandAuthorityExactScopeSignatureAndHistoricalVerification(t *testing.T) {
	f := newFixture(t)
	owner := f.owner.Public().(ed25519.PublicKey)
	e, a, err := VerifyEnvelope(f.raw, owner)
	must(t, err)
	must(t, e.Active(f.now))
	must(t, a.Active(f.now))
	if e.Request.ExpectedRevision != 7 || a.Repository != id("repository") || a.AuthorityEpoch != 1 {
		t.Fatal("binding lost")
	}
	_, _, err = VerifyEnvelope(f.raw, f.service.Public().(ed25519.PublicKey))
	if err == nil {
		t.Fatal("service substituted owner")
	}
	for _, mutate := range []func(*Envelope){func(e *Envelope) { e.Node = id("foreign") }, func(e *Envelope) { e.Request.Tenant = id("foreign") }, func(e *Envelope) { e.Request.Domain = id("foreign") }, func(e *Envelope) { e.Request.Kind = "shell" }, func(e *Envelope) { e.Request.ExpectedRevision = 0 }, func(e *Envelope) { e.Request.ExpiresUnix = f.authority.ExpiresUnix + 1 }} {
		changed := f.envelope
		mutate(&changed)
		if _, err := SignEnvelope(changed, owner, f.service); err == nil {
			t.Fatal("signed invalid scope/request")
		}
	}
	for _, mutate := range []func(*Envelope){func(e *Envelope) { e.ConfigurationDigest = id("different-policy") }, func(e *Envelope) { e.Actor = id("forged-actor") }, func(e *Envelope) { e.Sequence++ }, func(e *Envelope) { e.Request.ExpectedRevision++ }} {
		changed := e
		mutate(&changed)
		raw, _ := json.Marshal(changed)
		if _, _, err := VerifyEnvelope(raw, owner); err == nil {
			t.Fatal("signature did not bind envelope field")
		}
	}
	raw := bytes.Replace(f.raw, []byte(`"request":`), []byte(`"path":"/private/data","request":`), 1)
	if _, _, err := VerifyEnvelope(raw, owner); err == nil {
		t.Fatal("unknown field accepted")
	}
	later := f.now.Add(2 * time.Hour)
	_, _, err = VerifyEnvelope(f.raw, owner)
	must(t, err)
	if e.Active(later) == nil || a.Active(later) == nil {
		t.Fatal("historical signature became active authority")
	}
	same := f.authority
	same.Service = f.node.Public().(ed25519.PublicKey)
	if _, err = SignAuthority(same, f.owner); err == nil {
		t.Fatal("node became its own command service")
	}
}
func TestCommandKindsRejectIrrelevantFieldsAndOpaqueSelectionConfusion(t *testing.T) {
	f := newFixture(t)
	requests := []Request{}
	for _, kind := range f.authority.Kinds {
		r := f.envelope.Request
		r.Kind = kind
		switch kind {
		case "retry":
			r.Job = id("job")
		case "scrub":
			r.Generation = id("generation")
		case "restore":
			r.Generation = id("generation")
			r.Preset = id("preset")
			r.Versions = []string{id("version")}
		case "maintenance":
			r.Reason = "OWNER_MAINTENANCE"
			r.MaintenancePermit = []byte("separately verified permit")
		}
		must(t, r.Validate(f.authority))
		requests = append(requests, r)
	}
	for _, r := range requests {
		r.Preset = "/untrusted/path"
		if r.Validate(f.authority) == nil {
			t.Fatal("path accepted as preset")
		}
	}
	r := f.envelope.Request
	r.Generation = id("unexpected-generation")
	if r.Validate(f.authority) == nil {
		t.Fatal("pause accepted irrelevant selection")
	}
	r = requests[4]
	r.Versions = append(r.Versions, r.Versions[0])
	if r.Validate(f.authority) == nil {
		t.Fatal("duplicate restore selection")
	}
	a := f.authority
	a.Kinds = []string{"retry"}
	if f.envelope.Request.Validate(a) == nil {
		t.Fatal("ungranted pause")
	}
	r = f.envelope.Request
	r.Reason = "private path or provider error"
	if r.Validate(f.authority) == nil {
		t.Fatal("arbitrary reason text accepted")
	}
}
func TestCommandAckRequiresOriginalEnvelopeActualEffectAndNodeSignature(t *testing.T) {
	f := newFixture(t)
	owner, node := f.owner.Public().(ed25519.PublicKey), f.node.Public().(ed25519.PublicKey)
	ack := Ack{Format: AckFormat, Node: f.authority.Node, Operation: f.envelope.Request.Operation, EnvelopeDigest: storage.Hash(f.raw), State: "COMPLETE", StartedUnix: f.now.Unix() - 3, ObservedUnix: f.now.Unix(), ControlRevision: 3, ResultDigest: id("applied-control-state")}
	raw, e := SignAck(ack, f.raw, owner, f.node, f.now)
	must(t, e)
	_, e = VerifyAck(raw, f.raw, owner, node, f.now)
	must(t, e)
	for _, mutate := range []func(*Ack){func(a *Ack) { a.EnvelopeDigest = id("different") }, func(a *Ack) { a.Operation = id("different") }, func(a *Ack) { a.ControlRevision = 0 }, func(a *Ack) { a.StartedUnix = 0 }, func(a *Ack) { a.ResultDigest = "" }, func(a *Ack) { a.ObservedUnix = f.now.Unix() + 1 }} {
		changed := ack
		mutate(&changed)
		if _, e = SignAck(changed, f.raw, owner, f.node, f.now); e == nil {
			t.Fatal("false completion signed")
		}
	}
	if _, e = SignAck(ack, f.raw, owner, f.service, f.now); e == nil {
		t.Fatal("service completed its own command")
	}
	failed := ack
	failed.State = "FAILED"
	failed.StartedUnix = 0
	failed.ControlRevision = 0
	failed.ResultDigest = ""
	failed.ErrorCode = "EXPIRED"
	failed.ObservedUnix = f.now.Add(2 * time.Hour).Unix()
	raw, e = SignAck(failed, f.raw, owner, f.node, f.now.Add(2*time.Hour))
	must(t, e)
	_, e = VerifyAck(raw, f.raw, owner, node, f.now.Add(2*time.Hour))
	must(t, e)
	ack.ObservedUnix = failed.ObservedUnix
	if _, e = SignAck(ack, f.raw, owner, f.node, f.now.Add(2*time.Hour)); e == nil {
		t.Fatal("completion beyond admitted deadline")
	}
}
