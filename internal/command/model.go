// Package command defines bounded owner-authorized management commands. It
// contains no network client, filesystem path, data key or execution shortcut.
package command

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

const AuthorityFormat = "outpost-command-authority-1"
const EnvelopeFormat = "outpost-management-command-1"
const AckFormat = "outpost-command-ack-1"
const MaxAuthority = 64 << 10
const MaxRequest = 2 << 20
const MaxEnvelope = 3 << 20
const MaxAck = 65536
const MaxSafeInteger = 9007199254740991

var ErrInvalid = errors.New("invalid command document")
var ErrDenied = errors.New("command authority denied")
var ErrExpired = errors.New("command authority inactive")
var ErrConflict = errors.New("command conflict")

func Identity(key ed25519.PublicKey) string {
	if len(key) != 32 {
		return ""
	}
	raw, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		return ""
	}
	return storage.Hash(raw)
}
func oneOf(v string, values ...string) bool {
	for _, s := range values {
		if v == s {
			return true
		}
	}
	return false
}
func instant(n int64) bool  { return n > 0 && n <= 1<<40 }
func counter(n uint64) bool { return n > 0 && n <= MaxSafeInteger }
func Kind(v string) bool {
	return oneOf(v, "retry", "pause", "resume", "scrub", "restore", "maintenance")
}
func Reason(v string) bool {
	return oneOf(v, "OPERATOR_REQUEST", "INCIDENT_RESPONSE", "RECOVERY_DRILL", "POLICY_CHANGE", "OWNER_MAINTENANCE")
}
func code(v string) bool {
	if len(v) == 0 || len(v) > 48 {
		return false
	}
	for _, c := range v {
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

type Authority struct {
	Format         string            `json:"format"`
	Service        ed25519.PublicKey `json:"servicePublicKey"`
	Node           string            `json:"node"`
	Tenant         string            `json:"tenant"`
	Domain         string            `json:"domain"`
	Repository     string            `json:"repository"`
	WriterEpoch    uint64            `json:"writerEpoch"`
	AuthorityEpoch uint64            `json:"authorityEpoch"`
	Kinds          []string          `json:"kinds"`
	NotBefore      int64             `json:"notBefore"`
	ExpiresUnix    int64             `json:"expiresUnix"`
	Signature      []byte            `json:"signature,omitempty"`
}

func (a Authority) Validate() error {
	if a.Format != AuthorityFormat || len(a.Service) != 32 || !storage.ID(a.Node) || Identity(a.Service) == a.Node || !storage.ID(a.Tenant) || !storage.ID(a.Domain) || !storage.ID(a.Repository) || !counter(a.WriterEpoch) || !counter(a.AuthorityEpoch) || len(a.Kinds) == 0 || len(a.Kinds) > 6 || !instant(a.NotBefore) || !instant(a.ExpiresUnix) || a.ExpiresUnix <= a.NotBefore {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, k := range a.Kinds {
		if !Kind(k) || seen[k] {
			return ErrInvalid
		}
		seen[k] = true
	}
	return nil
}
func (a Authority) Active(now time.Time) error {
	if a.Validate() != nil {
		return ErrInvalid
	}
	if now.Unix() < a.NotBefore || now.Unix() >= a.ExpiresUnix {
		return ErrExpired
	}
	return nil
}
func (a Authority) Allows(kind string) bool { return oneOf(kind, a.Kinds...) }
func SignAuthority(a Authority, owner ed25519.PrivateKey) ([]byte, error) {
	if len(owner) != 64 || a.Validate() != nil || bytes.Equal(owner.Public().(ed25519.PublicKey), a.Service) {
		return nil, ErrInvalid
	}
	a.Signature = nil
	raw, _ := json.Marshal(a)
	a.Signature = ed25519.Sign(owner, append([]byte(AuthorityFormat+"\x00"), raw...))
	raw, _ = json.Marshal(a)
	if len(raw) > MaxAuthority {
		return nil, ErrInvalid
	}
	return raw, nil
}

// VerifyAuthority verifies historical provenance; Active is checked separately
// at admission/execution so expired audit records remain independently readable.
func VerifyAuthority(raw []byte, owner ed25519.PublicKey) (Authority, error) {
	var a Authority
	if len(owner) != 32 || storage.Decode(raw, &a, MaxAuthority) != nil || a.Validate() != nil || bytes.Equal(owner, a.Service) {
		return a, ErrInvalid
	}
	sig := a.Signature
	a.Signature = nil
	payload, _ := json.Marshal(a)
	a.Signature = sig
	if !ed25519.Verify(owner, append([]byte(AuthorityFormat+"\x00"), payload...), sig) {
		return a, ErrDenied
	}
	return a, nil
}

type Request struct {
	Operation         string   `json:"operationId"`
	Reason            string   `json:"reason"`
	Tenant            string   `json:"tenant"`
	Domain            string   `json:"domain"`
	Kind              string   `json:"kind"`
	ExpectedRevision  uint64   `json:"expectedConfigurationRevision"`
	Job               string   `json:"job,omitempty"`
	Generation        string   `json:"generation,omitempty"`
	Preset            string   `json:"preset,omitempty"`
	Versions          []string `json:"versions,omitempty"`
	Authority         []byte   `json:"authority"`
	MaintenancePermit []byte   `json:"maintenancePermit,omitempty"`
	ExpiresUnix       int64    `json:"expiresUnix"`
}

func (r Request) Validate(a Authority) error {
	if a.Validate() != nil || !storage.ID(r.Operation) || !Reason(r.Reason) || r.Tenant != a.Tenant || r.Domain != a.Domain || !Kind(r.Kind) || !a.Allows(r.Kind) || !counter(r.ExpectedRevision) || len(r.Authority) == 0 || len(r.Authority) > MaxAuthority || !instant(r.ExpiresUnix) || r.ExpiresUnix <= a.NotBefore || r.ExpiresUnix > a.ExpiresUnix {
		return ErrInvalid
	}
	if r.Job != "" && !storage.ID(r.Job) || r.Generation != "" && !storage.ID(r.Generation) || r.Preset != "" && !storage.ID(r.Preset) || len(r.Versions) > 256 || len(r.MaintenancePermit) > 1<<20 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, v := range r.Versions {
		if !storage.ID(v) || seen[v] {
			return ErrInvalid
		}
		seen[v] = true
	}
	switch r.Kind {
	case "retry":
		if r.Job == "" || r.Generation != "" || r.Preset != "" || len(r.Versions) > 0 || len(r.MaintenancePermit) > 0 {
			return ErrInvalid
		}
	case "pause", "resume":
		if r.Generation != "" || r.Preset != "" || len(r.Versions) > 0 || len(r.MaintenancePermit) > 0 {
			return ErrInvalid
		}
	case "scrub":
		if r.Job != "" || r.Generation == "" || r.Preset != "" || len(r.Versions) > 0 || len(r.MaintenancePermit) > 0 {
			return ErrInvalid
		}
	case "restore":
		if r.Job != "" || r.Generation == "" || r.Preset == "" || len(r.MaintenancePermit) > 0 {
			return ErrInvalid
		}
	case "maintenance":
		if r.Job != "" || r.Generation != "" || r.Preset != "" || len(r.Versions) > 0 || len(r.MaintenancePermit) == 0 || r.Reason != "OWNER_MAINTENANCE" {
			return ErrInvalid
		}
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxRequest {
		return ErrInvalid
	}
	return nil
}
func (r Request) Digest() string { raw, _ := json.Marshal(r); return storage.Hash(raw) }

type Envelope struct {
	Format              string  `json:"format"`
	Actor               string  `json:"actor"`
	Service             string  `json:"service"`
	Node                string  `json:"node"`
	Sequence            uint64  `json:"sequence"`
	ConfigurationDigest string  `json:"configurationDigest"`
	AdmittedUnix        int64   `json:"admittedUnix"`
	Request             Request `json:"request"`
	Signature           []byte  `json:"signature,omitempty"`
}

func (e Envelope) Validate(a Authority) error {
	if e.Format != EnvelopeFormat || !storage.ID(e.Actor) || e.Service != Identity(a.Service) || e.Node != a.Node || !counter(e.Sequence) || !storage.ID(e.ConfigurationDigest) || !instant(e.AdmittedUnix) || e.AdmittedUnix < a.NotBefore || e.AdmittedUnix >= e.Request.ExpiresUnix || e.Request.ExpiresUnix > e.AdmittedUnix+86400 || e.Request.Validate(a) != nil {
		return ErrInvalid
	}
	return nil
}
func (e Envelope) Active(now time.Time) error {
	if now.Unix() < e.AdmittedUnix || now.Unix() >= e.Request.ExpiresUnix {
		return ErrExpired
	}
	return nil
}
func SignEnvelope(e Envelope, owner ed25519.PublicKey, service ed25519.PrivateKey) ([]byte, error) {
	a, err := VerifyAuthority(e.Request.Authority, owner)
	if err != nil {
		return nil, err
	}
	if len(service) != 64 || !bytes.Equal(a.Service, service.Public().(ed25519.PublicKey)) || e.Validate(a) != nil {
		return nil, ErrDenied
	}
	e.Signature = nil
	raw, _ := json.Marshal(e)
	e.Signature = ed25519.Sign(service, append([]byte(EnvelopeFormat+"\x00"), raw...))
	raw, _ = json.Marshal(e)
	if len(raw) > MaxEnvelope {
		return nil, ErrInvalid
	}
	return raw, nil
}
func VerifyEnvelope(raw []byte, owner ed25519.PublicKey) (Envelope, Authority, error) {
	var e Envelope
	if storage.Decode(raw, &e, MaxEnvelope) != nil {
		return e, Authority{}, ErrInvalid
	}
	a, err := VerifyAuthority(e.Request.Authority, owner)
	if err != nil {
		return e, a, err
	}
	if e.Validate(a) != nil {
		return e, a, ErrInvalid
	}
	sig := e.Signature
	e.Signature = nil
	payload, _ := json.Marshal(e)
	e.Signature = sig
	if !ed25519.Verify(a.Service, append([]byte(EnvelopeFormat+"\x00"), payload...), sig) {
		return e, a, ErrDenied
	}
	return e, a, nil
}

type Ack struct {
	Format          string `json:"format"`
	Node            string `json:"node"`
	Operation       string `json:"operationId"`
	EnvelopeDigest  string `json:"envelopeDigest"`
	State           string `json:"state"`
	StartedUnix     int64  `json:"startedUnix"`
	ObservedUnix    int64  `json:"observedUnix"`
	ControlRevision uint64 `json:"controlRevision"`
	ResultDigest    string `json:"resultDigest,omitempty"`
	ErrorCode       string `json:"errorCode,omitempty"`
	Signature       []byte `json:"signature,omitempty"`
}

func (a Ack) Validate(e Envelope, raw []byte, now time.Time) error {
	if a.Format != AckFormat || a.Node != e.Node || a.Operation != e.Request.Operation || a.EnvelopeDigest != storage.Hash(raw) || !oneOf(a.State, "COMPLETE", "FAILED") || !instant(a.ObservedUnix) || a.ObservedUnix < e.AdmittedUnix || a.ObservedUnix > now.Unix() || a.StartedUnix < 0 || a.StartedUnix > a.ObservedUnix || a.ControlRevision > MaxSafeInteger {
		return ErrInvalid
	}
	if a.StartedUnix != 0 && (a.StartedUnix < e.AdmittedUnix || a.StartedUnix >= e.Request.ExpiresUnix) {
		return ErrInvalid
	}
	if a.State == "COMPLETE" {
		if a.StartedUnix == 0 || a.ObservedUnix >= e.Request.ExpiresUnix || !storage.ID(a.ResultDigest) || a.ErrorCode != "" || oneOf(e.Request.Kind, "pause", "resume") && a.ControlRevision == 0 {
			return ErrInvalid
		}
	} else if !code(a.ErrorCode) || a.ResultDigest != "" {
		return ErrInvalid
	}
	return nil
}
func SignAck(a Ack, envelope []byte, owner ed25519.PublicKey, node ed25519.PrivateKey, now time.Time) ([]byte, error) {
	e, _, err := VerifyEnvelope(envelope, owner)
	if err != nil {
		return nil, err
	}
	if len(node) != 64 || Identity(node.Public().(ed25519.PublicKey)) != e.Node || a.Validate(e, envelope, now) != nil {
		return nil, ErrDenied
	}
	a.Signature = nil
	raw, _ := json.Marshal(a)
	a.Signature = ed25519.Sign(node, append([]byte(AckFormat+"\x00"), raw...))
	raw, _ = json.Marshal(a)
	return raw, nil
}
func VerifyAck(raw, envelope []byte, owner, node ed25519.PublicKey, now time.Time) (Ack, error) {
	var a Ack
	e, _, err := VerifyEnvelope(envelope, owner)
	if err != nil {
		return a, err
	}
	if len(node) != 32 || Identity(node) != e.Node || storage.Decode(raw, &a, MaxAck) != nil || a.Validate(e, envelope, now) != nil {
		return a, ErrInvalid
	}
	sig := a.Signature
	a.Signature = nil
	payload, _ := json.Marshal(a)
	a.Signature = sig
	if !ed25519.Verify(node, append([]byte(AckFormat+"\x00"), payload...), sig) {
		return a, ErrDenied
	}
	return a, nil
}
