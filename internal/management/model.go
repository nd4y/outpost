// Package management implements the keyless, explicitly scoped operator plane.
// Its signed observations do not replace independent backup verification.
package management

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

const EnrollmentFormat = "outpost-management-enrollment-1"
const ReportFormat = "outpost-management-report-1"
const CommandReportFormat = "outpost-management-report-2"
const RecoveryReportFormat = "outpost-management-report-3"
const CommandFormat = "outpost-management-command-1"
const MaxEnrollment = 65536
const MaxReport = 8 << 20
const MaxSafeInteger = 9007199254740991

var ErrInvalid = errors.New("management input or state invalid")
var ErrDenied = errors.New("management operation denied")
var ErrConflict = errors.New("management revision or operation conflict")
var ErrCapacity = errors.New("management capacity reached")
var ErrUnavailable = errors.New("management observation unavailable")

type Scope struct {
	Tenant string `json:"tenant"`
	Domain string `json:"domain"`
}
type Principal struct {
	Actor  string   `json:"actor"`
	Roles  []string `json:"roles"`
	Scopes []Scope  `json:"scopes"`
}

func (p Principal) Validate() error {
	if !storage.ID(p.Actor) || len(p.Roles) == 0 || len(p.Roles) > 5 || len(p.Scopes) == 0 || len(p.Scopes) > 128 {
		return ErrInvalid
	}
	roles := map[string]bool{}
	for _, r := range p.Roles {
		if roles[r] || !oneOf(r, "owner", "operator", "viewer", "recovery", "node") {
			return ErrInvalid
		}
		roles[r] = true
	}
	scopes := map[Scope]bool{}
	for _, s := range p.Scopes {
		if !storage.ID(s.Tenant) || !storage.ID(s.Domain) || scopes[s] {
			return ErrInvalid
		}
		scopes[s] = true
	}
	return nil
}
func (p Principal) Role(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}
func (p Principal) Allows(tenant, domain string) bool {
	for _, s := range p.Scopes {
		if s.Tenant == tenant && (domain == "" || s.Domain == domain) {
			return true
		}
	}
	return false
}
func oneOf(v string, values ...string) bool {
	for _, s := range values {
		if v == s {
			return true
		}
	}
	return false
}
func validTime(n int64) bool { return n > 0 && n <= 1<<40 }
func safe(n uint64) bool     { return n <= MaxSafeInteger }
func identity(key ed25519.PublicKey) string {
	if len(key) != ed25519.PublicKeySize {
		return ""
	}
	raw, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		return ""
	}
	return storage.Hash(raw)
}
func canonical(raw []byte, out any, max int) error {
	if storage.Decode(raw, out, max) != nil {
		return ErrInvalid
	}
	again, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, again) {
		return ErrInvalid
	}
	return nil
}

type DomainAdmission struct {
	Domain     string `json:"domain"`
	Repository string `json:"repository"`
	Epoch      uint64 `json:"epoch"`
}
type Enrollment struct {
	Format      string            `json:"format"`
	Tenant      string            `json:"tenant"`
	Node        string            `json:"node"`
	PublicKey   ed25519.PublicKey `json:"publicKey"`
	Class       string            `json:"class"`
	Revision    uint64            `json:"revision"`
	NotBefore   int64             `json:"notBefore"`
	ExpiresUnix int64             `json:"expiresUnix"`
	Domains     []DomainAdmission `json:"domains"`
	Revoked     bool              `json:"revoked"`
	Signature   []byte            `json:"signature,omitempty"`
}

func (e Enrollment) Validate() error {
	if e.Format != EnrollmentFormat || !storage.ID(e.Tenant) || e.Node != identity(e.PublicKey) || !oneOf(e.Class, "trusted", "untrusted") || e.Revision == 0 || !safe(e.Revision) || !validTime(e.NotBefore) || !validTime(e.ExpiresUnix) || e.ExpiresUnix <= e.NotBefore || len(e.Domains) == 0 || len(e.Domains) > 128 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, d := range e.Domains {
		if !storage.ID(d.Domain) || !storage.ID(d.Repository) || d.Epoch == 0 || !safe(d.Epoch) || seen[d.Domain] {
			return ErrInvalid
		}
		seen[d.Domain] = true
	}
	return nil
}
func (e Enrollment) Active(now time.Time) bool {
	return !e.Revoked && now.Unix() >= e.NotBefore && now.Unix() < e.ExpiresUnix
}
func (e Enrollment) Domain(id string) (DomainAdmission, bool) {
	for _, d := range e.Domains {
		if d.Domain == id {
			return d, true
		}
	}
	return DomainAdmission{}, false
}
func SignEnrollment(e Enrollment, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != 64 || e.Validate() != nil {
		return nil, ErrInvalid
	}
	e.Signature = nil
	raw, _ := json.Marshal(e)
	e.Signature = ed25519.Sign(key, append([]byte(EnrollmentFormat+"\x00"), raw...))
	raw, err := json.Marshal(e)
	if len(raw) > MaxEnrollment {
		return nil, ErrCapacity
	}
	return raw, err
}
func VerifyEnrollment(raw []byte, owner ed25519.PublicKey) (Enrollment, error) {
	var e Enrollment
	if len(owner) != 32 || canonical(raw, &e, MaxEnrollment) != nil || e.Validate() != nil {
		return e, ErrInvalid
	}
	sig := e.Signature
	e.Signature = nil
	payload, _ := json.Marshal(e)
	e.Signature = sig
	if !ed25519.Verify(owner, append([]byte(EnrollmentFormat+"\x00"), payload...), sig) {
		return e, ErrDenied
	}
	return e, nil
}

type Space struct {
	State          string `json:"state"`
	Scope          string `json:"scope,omitempty"`
	AccountedBytes *int64 `json:"accountedBytes,omitempty"`
	LogicalBytes   *int64 `json:"logicalBytes"`
	PhysicalBytes  *int64 `json:"physicalBytes"`
	FreeBytes      *int64 `json:"freeBytes"`
	ReservedBytes  *int64 `json:"reservedBytes"`
	ObservedUnix   int64  `json:"observedUnix"`
}

func (s Space) valid(now int64) bool {
	if s.State == "UNKNOWN" {
		return s.LogicalBytes == nil && s.PhysicalBytes == nil && s.FreeBytes == nil && s.ReservedBytes == nil && s.AccountedBytes == nil && s.Scope == "" && s.ObservedUnix == 0
	}
	if s.State != "OBSERVED" || !oneOf(s.Scope, "", "VOLUME") || !validTime(s.ObservedUnix) || s.ObservedUnix > now {
		return false
	}
	for _, n := range []*int64{s.LogicalBytes, s.PhysicalBytes, s.FreeBytes, s.ReservedBytes, s.AccountedBytes} {
		if n != nil && (*n < 0 || *n > MaxSafeInteger) {
			return false
		}
	}
	return s.PhysicalBytes != nil && s.FreeBytes != nil
}

type Generation struct {
	Generation          string `json:"generation"`
	Sequence            uint64 `json:"sequence"`
	CreatedUnix         int64  `json:"createdUnix"`
	Status              string `json:"status"`
	Target              string `json:"target"`
	Verification        string `json:"verification"`
	VerifiedUnix        int64  `json:"verifiedUnix"`
	RestoreVerifiedUnix int64  `json:"restoreVerifiedUnix"`
	LogicalBytes        *int64 `json:"logicalBytes"`
	Objects             uint64 `json:"objects"`
	Pinned              bool   `json:"pinned"`
}
type Job struct {
	Operation      string `json:"operationId"`
	Domain         string `json:"domain"`
	Generation     string `json:"generation"`
	Kind           string `json:"kind"`
	Phase          string `json:"phase"`
	UpdatedUnix    int64  `json:"updatedUnix"`
	CompletedBytes *int64 `json:"completedBytes"`
	TotalBytes     *int64 `json:"totalBytes"`
	ErrorCode      string `json:"errorCode,omitempty"`
}
type Report struct {
	Format                string               `json:"format"`
	Node                  string               `json:"node"`
	Tenant                string               `json:"tenant"`
	Domain                string               `json:"domain"`
	EnrollmentRevision    uint64               `json:"enrollmentRevision"`
	Sequence              uint64               `json:"sequence"`
	ConfigurationRevision uint64               `json:"configurationRevision"`
	ObservedUnix          int64                `json:"observedUnix"`
	InventoryState        string               `json:"inventoryState,omitempty"`
	Generations           []Generation         `json:"generations"`
	Jobs                  []Job                `json:"jobs"`
	Commands              []CommandObservation `json:"commands,omitempty"`
	Space                 Space                `json:"space"`
	Signature             []byte               `json:"signature,omitempty"`
}

func stableCode(code string) bool {
	if len(code) > 48 {
		return false
	}
	for _, c := range code {
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func (r Report) Validate(e Enrollment, now time.Time) error {
	if e.Validate() != nil || (r.Format != ReportFormat && r.Format != CommandReportFormat && r.Format != RecoveryReportFormat) || r.Node != e.Node || r.Tenant != e.Tenant || r.EnrollmentRevision != e.Revision || r.Sequence == 0 || !safe(r.Sequence) || !safe(r.ConfigurationRevision) || !validTime(r.ObservedUnix) || r.ObservedUnix > now.Unix() || r.ObservedUnix < e.NotBefore || r.ObservedUnix >= e.ExpiresUnix || r.Generations == nil || r.Jobs == nil || len(r.Generations) > 256 || len(r.Jobs) > 4096 || !r.Space.valid(r.ObservedUnix) || !oneOf(r.InventoryState, "", "UNKNOWN", "OBSERVED", "UNAVAILABLE") || r.InventoryState == "UNAVAILABLE" && len(r.Generations) != 0 {
		return ErrInvalid
	}
	if _, ok := e.Domain(r.Domain); !ok {
		return ErrDenied
	}
	seen := map[string]bool{}
	if len(r.Commands) > 2048 || r.Format == ReportFormat && len(r.Commands) > 0 {
		return ErrInvalid
	}
	for _, c := range r.Commands {
		if c.Kind == "restore" && r.Format != RecoveryReportFormat || seen[c.Operation] || c.Validate(r.ObservedUnix) != nil {
			return ErrInvalid
		}
		seen[c.Operation] = true
	}
	seen = map[string]bool{}
	for _, g := range r.Generations {
		k := g.Generation + g.Target
		if !storage.ID(g.Generation) || !storage.ID(g.Target) || g.Sequence == 0 || !safe(g.Sequence) || g.LogicalBytes != nil && (*g.LogicalBytes < 0 || *g.LogicalBytes > MaxSafeInteger) || !safe(g.Objects) || !validTime(g.CreatedUnix) || g.CreatedUnix > r.ObservedUnix || !oneOf(g.Status, "INCOMPLETE", "COMPLETE", "CORRUPT", "UNAVAILABLE") || !oneOf(g.Verification, "NONE", "CIPHERTEXT", "DECRYPTED") || g.VerifiedUnix < 0 || g.VerifiedUnix > r.ObservedUnix || g.RestoreVerifiedUnix < 0 || g.RestoreVerifiedUnix > r.ObservedUnix || seen[k] {
			return ErrInvalid
		}
		if (g.Verification == "NONE") != (g.VerifiedUnix == 0) || g.RestoreVerifiedUnix > 0 && g.Verification != "DECRYPTED" {
			return ErrInvalid
		}
		seen[k] = true
	}
	seen = map[string]bool{}
	for _, j := range r.Jobs {
		if !storage.ID(j.Operation) || j.Domain != r.Domain || !storage.ID(j.Generation) || !oneOf(j.Kind, "SOURCE", "PEER", "UPLOAD", "SCRUB", "RESTORE", "MAINTENANCE") || !oneOf(j.Phase, "QUEUED", "RUNNING", "RETRY_WAIT", "PAUSED", "BLOCKED", "COMPLETE", "WITHDRAWN", "FAILED") || !validTime(j.UpdatedUnix) || j.UpdatedUnix > r.ObservedUnix || !stableCode(j.ErrorCode) || seen[j.Operation] {
			return ErrInvalid
		}
		if j.TotalBytes != nil && (*j.TotalBytes < 0 || *j.TotalBytes > MaxSafeInteger) || j.CompletedBytes != nil && (*j.CompletedBytes < 0 || *j.CompletedBytes > MaxSafeInteger) || j.TotalBytes != nil && j.CompletedBytes != nil && *j.CompletedBytes > *j.TotalBytes {
			return ErrInvalid
		}
		seen[j.Operation] = true
	}
	return nil
}
func SignReport(r Report, e Enrollment, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != 64 || identity(key.Public().(ed25519.PublicKey)) != e.Node || r.Validate(e, now) != nil {
		return nil, ErrInvalid
	}
	r.Signature = nil
	raw, _ := json.Marshal(r)
	r.Signature = ed25519.Sign(key, append([]byte(r.Format+"\x00"), raw...))
	raw, err := json.Marshal(r)
	if len(raw) > MaxReport {
		return nil, ErrCapacity
	}
	return raw, err
}
func VerifyReport(raw []byte, e Enrollment, now time.Time) (Report, error) {
	var r Report
	if canonical(raw, &r, MaxReport) != nil || r.Validate(e, now) != nil {
		return r, ErrInvalid
	}
	sig := r.Signature
	r.Signature = nil
	payload, _ := json.Marshal(r)
	r.Signature = sig
	if !ed25519.Verify(e.PublicKey, append([]byte(r.Format+"\x00"), payload...), sig) {
		return r, ErrDenied
	}
	return r, nil
}
