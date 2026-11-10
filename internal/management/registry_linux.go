package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const registryFormat = "outpost-management-registry-1"
const maxRegistry = 16 << 20
const maxOperations = 2048

type Receipt struct {
	Format        string `json:"format"`
	Operation     string `json:"operationId"`
	RequestDigest string `json:"requestDigest"`
	State         string `json:"state"`
	ObservedUnix  int64  `json:"observedUnix"`
	ResultDigest  string `json:"resultDigest,omitempty"`
	ErrorCode     string `json:"errorCode,omitempty"`
}
type Audit struct {
	Sequence      uint64 `json:"sequence"`
	Actor         string `json:"actor"`
	Tenant        string `json:"tenant"`
	Domain        string `json:"domain,omitempty"`
	Operation     string `json:"operationId"`
	Reason        string `json:"reason"`
	Action        string `json:"action"`
	State         string `json:"state"`
	ObservedUnix  int64  `json:"observedUnix"`
	RequestDigest string `json:"requestDigest"`
	ResultDigest  string `json:"resultDigest,omitempty"`
}
type enrollmentOperation struct {
	Receipt  Receipt `json:"receipt"`
	Audit    Audit   `json:"audit"`
	Document []byte  `json:"document"`
	Expected uint64  `json:"expectedRevision"`
}
type reportPointer struct {
	Digest             string `json:"digest"`
	Sequence           uint64 `json:"sequence"`
	ObservedUnix       int64  `json:"observedUnix"`
	EnrollmentRevision uint64 `json:"enrollmentRevision"`
	Slot               int    `json:"slot"`
}
type registryState struct {
	Format       string            `json:"format"`
	Owner        ed25519.PublicKey `json:"owner"`
	Signer       ed25519.PublicKey `json:"signer"`
	Revision     uint64            `json:"revision"`
	ObservedUnix int64             `json:"observedUnix"`
	Enrollments  map[string][]byte `json:"enrollments"`
	// Removed domains retain tenant/repository/epoch fences.
	Domains           map[string]domainFence         `json:"domains"`
	Operations        map[string]enrollmentOperation `json:"operations"`
	Reports           map[string]reportPointer       `json:"reports"`
	Configurations    map[string]configPointer       `json:"configurations"`
	ConfigOperations  map[string]configOperation     `json:"configOperations"`
	CommandOperations map[string]commandOperation    `json:"commandOperations,omitempty"`
	Resolutions       map[string]intentResolution    `json:"resolutions,omitempty"`
	LegacyCheckpoint  string                         `json:"legacyCheckpoint,omitempty"`
	JournalCopy       bool                           `json:"journalCopy,omitempty"`
	Signature         []byte                         `json:"signature,omitempty"`
}
type domainFence struct {
	Tenant     string `json:"tenant"`
	Repository string `json:"repository"`
	Epoch      uint64 `json:"epoch"`
}
type Options struct {
	Root        *os.Root
	Directory   string
	Owner       ed25519.PublicKey
	Signer      ed25519.PrivateKey
	Initialize  bool
	JournalCopy bool
	Guard       func(context.Context) error
	Admission   statefile.Admission
}
type Registry struct {
	store       *statefile.Store
	owner       ed25519.PublicKey
	signer      ed25519.PrivateKey
	guard       func(context.Context) error
	root        *os.Root
	blobs       *statefile.Store
	admission   statefile.Admission
	journalCopy bool
	// Fault is a local process-interruption hook, never request input.
	Fault func(string) error
}

type registryOpenMode uint8

const (
	registryNormal registryOpenMode = iota
	registryRepair
	registryEnableCopy
)

func Open(o Options) (*Registry, error) {
	return openRegistry(context.Background(), o, registryNormal)
}

// RecoverRegistry opens the exact repaired registry. The management service
// supplies the stopped-service lease and the admitted storage guard.
func RecoverRegistry(ctx context.Context, o Options) (*Registry, error) {
	return openRegistry(ctx, o, registryRepair)
}

// EnableRegistryJournal converts an admitted registry to journal-copy mode.
// The management service supplies the stopped-service lease and profile fence.
func EnableRegistryJournal(ctx context.Context, o Options) (*Registry, error) {
	return openRegistry(ctx, o, registryEnableCopy)
}

func openRegistry(ctx context.Context, o Options, mode registryOpenMode) (*Registry, error) {
	if mode != registryNormal && (o.Initialize || !o.JournalCopy) {
		return nil, ErrInvalid
	}
	if len(o.Owner) != 32 || len(o.Signer) != 64 || bytes.Equal(o.Owner, o.Signer.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	if o.Guard != nil {
		if e := o.Guard(ctx); e != nil {
			return nil, e
		}
	}
	root, e := localfs.Directory(o.Root, o.Directory, o.Initialize)
	if e != nil {
		return nil, e
	}
	limit := maxRegistry
	if o.JournalCopy {
		limit = maxRegistryJournal
	}
	s, e := statefile.OpenAt(root, ".", limit, false)
	if e != nil {
		root.Close()
		return nil, e
	}
	s.Admit = o.Admission
	r := &Registry{store: s, owner: append(ed25519.PublicKey(nil), o.Owner...), signer: append(ed25519.PrivateKey(nil), o.Signer...), guard: o.Guard, root: root, admission: o.Admission, journalCopy: o.JournalCopy}
	r.blobs, e = statefile.OpenAt(root, "blobs", control.MaxConfig+2<<20, o.Initialize)
	if e != nil {
		s.Close()
		root.Close()
		return nil, e
	}
	r.blobs.Admit = r.subAdmission("blobs")
	e = s.WithLock(ctx, func() error {
		if o.Initialize || !o.JournalCopy {
			if e := r.requireNoJournalCopy(); e != nil {
				return e
			}
		}
		switch mode {
		case registryRepair:
			return r.recoverRegistryJournal(ctx, false)
		case registryEnableCopy:
			return r.enableRegistryJournal(ctx)
		}
		_, e := r.load()
		if o.Initialize {
			if !errors.Is(e, os.ErrNotExist) {
				return ErrConflict
			}
			return r.save(registryState{Format: registryFormat, Owner: r.owner, Signer: r.signer.Public().(ed25519.PublicKey), Enrollments: map[string][]byte{}, Domains: map[string]domainFence{}, Operations: map[string]enrollmentOperation{}, Reports: map[string]reportPointer{}, Configurations: map[string]configPointer{}, ConfigOperations: map[string]configOperation{}})
		}
		return e
	})
	if e != nil {
		r.Close()
		return nil, e
	}
	return r, nil
}
func (r *Registry) Close() error {
	return errors.Join(r.store.Close(), r.blobs.Close(), r.root.Close())
}
func (r *Registry) subAdmission(prefix string) statefile.Admission {
	return func(name string, size int) (func(bool) error, error) {
		if e := r.check(context.Background()); e != nil {
			return nil, e
		}
		if r.admission == nil {
			return func(bool) error { return r.check(context.Background()) }, nil
		}
		done, e := r.admission(prefix+"/"+name, size)
		if e != nil {
			return nil, e
		}
		return func(ok bool) error { return errors.Join(done(ok), r.check(context.Background())) }, nil
	}
}
func (r *Registry) check(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if r.guard != nil {
		return r.guard(ctx)
	}
	return nil
}
func (r *Registry) point(p string) error {
	if r.Fault != nil {
		return r.Fault(p)
	}
	return nil
}
func (r *Registry) load() (registryState, error) {
	raw, e := r.store.Read("registry.json")
	if e != nil {
		if r.journalCopy {
			e = errors.Join(ErrRegistryJournal, e)
		}
		return registryState{}, e
	}
	s, e := validateRegistry(raw, r.owner, r.signer.Public().(ed25519.PublicKey))
	if e != nil {
		return s, e
	}
	if s.JournalCopy != r.journalCopy {
		return s, ErrRegistryJournal
	}
	if r.journalCopy {
		e = r.checkRegistryJournal(raw)
	}
	return s, e
}

// validateRegistry is shared by the live store and the keyless snapshot reader.
func validateRegistry(raw []byte, owner, signer ed25519.PublicKey) (registryState, error) {
	var s registryState
	r := &Registry{owner: owner}
	if canonical(raw, &s, maxRegistry) != nil || (s.Format != registryFormat && s.Format != resolutionFormat) || !bytes.Equal(s.Owner, r.owner) || !bytes.Equal(s.Signer, signer) || !safe(s.Revision) || !validTime(s.ObservedUnix) || s.ObservedUnix > time.Now().Unix() || s.Enrollments == nil || len(s.Enrollments) > 128 || s.Domains == nil || len(s.Domains) > 128 || s.Operations == nil || len(s.Operations) > maxOperations || s.Reports == nil || len(s.Reports) > 16384 {
		return s, ErrInvalid
	}
	sig := s.Signature
	s.Signature = nil
	raw, _ = json.Marshal(s)
	s.Signature = sig
	if !ed25519.Verify(s.Signer, append([]byte(s.Format+"\x00"), raw...), sig) {
		return s, ErrInvalid
	}
	for node, raw := range s.Enrollments {
		enrollment, e := VerifyEnrollment(raw, r.owner)
		if e != nil || node != enrollment.Node {
			return s, ErrInvalid
		}
		for _, d := range enrollment.Domains {
			f, ok := s.Domains[d.Domain]
			if !ok || f.Tenant != enrollment.Tenant || f.Repository != d.Repository || f.Epoch < d.Epoch {
				return s, ErrInvalid
			}
		}
	}
	for domain, f := range s.Domains {
		if !storage.ID(domain) || !storage.ID(f.Tenant) || !storage.ID(f.Repository) || f.Epoch == 0 || !safe(f.Epoch) {
			return s, ErrInvalid
		}
	}
	for id, o := range s.Operations {
		if !storage.ID(id) || id != o.Receipt.Operation || id != o.Audit.Operation || !storage.ID(o.Receipt.RequestDigest) || o.Receipt.RequestDigest != o.Audit.RequestDigest || o.Receipt.Format != "outpost-management-receipt-1" || !oneOf(o.Receipt.State, "ADMITTED", "COMPLETE") || o.Receipt.State != o.Audit.State || !validTime(o.Receipt.ObservedUnix) || o.Receipt.ObservedUnix > s.ObservedUnix || o.Audit.ObservedUnix != o.Receipt.ObservedUnix || o.Audit.Sequence == 0 || o.Audit.Sequence > s.Revision || !storage.ID(o.Audit.Actor) || !storage.ID(o.Audit.Tenant) || !oneOf(o.Audit.Action, "ENROLL", "REVOKE") || !oneOf(o.Audit.Reason, "INITIAL_ENROLLMENT", "POLICY_CHANGE", "REVOKE") || !safe(o.Expected) {
			return s, ErrInvalid
		}
		if _, e := VerifyEnrollment(o.Document, r.owner); e != nil {
			return s, ErrInvalid
		}
		if o.Receipt.State == "COMPLETE" && (o.Receipt.ResultDigest != storage.Hash(o.Document) || o.Audit.ResultDigest != o.Receipt.ResultDigest) {
			return s, ErrInvalid
		}
	}
	for k, p := range s.Reports {
		if !storage.ID(k) || !storage.ID(p.Digest) || p.Sequence == 0 || !safe(p.Sequence) || p.EnrollmentRevision == 0 || !safe(p.EnrollmentRevision) || !validTime(p.ObservedUnix) || p.ObservedUnix > s.ObservedUnix || p.Slot < 0 || p.Slot > 1 {
			return s, ErrInvalid
		}
	}
	if s.Configurations == nil || s.ConfigOperations == nil || len(s.Configurations) > 128 || len(s.Operations)+len(s.ConfigOperations)+len(s.CommandOperations) > maxOperations {
		return s, ErrInvalid
	}
	if e := r.validateConfigState(s); e != nil {
		return s, e
	}
	if e := r.validateCommandState(s); e != nil {
		return s, e
	}
	if e := r.validateResolutions(s); e != nil {
		return s, e
	}
	return s, nil
}
func (r *Registry) save(s registryState) error {
	if e := r.check(context.Background()); e != nil {
		return e
	}
	now := time.Now().Unix()
	if now < s.ObservedUnix || s.Revision >= MaxSafeInteger {
		return ErrInvalid
	}
	s.Revision++
	s.ObservedUnix = now
	s.JournalCopy = r.journalCopy
	s.Signature = nil
	raw, _ := json.Marshal(s)
	s.Signature = ed25519.Sign(r.signer, append([]byte(s.Format+"\x00"), raw...))
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if len(raw) > maxRegistry {
		return ErrCapacity
	}
	if r.journalCopy {
		if e = r.writeRegistryJournal(raw, s.Revision == 1); e != nil {
			return e
		}
	}
	if e = r.store.Write("registry.json", raw); e != nil {
		return e
	}
	return r.check(context.Background())
}
func scopeEnrollment(p Principal, e Enrollment) bool {
	if !p.Role("owner") {
		return false
	}
	for _, d := range e.Domains {
		if !p.Allows(e.Tenant, d.Domain) {
			return false
		}
	}
	return true
}
func (r *Registry) validateEnrollment(s registryState, p Principal, next Enrollment, expected uint64) error {
	if !scopeEnrollment(p, next) {
		return ErrDenied
	}
	oldRaw, exists := s.Enrollments[next.Node]
	if exists {
		old, e := VerifyEnrollment(oldRaw, r.owner)
		if e != nil {
			return e
		}
		if !scopeEnrollment(p, old) || old.Tenant != next.Tenant {
			return ErrDenied
		}
		if old.Revision != expected || next.Revision <= old.Revision {
			return ErrConflict
		}
	} else if expected != 0 {
		return ErrConflict
	} else if len(s.Enrollments) >= 128 {
		return ErrCapacity
	}
	count := len(s.Domains)
	for _, d := range next.Domains {
		if f, ok := s.Domains[d.Domain]; ok {
			if f.Tenant != next.Tenant || f.Repository != d.Repository || d.Epoch < f.Epoch {
				return ErrConflict
			}
		} else {
			count++
		}
	}
	if count > 128 {
		return ErrCapacity
	}
	return nil
}
func (r *Registry) ApplyEnrollment(ctx context.Context, p Principal, operation, reason string, raw []byte, expected uint64) (Receipt, error) {
	var out Receipt
	if p.Validate() != nil || !storage.ID(operation) || !oneOf(reason, "INITIAL_ENROLLMENT", "POLICY_CHANGE", "REVOKE") || !safe(expected) {
		return out, ErrInvalid
	}
	next, e := VerifyEnrollment(raw, r.owner)
	if e != nil {
		return out, e
	}
	if next.Revoked != (reason == "REVOKE") {
		return out, ErrInvalid
	}
	request, _ := json.Marshal(struct {
		Actor, Operation, Reason string
		Document                 []byte
		Expected                 uint64
	}{p.Actor, operation, reason, raw, expected})
	digest := storage.Hash(request)
	e = r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		if resolutionID(s, operation) {
			return ErrConflict
		}
		op, exists := s.Operations[operation]
		if _, used := s.ConfigOperations[operation]; used {
			return ErrConflict
		}
		if _, used := s.CommandOperations[operation]; used {
			return ErrConflict
		}
		if exists {
			if op.Receipt.RequestDigest != digest {
				return ErrConflict
			}
			if !scopeEnrollment(p, next) {
				return ErrDenied
			}
			if v, ok := s.Resolutions[operation]; ok {
				if !allowsDomains(p, next.Tenant, v.Domains) {
					return ErrDenied
				}
				out = resolutionReceipt(s, op.Receipt)
				return nil
			}
			if op.Receipt.State == "COMPLETE" {
				out = op.Receipt
				return nil
			}
		} else {
			if len(s.Operations)+len(s.ConfigOperations)+len(s.CommandOperations) >= maxOperations {
				return ErrCapacity
			}
			// Do not let a later enrollment overtake an uncertain earlier effect.
			for _, pending := range s.Operations {
				if pending.Receipt.State == "ADMITTED" && !resolved(s, pending.Receipt.Operation) {
					return ErrConflict
				}
			}
			if !next.Revoked && !next.Active(time.Now()) {
				return ErrDenied
			}
			if e := r.validateEnrollment(s, p, next, expected); e != nil {
				return e
			}
			action := "ENROLL"
			if next.Revoked {
				action = "REVOKE"
			}
			now := time.Now().Unix()
			op = enrollmentOperation{Receipt: Receipt{Format: "outpost-management-receipt-1", Operation: operation, RequestDigest: digest, State: "ADMITTED", ObservedUnix: now}, Audit: Audit{Sequence: s.Revision + 1, Actor: p.Actor, Tenant: next.Tenant, Operation: operation, Reason: reason, Action: action, State: "ADMITTED", ObservedUnix: now, RequestDigest: digest}, Document: append([]byte(nil), raw...), Expected: expected}
			s.Operations[operation] = op
			if e := r.save(s); e != nil {
				return e
			}
			if e := r.point("management-enrollment-intent-durable"); e != nil {
				return e
			}
			s, e = r.load()
			if e != nil {
				return e
			}
		}
		if e := r.validateEnrollment(s, p, next, expected); e != nil {
			return e
		}
		s.Enrollments[next.Node] = append([]byte(nil), raw...)
		for _, d := range next.Domains {
			s.Domains[d.Domain] = domainFence{next.Tenant, d.Repository, d.Epoch}
		}
		op.Receipt.State = "COMPLETE"
		op.Receipt.ObservedUnix = time.Now().Unix()
		op.Receipt.ResultDigest = storage.Hash(raw)
		op.Audit.State = "COMPLETE"
		op.Audit.ObservedUnix = op.Receipt.ObservedUnix
		op.Audit.ResultDigest = op.Receipt.ResultDigest
		s.Operations[operation] = op
		if e := r.save(s); e != nil {
			return e
		}
		if e := r.point("management-enrollment-result-durable"); e != nil {
			return e
		}
		out = op.Receipt
		return nil
	})
	return out, e
}
func (r *Registry) Enrollment(ctx context.Context, p Principal, tenant, node string) (Enrollment, error) {
	var out Enrollment
	if p.Validate() != nil || !storage.ID(tenant) || !storage.ID(node) || !p.Allows(tenant, "") {
		return out, ErrDenied
	}
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		raw, ok := s.Enrollments[node]
		if !ok {
			return ErrUnavailable
		}
		out, e = VerifyEnrollment(raw, r.owner)
		if e != nil {
			return e
		}
		if out.Tenant != tenant {
			return ErrUnavailable
		}
		for _, d := range out.Domains {
			if !p.Allows(tenant, d.Domain) {
				return ErrUnavailable
			}
		}
		return nil
	})
	return out, e
}
func (r *Registry) Audit(ctx context.Context, p Principal, tenant string, after uint64, limit int) ([]Audit, uint64, error) {
	if p.Validate() != nil || !p.Allows(tenant, "") || !p.Role("owner") && !p.Role("operator") || limit < 1 || limit > 256 {
		return nil, 0, ErrDenied
	}
	out := []Audit{}
	var revision uint64
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		revision = s.Revision
		for _, o := range s.Operations {
			a := o.Audit
			if a.Tenant != tenant || a.Sequence <= after {
				continue
			}
			enrollment, e := VerifyEnrollment(o.Document, r.owner)
			if e != nil {
				return e
			}
			visible := true
			for _, d := range enrollment.Domains {
				if !p.Allows(tenant, d.Domain) {
					visible = false
					break
				}
			}
			if visible {
				out = append(out, a)
			}
		}
		for _, o := range s.ConfigOperations {
			a := o.Audit
			if a.Tenant != tenant || a.Sequence <= after {
				continue
			}
			visible := true
			for _, domain := range o.Domains {
				if !p.Allows(tenant, domain) {
					visible = false
					break
				}
			}
			if visible {
				out = append(out, a)
			}
		}
		for _, o := range s.CommandOperations {
			if o.Audit.Tenant == tenant && o.Audit.Sequence > after && p.Allows(tenant, o.Audit.Domain) {
				out = append(out, o.Audit)
			}
		}
		for _, v := range s.Resolutions {
			if v.Audit.Tenant == tenant && v.Audit.Sequence > after && allowsDomains(p, tenant, v.Domains) {
				out = append(out, v.Audit)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
		if len(out) > limit {
			out = out[:limit]
		}
		return nil
	})
	return out, revision, e
}
