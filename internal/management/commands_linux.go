package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

type commandOperation struct {
	Receipt         Receipt               `json:"receipt"`
	Audit           Audit                 `json:"audit"`
	Node            string                `json:"node"`
	NodeKey         ed25519.PublicKey     `json:"nodePublicKey"`
	Request         string                `json:"request"`
	Configuration   string                `json:"configuration"`
	Envelope        string                `json:"envelope,omitempty"`
	Acknowledgement []byte                `json:"acknowledgement,omitempty"`
	Retention       *retentionCommandLink `json:"retention,omitempty"`
}

func commandRole(p Principal, kind string) bool {
	if p.Role("owner") {
		return true
	}
	if kind == "restore" {
		return p.Role("recovery")
	}
	return kind != "maintenance" && kind != "retention" && p.Role("operator")
}
func commandRequestDigest(p Principal, node string, input command.Request) string {
	raw, _ := json.Marshal(struct {
		Actor, Node string
		Request     command.Request
	}{p.Actor, node, input})
	return storage.Hash(raw)
}
func (r *Registry) commandBlob(kind, digest string, raw []byte) error {
	if !oneOf(kind, "request", "envelope") || !storage.ID(digest) || storage.Hash(raw) != digest {
		return ErrInvalid
	}
	name := "command-" + kind + "-" + digest + ".json"
	existing, e := r.blobs.Read(name)
	if e == nil {
		if !bytes.Equal(existing, raw) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return r.blobs.Write(name, raw)
}
func (r *Registry) commandRequest(o commandOperation) (command.Request, command.Authority, error) {
	var input command.Request
	raw, e := r.blobs.Read("command-request-" + o.Request + ".json")
	if e != nil {
		return input, command.Authority{}, e
	}
	if storage.Hash(raw) != o.Request || storage.Decode(raw, &input, command.MaxRequest) != nil {
		return input, command.Authority{}, ErrInvalid
	}
	a, e := command.VerifyAuthority(input.Authority, r.owner)
	if e != nil || input.Validate(a) != nil || a.Node != o.Node || command.Identity(a.Service) != identity(r.signer.Public().(ed25519.PublicKey)) || input.Operation != o.Receipt.Operation || input.Tenant != o.Audit.Tenant || input.Domain != o.Audit.Domain || input.Reason != o.Audit.Reason || "COMMAND_"+strings.ToUpper(input.Kind) != o.Audit.Action || commandRequestDigest(Principal{Actor: o.Audit.Actor}, o.Node, input) != o.Receipt.RequestDigest {
		return input, a, ErrInvalid
	}
	return input, a, nil
}
func (r *Registry) readCommand(o commandOperation) ([]byte, command.Envelope, error) {
	var envelope command.Envelope
	if o.Envelope == "" {
		return nil, envelope, ErrUnavailable
	}
	raw, e := r.blobs.Read("command-envelope-" + o.Envelope + ".json")
	if e != nil {
		return nil, envelope, e
	}
	envelope, _, e = command.VerifyEnvelope(raw, r.owner)
	if e != nil || storage.Hash(raw) != o.Envelope || envelope.Node != o.Node || envelope.Actor != o.Audit.Actor || envelope.ConfigurationDigest != o.Configuration || envelope.Sequence != o.Audit.Sequence || envelope.AdmittedUnix != o.Audit.ObservedUnix || envelope.Request.Digest() != o.Request {
		return nil, envelope, ErrInvalid
	}
	return raw, envelope, nil
}
func (r *Registry) validateCommandState(s registryState) error {
	for id, o := range s.CommandOperations {
		_, enrollment := s.Operations[id]
		_, configuration := s.ConfigOperations[id]
		if enrollment || configuration || !storage.ID(id) || id != o.Receipt.Operation || id != o.Audit.Operation || !storage.ID(o.Node) || command.Identity(o.NodeKey) != o.Node || !storage.ID(o.Request) || !storage.ID(o.Configuration) || o.Envelope != "" && !storage.ID(o.Envelope) || o.Receipt.Format != "outpost-management-receipt-1" || !oneOf(o.Receipt.State, "ADMITTED", "COMPLETE", "FAILED") || o.Audit.State != o.Receipt.State || !storage.ID(o.Receipt.RequestDigest) || o.Audit.RequestDigest != o.Receipt.RequestDigest || !storage.ID(o.Audit.Actor) || !storage.ID(o.Audit.Tenant) || !storage.ID(o.Audit.Domain) || !command.Reason(o.Audit.Reason) || !strings.HasPrefix(o.Audit.Action, "COMMAND_") || !command.Kind(strings.ToLower(strings.TrimPrefix(o.Audit.Action, "COMMAND_"))) || o.Audit.Sequence == 0 || o.Audit.Sequence > s.Revision || !validTime(o.Audit.ObservedUnix) || o.Audit.ObservedUnix > s.ObservedUnix || !validTime(o.Receipt.ObservedUnix) || o.Receipt.ObservedUnix < o.Audit.ObservedUnix || o.Receipt.ObservedUnix > s.ObservedUnix || len(o.Acknowledgement) > command.MaxAck {
			return ErrInvalid
		}
		if o.Retention != nil && !o.Retention.valid(o) {
			return ErrInvalid
		}
		if o.Receipt.State == "ADMITTED" {
			if len(o.Acknowledgement) != 0 || o.Receipt.ResultDigest != "" || o.Audit.ResultDigest != "" || o.Receipt.ErrorCode != "" || o.Receipt.ObservedUnix != o.Audit.ObservedUnix {
				return ErrInvalid
			}
		} else if o.Envelope == "" || len(o.Acknowledgement) == 0 || o.Receipt.ResultDigest != storage.Hash(o.Acknowledgement) || o.Audit.ResultDigest != o.Receipt.ResultDigest || o.Receipt.State == "COMPLETE" && o.Receipt.ErrorCode != "" || o.Receipt.State == "FAILED" && (o.Receipt.ErrorCode == "" || !stableCode(o.Receipt.ErrorCode)) {
			return ErrInvalid
		}
	}
	return nil
}
func (r *Registry) admitCommandPolicy(ctx context.Context, s registryState, p Principal, tenant, node string, input command.Request) (Enrollment, string, error) {
	var enrollment Enrollment
	if p.Validate() != nil || input.Tenant != tenant || !p.Allows(tenant, input.Domain) || !commandRole(p, input.Kind) {
		return enrollment, "", ErrDenied
	}
	enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
	if e != nil || enrollment.Tenant != tenant || !enrollment.Active(time.Now()) {
		return enrollment, "", ErrDenied
	}
	admitted, ok := enrollment.Domain(input.Domain)
	fence := s.Domains[input.Domain]
	if !ok || fence.Tenant != tenant || fence.Repository != admitted.Repository || fence.Epoch != admitted.Epoch {
		return enrollment, "", ErrDenied
	}
	for _, pending := range s.Operations {
		if pending.Receipt.State == "ADMITTED" && !resolved(s, pending.Receipt.Operation) {
			next, e := VerifyEnrollment(pending.Document, r.owner)
			if e != nil {
				return enrollment, "", e
			}
			if next.Node == node {
				return enrollment, "", ErrConflict
			}
		}
	}
	cfg, raw, e := r.configuration(ctx, s, node)
	if e != nil {
		return enrollment, "", e
	}
	if cfg.Revision != input.ExpectedRevision {
		return enrollment, "", ErrConflict
	}
	a, e := cfg.CommandAuthority(input.Authority, r.owner, time.Now())
	if e != nil || input.Validate(a) != nil || a.Tenant != tenant || command.Identity(a.Service) != identity(r.signer.Public().(ed25519.PublicKey)) || input.ExpiresUnix <= time.Now().Unix() || input.ExpiresUnix > cfg.ExpiresUnix || input.ExpiresUnix > time.Now().Unix()+86400 {
		return enrollment, "", ErrDenied
	}
	if plan, exists := s.RetentionPlans[input.Operation]; exists {
		if hasPlannedClose(s, plan.Plan.Tenant, plan.Plan.Request.Preview) {
			return enrollment, "", ErrConflict
		}
		permit, err := cfg.MaintenancePermit(input)
		if err != nil || !plan.matches(tenant, node, input, permit) {
			return enrollment, "", ErrConflict
		}
		if _, err = generation.VerifyPermit(input.MaintenancePermit, plan.Trust); err != nil {
			return enrollment, "", ErrConflict
		}
	}
	if input.Kind == "retention" {
		grant, e := cfg.RetentionProtection(input)
		if e != nil || enrollment.Class != "trusted" {
			return enrollment, "", ErrDenied
		}
		if e = admitRetentionLink(s, node, input, grant); e != nil {
			return enrollment, "", e
		}
	}
	return enrollment, storage.Hash(raw), nil
}

// AdmitCommand persists the original actor/policy/request intent before it
// publishes a signed envelope. ADMITTED never claims that the node executed it.
func (r *Registry) AdmitCommand(ctx context.Context, p Principal, tenant, node string, input command.Request) (Receipt, error) {
	var out Receipt
	if !storage.ID(node) || !storage.ID(tenant) || !storage.ID(input.Operation) {
		return out, ErrInvalid
	}
	digest := commandRequestDigest(p, node, input)
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		if resolutionID(s, input.Operation) {
			return ErrConflict
		}
		if _, used := s.Operations[input.Operation]; used {
			return ErrConflict
		}
		if _, used := s.ConfigOperations[input.Operation]; used {
			return ErrConflict
		}
		if p.Validate() != nil || !p.Allows(tenant, input.Domain) || input.Tenant != tenant || !commandRole(p, input.Kind) {
			return ErrDenied
		}
		o, exists := s.CommandOperations[input.Operation]
		if exists {
			if o.Node != node || o.Receipt.RequestDigest != digest {
				return ErrConflict
			}
			if resolved(s, input.Operation) {
				out = resolutionReceipt(s, o.Receipt)
				return nil
			}
			if _, _, e := r.commandRequest(o); e != nil {
				return e
			}
			if o.Envelope != "" {
				if _, _, e := r.readCommand(o); e != nil {
					return e
				}
				out = o.Receipt
				return nil
			}
		}
		enrollment, configuration, e := r.admitCommandPolicy(ctx, s, p, tenant, node, input)
		if e != nil {
			return e
		}
		if !exists {
			if len(s.Operations)+len(s.ConfigOperations)+len(s.CommandOperations) >= maxOperations {
				return ErrCapacity
			}
			request, _ := json.Marshal(input)
			requestID := storage.Hash(request)
			if e = r.commandBlob("request", requestID, request); e != nil {
				return e
			}
			now := time.Now().Unix()
			o = commandOperation{Node: node, NodeKey: enrollment.PublicKey, Request: requestID, Configuration: configuration, Receipt: Receipt{Format: "outpost-management-receipt-1", Operation: input.Operation, RequestDigest: digest, State: "ADMITTED", ObservedUnix: now}, Audit: Audit{Sequence: s.Revision + 1, Actor: p.Actor, Tenant: tenant, Domain: input.Domain, Operation: input.Operation, Reason: input.Reason, Action: "COMMAND_" + strings.ToUpper(input.Kind), State: "ADMITTED", ObservedUnix: now, RequestDigest: digest}}
			if input.Kind == "retention" {
				var grant generation.RetentionProtection
				if e = json.Unmarshal(input.RetentionGrant, &grant); e != nil {
					return ErrInvalid
				}
				o.Retention = linkRetentionGrant(grant, input.RetentionGrant)
			}
			if s.CommandOperations == nil {
				s.CommandOperations = map[string]commandOperation{}
			}
			s.CommandOperations[input.Operation] = o
			if e = r.save(s); e != nil {
				return e
			}
			if e = r.point("management-command-intent-durable"); e != nil {
				return e
			}
			s, e = r.load()
			if e != nil {
				return e
			}
		} else if configuration != o.Configuration {
			return ErrConflict
		}
		envelope := command.Envelope{Format: command.EnvelopeFormat, Actor: o.Audit.Actor, Service: identity(r.signer.Public().(ed25519.PublicKey)), Node: node, Sequence: o.Audit.Sequence, ConfigurationDigest: o.Configuration, AdmittedUnix: o.Audit.ObservedUnix, Request: input}
		raw, e := command.SignEnvelope(envelope, r.owner, r.signer)
		if e != nil {
			return e
		}
		envelopeID := storage.Hash(raw)
		if e = r.commandBlob("envelope", envelopeID, raw); e != nil {
			return e
		}
		if e = r.point("management-command-envelope-durable"); e != nil {
			return e
		}
		o.Envelope = envelopeID
		s.CommandOperations[input.Operation] = o
		if e = r.save(s); e != nil {
			return e
		}
		if e = r.point("management-command-published-durable"); e != nil {
			return e
		}
		out = o.Receipt
		return nil
	})
	return out, e
}

type QueuedCommand struct {
	Document []byte `json:"document"`
	Sequence uint64 `json:"sequence"`
	position uint64
}

const MaxCommandPage = 8 << 20

type CommandPage struct {
	Format     string          `json:"format"`
	Revision   uint64          `json:"revision"`
	Commands   []QueuedCommand `json:"commands"`
	NextCursor string          `json:"nextCursor,omitempty"`
}

func (r *Registry) CommandPage(ctx context.Context, p Principal, tenant, node string, limit int, token, path string) (CommandPage, error) {
	var out CommandPage
	if limit < 1 || limit > 32 {
		return out, ErrInvalid
	}
	binding := cursorBinding(p, path+"/command-order-2")
	cur, e := r.readCursor(token, binding)
	if e != nil {
		return out, e
	}
	after := uint64(0)
	if token != "" {
		after, e = strconv.ParseUint(cur.Position, 10, 64)
		if e != nil || !command.ValidPosition(after) {
			return out, ErrConflict
		}
	}
	commands, revision, e := r.Commands(ctx, p, tenant, node, after, limit)
	if e != nil {
		return out, e
	}
	if token != "" && cur.Revision != revision {
		return out, ErrConflict
	}
	out = CommandPage{Format: "outpost-management-commands-2", Revision: revision, Commands: commands}
	// A nonempty page supplies a cursor even when the following page is empty.
	// Consumers restart at the first page after any ACK or registry revision.
	if len(commands) > 0 {
		out.NextCursor = r.writeCursor(revision, strconv.FormatUint(commands[len(commands)-1].position, 10), binding)
	}
	return out, nil
}

func (r *Registry) Commands(ctx context.Context, p Principal, tenant, node string, after uint64, limit int) ([]QueuedCommand, uint64, error) {
	if p.Validate() != nil || !p.Role("node") || p.Actor != node || !p.Allows(tenant, "") || limit < 1 || limit > 32 || !command.ValidPosition(after) {
		return nil, 0, ErrDenied
	}
	out := []QueuedCommand{}
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
		enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
		if e != nil || enrollment.Tenant != tenant || !enrollment.Active(time.Now()) {
			return ErrDenied
		}
		candidates := []commandOperation{}
		position := func(o commandOperation) uint64 {
			return command.Position(o.Audit.Sequence, strings.ToLower(strings.TrimPrefix(o.Audit.Action, "COMMAND_")))
		}
		for _, o := range s.CommandOperations {
			if o.Node == node && o.Audit.Tenant == tenant && p.Allows(tenant, o.Audit.Domain) && o.Receipt.State == "ADMITTED" && !resolved(s, o.Receipt.Operation) && position(o) > after {
				if d, ok := enrollment.Domain(o.Audit.Domain); ok {
					f := s.Domains[d.Domain]
					if f.Tenant != tenant || f.Repository != d.Repository || f.Epoch != d.Epoch {
						return ErrDenied
					}
					candidates = append(candidates, o)
				}
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return position(candidates[i]) < position(candidates[j]) })
		bytes := 0
		for _, o := range candidates {
			if o.Envelope == "" {
				break
			}
			raw, _, e := r.readCommand(o)
			if e != nil {
				return e
			}
			if bytes+len(raw) > 5<<20 {
				break
			}
			bytes += len(raw)
			out = append(out, QueuedCommand{raw, o.Audit.Sequence, position(o)})
			if len(out) == limit {
				break
			}
		}
		return nil
	})
	return out, revision, e
}
func (r *Registry) AcknowledgeCommand(ctx context.Context, p Principal, tenant, node, operation string, raw []byte) (Receipt, error) {
	var out Receipt
	if p.Validate() != nil || !p.Role("node") || p.Actor != node || !p.Allows(tenant, "") || !storage.ID(operation) {
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
		o, exists := s.CommandOperations[operation]
		if !exists || o.Node != node || o.Audit.Tenant != tenant || !p.Allows(tenant, o.Audit.Domain) {
			return ErrUnavailable
		}
		enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
		if e != nil || enrollment.Tenant != tenant || !enrollment.Active(time.Now()) {
			return ErrDenied
		}
		if _, ok := enrollment.Domain(o.Audit.Domain); !ok {
			return ErrDenied
		}
		envelope, _, e := r.readCommand(o)
		if e != nil {
			return e
		}
		ack, e := command.VerifyAck(raw, envelope, r.owner, o.NodeKey, time.Now())
		if e != nil {
			return ErrDenied
		}
		if len(o.Acknowledgement) > 0 {
			if !bytes.Equal(o.Acknowledgement, raw) {
				return ErrConflict
			}
			out = o.Receipt
			return nil
		}
		o.Acknowledgement = append([]byte(nil), raw...)
		o.Receipt.State = ack.State
		o.Receipt.ObservedUnix = ack.ObservedUnix
		o.Receipt.ResultDigest = storage.Hash(raw)
		o.Receipt.ErrorCode = ack.ErrorCode
		o.Audit.State = ack.State
		o.Audit.ResultDigest = o.Receipt.ResultDigest
		s.CommandOperations[operation] = o
		if e = r.save(s); e != nil {
			return e
		}
		if e = r.point("management-command-ack-durable"); e != nil {
			return e
		}
		out = o.Receipt
		return nil
	})
	return out, e
}
