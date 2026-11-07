package management

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

type ReconcileItem struct {
	Operation string `json:"operationId"`
	Sequence  uint64 `json:"sequence"`
	Action    string `json:"action"`
	State     string `json:"state"`
	ErrorCode string `json:"errorCode,omitempty"`
}
type ReconcileResult struct {
	Format       string          `json:"format"`
	ObservedUnix int64           `json:"observedUnix"`
	Items        []ReconcileItem `json:"items"`
	NextSequence uint64          `json:"nextSequence,omitempty"`
}

// Reconcile is a private service operation, never a request-supplied identity.
// Principals must be the current local ACL. Missing/revoked actors cannot create
// new effects. An exact already-durable cache effect can finish its original
// receipt without reapplying policy or claiming node execution.
// Resume at NextSequence; zero starts another bounded pass, including blocked
// earlier intents. No intent, payload, report or audit entry is deleted.
func (r *Registry) Reconcile(ctx context.Context, principals []Principal, after uint64, limit int) (ReconcileResult, error) {
	out := ReconcileResult{Format: "outpost-management-reconcile-1", Items: []ReconcileItem{}}
	if len(principals) > 128 || !safe(after) || limit < 1 || limit > 64 {
		return out, ErrInvalid
	}
	acl := map[string]Principal{}
	for _, p := range principals {
		if p.Validate() != nil {
			return out, ErrInvalid
		}
		if _, ok := acl[p.Actor]; ok {
			return out, ErrInvalid
		}
		p.Roles = append([]string(nil), p.Roles...)
		p.Scopes = append([]Scope(nil), p.Scopes...)
		acl[p.Actor] = p
	}
	var pending []ReconcileItem
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		add := func(a Audit) {
			if a.Sequence > after {
				pending = append(pending, ReconcileItem{Operation: a.Operation, Sequence: a.Sequence, Action: a.Action})
			}
		}
		for _, v := range s.Operations {
			if v.Receipt.State == "ADMITTED" && !resolved(s, v.Receipt.Operation) {
				add(v.Audit)
			}
		}
		for _, v := range s.ConfigOperations {
			if v.Receipt.State == "ADMITTED" && !resolved(s, v.Receipt.Operation) {
				add(v.Audit)
			}
		}
		for _, v := range s.CommandOperations {
			if v.Receipt.State == "ADMITTED" && !resolved(s, v.Receipt.Operation) && v.Envelope == "" {
				add(v.Audit)
			}
		}
		return nil
	})
	if e != nil {
		return out, e
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Sequence < pending[j].Sequence })
	if len(pending) > limit {
		pending = pending[:limit]
		out.NextSequence = pending[len(pending)-1].Sequence
	}
	for _, item := range pending {
		if e := r.check(ctx); e != nil {
			return out, e
		}
		state, e := r.reconcileOne(ctx, acl, item)
		if guard := r.check(ctx); guard != nil {
			return out, guard
		}
		if e != nil {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			item.State = "BLOCKED"
			item.ErrorCode = reconcileCode(e)
		} else {
			item.State = state
		}
		out.Items = append(out.Items, item)
	}
	out.ObservedUnix = time.Now().Unix()
	return out, nil
}

func reconcileCode(e error) string {
	switch {
	case errors.Is(e, ErrDenied), errors.Is(e, control.ErrInactive), errors.Is(e, command.ErrDenied), errors.Is(e, command.ErrExpired):
		return "AUTHORIZATION_UNAVAILABLE"
	case errors.Is(e, ErrConflict):
		return "STATE_CONFLICT"
	case errors.Is(e, ErrCapacity), errors.Is(e, statefile.ErrCapacity):
		return "CAPACITY"
	case errors.Is(e, ErrInvalid):
		return "INVALID_STATE"
	default:
		return "UNAVAILABLE"
	}
}

func (r *Registry) reconcileOne(ctx context.Context, acl map[string]Principal, item ReconcileItem) (string, error) {
	var enrollment enrollmentOperation
	var config configOperation
	var cmd commandOperation
	var candidate []byte
	var request command.Request
	var historical string
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		if resolved(s, item.Operation) {
			historical = "ABANDONED"
			return nil
		}
		switch item.Action {
		case "ENROLL", "REVOKE":
			var ok bool
			enrollment, ok = s.Operations[item.Operation]
			if !ok || enrollment.Audit.Sequence != item.Sequence {
				return ErrConflict
			}
			if enrollment.Receipt.State != "ADMITTED" {
				historical = enrollment.Receipt.State
			}
		case "APPLY_CONFIG":
			var ok bool
			config, ok = s.ConfigOperations[item.Operation]
			if !ok || config.Audit.Sequence != item.Sequence {
				return ErrConflict
			}
			if config.Receipt.State != "ADMITTED" {
				historical = config.Receipt.State
				return nil
			}
			candidate, e = r.blobs.Read("candidate-" + config.Candidate + ".json")
			if e != nil {
				return e
			}
			next, e := control.Verify(candidate, r.owner, config.Node)
			if e != nil || storage.Hash(candidate) != config.Candidate {
				return ErrInvalid
			}
			input := SignedMutation{Operation: item.Operation, Reason: config.Audit.Reason, Document: candidate, Expected: config.Expected, PreviewDigest: config.Candidate}
			if configurationRequestDigest(Principal{Actor: config.Audit.Actor}, config.Audit.Tenant, config.Node, input) != config.Receipt.RequestDigest {
				return ErrInvalid
			}
			current, e := r.cacheRaw(ctx, config.Node)
			if errors.Is(e, os.ErrNotExist) || errors.Is(e, control.ErrInactive) {
				return nil
			}
			if e != nil {
				return e
			}
			if bytes.Equal(current, candidate) {
				if pointer, ok := s.Configurations[config.Node]; ok && pointer.Revision != config.Expected && pointer.Digest != config.Candidate {
					return ErrConflict
				}
				if e = r.finishConfiguration(&s, config, next.Revision); e != nil {
					return e
				}
				historical = "COMPLETE"
			}
		default:
			var ok bool
			cmd, ok = s.CommandOperations[item.Operation]
			if !ok || cmd.Audit.Sequence != item.Sequence {
				return ErrConflict
			}
			if cmd.Receipt.State != "ADMITTED" {
				historical = cmd.Receipt.State
				return nil
			}
			if cmd.Envelope != "" {
				if _, _, e = r.readCommand(cmd); e != nil {
					return e
				}
				historical = "PUBLISHED"
				return nil
			}
			request, _, e = r.commandRequest(cmd)
			if e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return "", e
	}
	if historical != "" {
		return historical, nil
	}
	switch item.Action {
	case "ENROLL", "REVOKE":
		p, ok := acl[enrollment.Audit.Actor]
		if !ok {
			return "", ErrDenied
		}
		next, e := VerifyEnrollment(enrollment.Document, r.owner)
		if e != nil {
			return "", e
		}
		if !next.Revoked && !next.Active(time.Now()) {
			return "", ErrDenied
		}
		receipt, e := r.ApplyEnrollment(ctx, p, item.Operation, enrollment.Audit.Reason, enrollment.Document, enrollment.Expected)
		return receipt.State, e
	case "APPLY_CONFIG":
		p, ok := acl[config.Audit.Actor]
		if !ok {
			return "", ErrDenied
		}
		input := SignedMutation{Operation: item.Operation, Reason: config.Audit.Reason, Document: candidate, Expected: config.Expected, PreviewDigest: config.Candidate}
		receipt, e := r.ApplyConfiguration(ctx, p, config.Audit.Tenant, config.Node, input)
		return receipt.State, e
	default:
		p, ok := acl[cmd.Audit.Actor]
		if !ok {
			return "", ErrDenied
		}
		receipt, e := r.AdmitCommand(ctx, p, cmd.Audit.Tenant, cmd.Node, request)
		if e != nil {
			return "", e
		}
		if receipt.State == "ADMITTED" {
			return "PUBLISHED", nil
		}
		return receipt.State, nil
	}
}
