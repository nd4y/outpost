package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const AbandonmentFormat = "outpost-upload-abandonment-1"
const MaxAbandonment = 4096

type AbandonmentBinding struct {
	Node       string `json:"node"`
	Domain     string `json:"domain"`
	Repository string `json:"repository"`
	Epoch      uint64 `json:"epoch"`
	Queue      string `json:"queue"`
	Operation  string `json:"operation"`
	Plan       string `json:"plan"`
	Generation string `json:"generation"`
}

type AbandonmentGrant struct {
	Format string `json:"format"`
	AbandonmentBinding
	NotBefore   int64  `json:"notBefore"`
	ExpiresUnix int64  `json:"expiresUnix"`
	Signature   []byte `json:"signature,omitempty"`
}

type AbandonmentReceipt struct {
	Format string `json:"format"`
	AbandonmentBinding
	GrantDigest  string `json:"grantDigest"`
	ReleasedUnix int64  `json:"releasedUnix"`
}

type queueAbandonment struct {
	Grant        json.RawMessage `json:"grant"`
	ReleasedUnix int64           `json:"releasedUnix,omitempty"`
}

func (g AbandonmentGrant) valid() bool {
	return g.Format == AbandonmentFormat && storage.ID(g.Node) && storage.ID(g.Domain) &&
		storage.ID(g.Repository) && g.Epoch > 0 && storage.ID(g.Queue) &&
		storage.ID(g.Operation) && storage.ID(g.Plan) && storage.ID(g.Generation) &&
		g.NotBefore > 0 && g.ExpiresUnix > g.NotBefore && g.ExpiresUnix <= 1<<40 &&
		g.ExpiresUnix-g.NotBefore <= 86400
}

func SignAbandonment(g AbandonmentGrant, key ed25519.PrivateKey) ([]byte, error) {
	if !g.valid() || len(g.Signature) != 0 || len(key) != ed25519.PrivateKeySize {
		return nil, ErrDenied
	}
	unsigned, e := json.Marshal(g)
	if e != nil {
		return nil, e
	}
	g.Signature = ed25519.Sign(key, append([]byte(AbandonmentFormat+"\x00"), unsigned...))
	return json.Marshal(g)
}

func verifyAbandonment(raw []byte, key ed25519.PublicKey) (AbandonmentGrant, error) {
	var g AbandonmentGrant
	if storage.Decode(raw, &g, MaxAbandonment) != nil || !g.valid() || len(key) != ed25519.PublicKeySize {
		return g, ErrDenied
	}

	sig := g.Signature
	g.Signature = nil
	unsigned, e := json.Marshal(g)
	if e != nil || !ed25519.Verify(key, append([]byte(AbandonmentFormat+"\x00"), unsigned...), sig) {
		return g, ErrDenied
	}
	return g, nil
}

func (q *Queue) abandonmentBinding(instance string, p Plan, raw []byte) AbandonmentBinding {
	t := q.authority.Generation
	return AbandonmentBinding{Node: q.worker, Domain: t.Domain, Repository: t.Repository, Epoch: t.Epoch,
		Queue: instance, Operation: p.Operation, Plan: storage.Hash(raw), Generation: p.Generation}
}

func (q *Queue) validAbandonment(s QueueState, p Plan, job QueueJob) bool {
	a := job.Abandonment
	if a == nil {
		return true
	}
	g, e := verifyAbandonment(a.Grant, q.authority.Generation.Maintenance)
	return e == nil && g.AbandonmentBinding == q.abandonmentBinding(s.Instance, p, job.Plan) &&
		job.Phase == "EXPIRED" && job.Receipt == nil && !job.CleanupPending &&
		(a.ReleasedUnix == 0 || a.ReleasedUnix >= max(g.NotBefore, p.ExpiresUnix) && a.ReleasedUnix < g.ExpiresUnix)
}

// PreviewAbandonment reads the expired job's exact local binding for offline signing.
func (q *Queue) PreviewAbandonment(ctx context.Context, operation string) (AbandonmentGrant, error) {
	var out AbandonmentGrant
	s, e := q.Status(ctx)
	if e != nil {
		return out, e
	}
	j, ok := s.Jobs[operation]
	if !ok || j.Receipt != nil {
		return out, ErrDenied
	}
	p, e := Verify(j.Plan, q.authority)
	now := time.Now().Unix()
	if e != nil || now < p.ExpiresUnix {
		return out, ErrDenied
	}
	journal, e := q.journal(j, false)
	if e != nil {
		return out, e
	}
	defer journal.Close()
	if e = requireUnfinishedUpload(ctx, journal); e != nil {
		return out, e
	}
	return AbandonmentGrant{Format: AbandonmentFormat, AbandonmentBinding: q.abandonmentBinding(s.Instance, p, j.Plan),
		NotBefore: now, ExpiresUnix: now + 3600}, nil
}

func requireUnfinishedUpload(ctx context.Context, journal *Journal) error {
	s, e := journal.Status(ctx)
	if e != nil {
		return e
	}
	if s.Receipt != nil {
		return ErrConflict
	}
	return nil
}

func (q *Queue) guardAbandonment(ctx context.Context, grant AbandonmentGrant) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if q.Guard != nil {
		if e := q.Guard(ctx); e != nil {
			return e
		}
	}
	now := time.Now().Unix()
	if now < grant.NotBefore || now >= grant.ExpiresUnix {
		return ErrDenied
	}
	return nil
}

// Abandon retains the expired job and its history while releasing only its
// local upload pins. The execution lease belongs to the caller.
func (q *Queue) Abandon(ctx context.Context, source *generation.Replica, operation string, raw []byte) (AbandonmentReceipt, error) {
	var out AbandonmentReceipt
	g, e := verifyAbandonment(raw, q.authority.Generation.Maintenance)
	if e != nil || g.Operation != operation || !queueSource(q, source) {
		return out, ErrDenied
	}
	unlock, e := lock(ctx, q.root, "runner.lock")
	if e != nil {
		return out, e
	}
	defer unlock()
	s, e := q.Status(ctx)
	if e != nil {
		return out, e
	}
	j, ok := s.Jobs[g.Operation]
	if !ok || j.Receipt != nil {
		return out, ErrDenied
	}
	p, e := Verify(j.Plan, q.authority)
	if e != nil || g.AbandonmentBinding != q.abandonmentBinding(s.Instance, p, j.Plan) || time.Now().Unix() < p.ExpiresUnix {
		return out, ErrDenied
	}
	out = AbandonmentReceipt{Format: "outpost-upload-abandonment-receipt-1", AbandonmentBinding: g.AbandonmentBinding}
	if j.Abandonment != nil && j.Abandonment.ReleasedUnix != 0 {
		out.GrantDigest, out.ReleasedUnix = storage.Hash(j.Abandonment.Grant), j.Abandonment.ReleasedUnix
		return out, nil
	}
	if e = q.guardAbandonment(ctx, g); e != nil {
		return AbandonmentReceipt{}, e
	}
	active, cancel := context.WithDeadline(ctx, time.Unix(g.ExpiresUnix, 0))
	defer cancel()
	journal, e := q.journal(j, false)
	if e != nil {
		return AbandonmentReceipt{}, e
	}
	defer journal.Close()
	join, e := lock(active, journal.root, "worker.lock")
	if e != nil {
		return AbandonmentReceipt{}, e
	}
	defer join()
	if e = requireUnfinishedUpload(active, journal); e != nil {
		return AbandonmentReceipt{}, e
	}
	if e = q.guardAbandonment(active, g); e != nil {
		return AbandonmentReceipt{}, e
	}
	if j.Abandonment == nil || !bytes.Equal(j.Abandonment.Grant, raw) {
		if e = q.edit(active, func(s *QueueState) error {
			j := s.Jobs[g.Operation]
			j.Phase, j.ErrorCode, j.NextMillis = "EXPIRED", "EXPIRED", 0
			j.Abandonment = &queueAbandonment{Grant: append([]byte(nil), raw...)}
			s.Jobs[g.Operation] = j
			return nil
		}); e != nil {
			return AbandonmentReceipt{}, e
		}
		if e = q.checkpoint("abandonment-intent"); e != nil {
			return AbandonmentReceipt{}, e
		}
	}
	if e = q.guardAbandonment(active, g); e != nil {
		return AbandonmentReceipt{}, e
	}
	if e = source.ReleaseGenerationPins(active, g.Generation, q.pin(g.Operation), workerPin(g.Plan, q.worker)); e != nil {
		return AbandonmentReceipt{}, e
	}
	if e = q.checkpoint("abandonment-pins"); e != nil {
		return AbandonmentReceipt{}, e
	}
	if e = q.edit(active, func(s *QueueState) error {
		if e := q.guardAbandonment(active, g); e != nil {
			return e
		}
		now := time.Now().Unix()
		if now >= g.ExpiresUnix {
			return ErrDenied
		}
		out.GrantDigest, out.ReleasedUnix = storage.Hash(raw), now
		j := s.Jobs[g.Operation]
		j.Abandonment.ReleasedUnix = now
		s.Jobs[g.Operation] = j
		return nil
	}); e != nil {
		return AbandonmentReceipt{}, e
	}
	return out, nil
}
