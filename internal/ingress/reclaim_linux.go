package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const reclaimFormat = "outpost-ingress-reclaim-1"
const maxReclaimDocument = 2048

type ReclaimRequest struct {
	Authority []byte `json:"authority"`
	Intent    []byte `json:"intent"`
	Grant     []byte `json:"grant"`
}

type reclaimGrant struct {
	Format     string `json:"format"`
	Intent     string `json:"intent"`
	Generation string `json:"generation"`
	Signature  []byte `json:"signature,omitempty"`
}

// NewReclaimRequest binds cleanup to one signed ingress intent and one
// generation. A writer authorization cannot retire any replica generation.
func NewReclaimRequest(authority, intent []byte, generation string, owner ed25519.PublicKey, writer ed25519.PrivateKey) (ReclaimRequest, error) {
	a, err := VerifyAuthorityDocument(authority, owner)
	var i Intent
	if err != nil || canonicalIntent(intent, authority, owner, &i) != nil || !storage.ID(generation) ||
		len(writer) != ed25519.PrivateKeySize || !bytes.Equal(writer.Public().(ed25519.PublicKey), a.Trust.Writer) {
		return ReclaimRequest{}, ErrDenied
	}
	g := reclaimGrant{Format: reclaimFormat, Intent: storage.Hash(intent), Generation: generation}
	raw, _ := json.Marshal(g)
	g.Signature = ed25519.Sign(writer, raw)
	raw, _ = json.Marshal(g)
	return ReclaimRequest{Authority: bytes.Clone(authority), Intent: bytes.Clone(intent), Grant: raw}, nil
}

func verifyReclaim(raw, intent []byte, writer ed25519.PublicKey) (reclaimGrant, error) {
	var g reclaimGrant
	if len(raw) > maxReclaimDocument || canonical(raw, &g) != nil || g.Format != reclaimFormat ||
		g.Intent != storage.Hash(intent) || !storage.ID(g.Generation) {
		return g, ErrDenied
	}
	sig := g.Signature
	g.Signature = nil
	body, _ := json.Marshal(g)
	if !ed25519.Verify(writer, body, sig) {
		return g, ErrDenied
	}
	g.Signature = sig
	return g, nil
}

// Verify checks the historical authorization without extending permission to
// admit payload or publish an expired intent.
func (r ReclaimRequest) Verify(owner ed25519.PublicKey) (Intent, string, error) {
	var i Intent
	a, err := VerifyAuthorityDocument(r.Authority, owner)
	if err != nil || canonicalIntent(r.Intent, r.Authority, owner, &i) != nil {
		return i, "", ErrDenied
	}
	grant, err := verifyReclaim(r.Grant, r.Intent, a.Trust.Writer)
	return i, grant.Generation, err
}

type reclaimReply struct {
	Grant string `json:"grant"`
	Clean bool   `json:"clean"`
}

func (c *Client) ReclaimStep(ctx context.Context, request ReclaimRequest) (bool, error) {
	if !c.cleanup || !bytes.Equal(request.Authority, c.authority) || !bytes.Equal(request.Intent, c.intentRaw) {
		return false, ErrDenied
	}
	body, err := json.Marshal(request)
	if err != nil {
		return false, err
	}
	status, _, raw, err := c.request(ctx, http.MethodPut, "reclaim", nil, body, 4096)
	if err != nil {
		return false, err
	}
	var reply reclaimReply
	if status != http.StatusOK || decodeReply(raw, &reply) != nil || reply.Grant != storage.Hash(request.Grant) {
		return false, ErrProtocol
	}
	return reply.Clean, nil
}

func (g *Registry) serveReclaim(w http.ResponseWriter, r *http.Request, operation string) {
	deadline, _ := r.Context().Deadline()
	for _, expiry := range []time.Time{g.leaf.NotAfter, r.TLS.PeerCertificates[0].NotAfter, time.Unix(g.authority.ExpiresUnix, 0)} {
		if expiry.Before(deadline) {
			deadline = expiry
		}
	}
	ctx, stop, err := requestLifetime(w, r.Context(), deadline)
	if err != nil {
		fail(w, err)
		return
	}
	defer stop()
	raw, err := readBody(w, r, 4*MaxDocument+maxReclaimDocument)
	var request ReclaimRequest
	if err != nil || decodeReply(raw, &request) != nil || r.Header.Get("Outpost-Authority") != storage.Hash(request.Authority) {
		fail(w, ErrDenied)
		return
	}
	a, err := VerifyAuthorityDocument(request.Authority, g.options.Owner)
	var i Intent
	if err != nil || !SameAuthorityScope(a, g.authority) || a.Revision > g.authority.Revision ||
		a.Revision == g.authority.Revision && !bytes.Equal(request.Authority, g.options.Authority) ||
		canonicalIntent(request.Intent, request.Authority, g.options.Owner, &i) != nil || i.Operation != operation {
		fail(w, ErrDenied)
		return
	}
	grant, err := verifyReclaim(request.Grant, request.Intent, a.Trust.Writer)
	if err != nil || g.poisoned || time.Now().Unix() < g.state.ObservedUnix {
		fail(w, errors.Join(ErrConflict, err))
		return
	}
	clean, err := g.reclaim(ctx, request, i, grant)
	if err != nil {
		fail(w, err)
		return
	}
	jsonReply(w, http.StatusOK, reclaimReply{Grant: storage.Hash(request.Grant), Clean: clean})
}

func (g *Registry) reclaim(ctx context.Context, request ReclaimRequest, i Intent, grant reclaimGrant) (bool, error) {
	if !bytes.Equal(g.state.Intent, request.Intent) {
		var current Intent
		if len(g.state.Intent) == 0 || canonicalIntent(g.state.Intent, g.intentAuthority(), g.options.Owner, &current) == nil && current.Sequence > i.Sequence {
			// No matching admitted slot remains. A delayed request must
			// never touch the newer slot.
			return true, nil
		}
		return false, ErrConflict
	}
	s := g.session
	if s == nil {
		options := g.sessionOptions(request.Intent)
		options.Initialize = false
		var err error
		s, err = openSessionFor(ctx, options, sessionInspect)
		if err != nil {
			return false, err
		}
		defer s.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().Unix() < s.state.LastObserved || len(s.state.Catalog) != 0 && storage.Hash(s.state.Catalog) != grant.Generation ||
		s.state.Receipt != nil && s.state.Receipt.Generation != grant.Generation {
		return false, ErrConflict
	}
	if len(s.state.Reclaimed) == 0 {
		raw, err := g.options.Replica.Catalog(ctx, grant.Generation)
		if err != nil {
			return false, err
		}
		catalog, err := generation.VerifyCatalog(raw, g.authority.Trust)
		if err != nil || !i.matches(catalog) || storage.Hash(raw) != grant.Generation {
			return false, ErrConflict
		}
		verified, err := g.options.Replica.VerifyWindow(ctx, grant.Generation, storage.Hash(request.Grant), 32, 16<<20)
		if err != nil || !verified.Complete {
			return false, err
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		s.state.Reclaimed = bytes.Clone(request.Grant)
		s.state.LastObserved = time.Now().Unix()
		if err = s.save(); err != nil {
			return false, err
		}
		if err = s.point("capture-reclaim-durable"); err != nil {
			return false, err
		}
	} else if !bytes.Equal(s.state.Reclaimed, request.Grant) {
		return false, ErrConflict
	}
	if err := s.cleanupStaged(ctx, 256); err != nil {
		return false, err
	}
	if len(s.refs) != 0 {
		return false, nil
	}
	empty, err := s.slotEmpty()
	if err != nil || !empty {
		return false, errors.Join(ErrConflict, err)
	}
	return true, nil
}

// An exact readiness replay must respect a closed slot before an in-memory
// session has been opened, including after a receiver restart.
func (g *Registry) slotFenced(intent []byte) (bool, error) {
	if g.session != nil {
		g.session.mu.Lock()
		defer g.session.mu.Unlock()
		return len(g.session.state.Reclaimed) != 0 || len(g.session.state.Retired) != 0, nil
	}
	meta, err := statefile.OpenAt(g.root, "current/state", maxSessionDocument, false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer meta.Close()
	raw, err := meta.Read("session.json")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state sessionState
	if storage.Decode(raw, &state, maxSessionDocument) != nil {
		return false, ErrConflict
	}
	return bytes.Equal(state.Intent, intent) && (len(state.Reclaimed) != 0 || len(state.Retired) != 0), nil
}

func (s *Session) slotEmpty() (bool, error) {
	dir, err := s.objectRoot.Open(".")
	if err != nil {
		return false, err
	}
	names, err := dir.ReadDir(1)
	if errors.Is(err, io.EOF) || errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return len(names) == 0, errors.Join(err, dir.Close())
}
