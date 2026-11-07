package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func observationName(grant, id, target string) string {
	return "observation-" + storage.Hash([]byte(grant+"/"+id+"/"+target)) + ".json"
}
func (w *Worker) readObservation(ctx context.Context, grant []byte, id, target string) ([]byte, error) {
	var raw []byte
	e := w.state.WithLock(ctx, func() error {
		var e error
		raw, e = w.state.Read(observationName(storage.Hash(grant), id, target))
		return e
	})
	if e != nil {
		return nil, e
	}
	p, e := observation.VerifyProofDocument(raw, grant, w.owner, id)
	if e != nil || p.Target != target {
		return nil, observation.ErrDenied
	}
	return raw, nil
}
func (w *Worker) saveObservation(ctx context.Context, grant, raw []byte) ([]byte, error) {
	var p observation.Proof
	if storage.Decode(raw, &p, observation.MaxDocument) != nil {
		return nil, observation.ErrDenied
	}
	p, e := observation.VerifyProof(raw, grant, w.owner, p.Generation, time.Now())
	if e != nil {
		return nil, e
	}
	result := raw
	e = w.state.WithLock(ctx, func() error {
		name := observationName(p.Grant, p.Generation, p.Target)
		old, e := w.state.Read(name)
		if e == nil {
			previous, err := observation.VerifyProofDocument(old, grant, w.owner, p.Generation)
			if err != nil || previous.Target != p.Target {
				return observation.ErrDenied
			}
			if previous.ObservedUnix > p.ObservedUnix {
				return observation.ErrDenied
			}
			if previous.ObservedUnix == p.ObservedUnix {
				if !bytes.Equal(old, raw) {
					return observation.ErrDenied
				}
				result = old
				return nil
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		return w.state.Write(name, raw)
	})
	return result, e
}
func (w *Worker) serveObservations(out http.ResponseWriter, r *http.Request, parts []string) {
	if (len(parts) != 6 || r.Method != http.MethodGet) && (len(parts) != 7 || r.Method != http.MethodPut) || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Encoding") != "" || r.Method == http.MethodGet && r.ContentLength != 0 || r.Method == http.MethodPut && (r.ContentLength < 1 || r.ContentLength > observation.MaxDocument) {
		http.Error(out, "denied", 403)
		return
	}
	domain, grantID, id := parts[2], parts[4], parts[5]
	if !storage.ID(domain) || !storage.ID(grantID) || !storage.ID(id) {
		http.Error(out, "denied", 403)
		return
	}
	remote := peer.Identity(r.TLS.PeerCertificates[0])
	if !currentPeer(r.TLS, remote) || !w.certificateCurrent() {
		http.Error(out, "denied", 403)
		return
	}
	w.mu.Lock()
	v := w.active
	if v == nil || v.ctx.Err() != nil || v.cfg.Active(time.Now()) != nil {
		w.mu.Unlock()
		http.Error(out, "inactive", 503)
		return
	}
	var rawGrant []byte
	var g observation.Grant
	for _, raw := range v.cfg.Observations {
		if storage.Hash(raw) == grantID {
			var e error
			g, e = observation.VerifyGrant(raw, w.owner)
			if e == nil {
				rawGrant = raw
			}
			break
		}
	}
	allowed := len(rawGrant) > 0 && g.Active(time.Now()) && g.Trust.Domain == domain && g.Collector == w.node && v.domains[domain] != nil
	if r.Method == http.MethodGet {
		allowed = allowed && g.Reader == remote
	} else {
		allowed = allowed && g.Target(remote) && parts[6] == remote
	}
	if !allowed {
		w.mu.Unlock()
		http.Error(out, "denied", 403)
		return
	}
	select {
	case v.metadata <- struct{}{}:
	default:
		w.mu.Unlock()
		out.Header().Set("Retry-After", "1")
		http.Error(out, "busy", 503)
		return
	}
	defer func() { <-v.metadata }()
	v.requests.Add(1)
	w.mu.Unlock()
	defer v.requests.Done()
	ctx, cleanup, e := w.requestContext(out, r, v)
	if e != nil {
		http.Error(out, "unavailable", 503)
		return
	}
	defer cleanup()
	// A collector admits evidence only for its own recorded complete generation.
	entries, e := v.domains[domain].replica.Inventory(ctx)
	known := false
	for _, entry := range entries {
		if entry.Generation == id {
			known = true
			break
		}
	}
	if e != nil || !known {
		http.Error(out, "pending", 503)
		return
	}
	var response []byte
	if r.Method == http.MethodPut {
		raw, err := io.ReadAll(io.LimitReader(r.Body, observation.MaxDocument+1))
		if err != nil {
			http.Error(out, "unavailable", 503)
			return
		}
		p, err := observation.VerifyProof(raw, rawGrant, w.owner, id, time.Now())
		if err != nil || p.Target != remote || ctx.Err() != nil {
			http.Error(out, "denied", 403)
			return
		}
		response, e = w.saveObservation(ctx, rawGrant, raw)
	} else {
		b := observation.Bundle{Format: observation.ProofFormat, Grant: grantID, Generation: id, Proofs: []json.RawMessage{}}
		for _, target := range g.Targets {
			raw, err := w.readObservation(ctx, rawGrant, id, target)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				e = err
				break
			}
			if _, err = observation.VerifyProof(raw, rawGrant, w.owner, id, time.Now()); err != nil {
				continue
			}
			b.Proofs = append(b.Proofs, raw)
		}
		if e == nil {
			response, e = json.Marshal(b)
		}
	}
	if e != nil || ctx.Err() != nil || !g.Active(time.Now()) {
		http.Error(out, "unavailable", 503)
		return
	}
	if len(response) > observation.MaxReply {
		http.Error(out, "capacity", 507)
		return
	}
	out.Header().Set("Content-Type", "application/json")
	out.Header().Set("Content-Length", strconv.Itoa(len(response)))
	out.Header().Set("Cache-Control", "no-store")
	out.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = out.Write(response)
}

type ObservationState struct {
	Format   string                      `json:"format"`
	Revision uint64                      `json:"configurationRevision"`
	Grants   map[string]ObservationRoute `json:"grants"`
}
type ObservationRoute struct {
	Generation  string `json:"generation,omitempty"`
	Phase       string `json:"phase"`
	ErrorCode   string `json:"errorCode,omitempty"`
	CheckedUnix int64  `json:"checkedUnix"`
}

func (w *Worker) ObservationStatus(ctx context.Context) (ObservationState, error) {
	s := ObservationState{Format: "outpost-observation-status-1", Grants: map[string]ObservationRoute{}}
	e := w.state.WithLock(ctx, func() error {
		raw, e := w.state.Read("observations.json")
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if e != nil {
			return e
		}
		if storage.Decode(raw, &s, observation.MaxReply) != nil || s.Format != "outpost-observation-status-1" || s.Grants == nil || len(s.Grants) > 64 {
			return ErrDenied
		}
		for id, r := range s.Grants {
			if !storage.ID(id) || r.Generation != "" && !storage.ID(r.Generation) || r.CheckedUnix < 1 || r.CheckedUnix > time.Now().Unix() || r.Phase != "PUBLISHED" && r.Phase != "PENDING" && r.Phase != "RETRY_WAIT" {
				return ErrDenied
			}
		}
		return nil
	})
	return s, e
}
func (w *Worker) recordObservation(ctx context.Context, v *view, grant, id string, err error) error {
	s, e := w.ObservationStatus(ctx)
	if e != nil {
		return e
	}
	if s.Revision != v.cfg.Revision {
		s.Revision = v.cfg.Revision
		s.Grants = map[string]ObservationRoute{}
	}
	r := ObservationRoute{Generation: id, Phase: "PUBLISHED", CheckedUnix: time.Now().Unix()}
	if id == "" {
		r.Phase = "PENDING"
	}
	if err != nil {
		r.Phase = "RETRY_WAIT"
		r.ErrorCode = errorCode(err)
	}
	old := s.Grants[grant]
	if old.Generation == r.Generation && old.Phase == r.Phase && old.ErrorCode == r.ErrorCode && r.CheckedUnix-old.CheckedUnix < 30 {
		return nil
	}
	s.Grants[grant] = r
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return w.state.WithLock(ctx, func() error { return w.state.Write("observations.json", raw) })
}
func (w *Worker) observeOne(ctx context.Context, v *view, raw []byte, g observation.Grant, id string) error {
	local := v.domains[g.Trust.Domain]
	if local == nil {
		return ErrDenied
	}
	proof, e := w.readObservation(ctx, raw, id, w.node)
	if errors.Is(e, os.ErrNotExist) {
		catalog, err := local.replica.Catalog(ctx, id)
		if err != nil {
			return err
		}
		result, err := local.replica.ReceiveBatch(ctx, catalog, 16, 32<<20, func(generation.Object) ([]byte, error) { return nil, generation.ErrIncomplete })
		if err != nil {
			return err
		}
		if !result.Complete {
			return observation.ErrPending
		}
		proof, e = observation.SignProof(raw, w.owner, id, result.VerifiedAt, w.cert.PrivateKey.(ed25519.PrivateKey), time.Now())
		if e != nil {
			return e
		}
		proof, e = w.saveObservation(ctx, raw, proof)
	}
	if e != nil {
		return e
	}
	if _, e = observation.VerifyProof(proof, raw, w.owner, id, time.Now()); e != nil {
		return e
	}
	if g.Collector == w.node {
		return nil
	}
	collector, ok := v.cfg.NodeByID(g.Collector)
	if !ok {
		return ErrDenied
	}
	client, e := observation.NewClient(collector.Endpoint, raw, w.owner, w.cert, w.roots, time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond)
	if e != nil {
		return e
	}
	defer client.Close()
	return client.Publish(ctx, proof)
}

// One bounded generation per grant and pass keeps a failed older copy from
// starving newer observations. Policy cancellation joins this loop.
func (w *Worker) observe(v *view) error {
	if len(v.cfg.Observations) == 0 {
		return nil
	}
	cursors := map[string]int{}
	for v.ctx.Err() == nil {
		for _, raw := range v.cfg.Observations {
			g, e := observation.VerifyGrant(raw, w.owner)
			if e != nil {
				v.cancel()
				return e
			}
			if !g.Target(w.node) {
				continue
			}
			ctx, cancel := context.WithTimeout(v.ctx, time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond)
			var id string
			local := v.domains[g.Trust.Domain]
			if local == nil {
				e = ErrDenied
			} else {
				var entries []generation.InventoryEntry
				entries, e = local.replica.Inventory(ctx)
				if e == nil && len(entries) > 0 {
					key := storage.Hash(raw)
					n := cursors[key] % len(entries)
					cursors[key] = n + 1
					id = entries[n].Generation
					e = w.observeOne(ctx, v, raw, g, id)
				}
			}
			cancel()
			if v.ctx.Err() != nil {
				return nil
			}
			if e = w.recordObservation(v.ctx, v, storage.Hash(raw), id, e); e != nil {
				v.cancel()
				return e
			}
		}
		select {
		case <-v.ctx.Done():
			return nil
		case <-time.After(time.Duration(v.cfg.Limits.PollSeconds) * time.Second):
		}
	}
	return nil
}
