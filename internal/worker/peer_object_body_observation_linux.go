package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const peerBodiesFormatV1 = "outpost-peer-object-body-1"
const peerBodiesFormatV2 = "outpost-peer-object-body-2"
const peerBodiesDirectory = "telemetry/peer-object-bodies"
const maxPeerBodyObservation = 1024

type PeerObjectBodyObservation struct {
	Route string `json:"route"`
	peer.PushedObjectBodyObservation
}

type signedPeerObjectBody struct {
	Format string `json:"format"`
	PeerObjectBodyObservation
	Signature []byte `json:"signature,omitempty"`
}

func peerObjectBodyRoute(trust generation.Trust, sender, receiver string) string {
	return storage.Hash([]byte(fmt.Sprintf("%s/%s/%s/%d/%s/%s", peerBodiesFormatV1,
		trust.Domain, trust.Repository, trust.Epoch, sender, receiver)))
}

func peerObjectBodyObserver(v *view, trust generation.Trust, sender, receiver string) func(peer.PushedObjectBodyObservation) {
	if v.peerObjectBodies == nil {
		return nil
	}
	route := peerObjectBodyRoute(trust, sender, receiver)
	return func(body peer.PushedObjectBodyObservation) {
		select {
		case v.peerObjectBodies <- PeerObjectBodyObservation{Route: route, PushedObjectBodyObservation: body}:
		default:
		}
	}
}

func (m PeerObjectBodyObservation) valid(format string, now int64) bool {
	if !storage.ID(m.Route) || m.ObservedUnixMillis <= 0 || m.ObservedUnixMillis > now ||
		m.TransportReadBodyBytes <= 0 || m.TransportReadBodyBytes > generation.MaxObject ||
		m.AcknowledgedBodyBytes != m.TransportReadBodyBytes {
		return false
	}
	switch format {
	case peerBodiesFormatV1:
		return m.ElapsedNanos == 0 && m.AlreadyPresentBodyBytes == nil
	case peerBodiesFormatV2:
		return m.ElapsedNanos > 0 && (m.AlreadyPresentBodyBytes == nil ||
			*m.AlreadyPresentBodyBytes == 0 || *m.AlreadyPresentBodyBytes == m.AcknowledgedBodyBytes)
	default:
		return false
	}
}

func (w *Worker) writePeerObjectBody(ctx context.Context, observation PeerObjectBodyObservation) error {
	now := time.Now().UnixMilli()
	if w.budget == nil || !observation.valid(peerBodiesFormatV2, now) {
		return ErrDenied
	}
	if err := w.check(ctx); err != nil {
		return err
	}
	store, err := statefile.OpenAt(w.root, peerBodiesDirectory, maxPeerBodyObservation, true)
	if err != nil {
		return err
	}
	defer store.Close()
	key := w.cert.PrivateKey.(ed25519.PrivateKey)
	name := observation.Route + ".v2.json"
	prior, valid := readPeerObjectBody(store, name, observation.Route, peerBodiesFormatV2, now, key.Public().(ed25519.PublicKey))
	if valid && prior.ObservedUnixMillis > observation.ObservedUnixMillis {
		return nil
	}
	store.Admit = func(name string, size int) (func(bool) error, error) {
		if err := w.check(ctx); err != nil {
			return nil, err
		}
		return w.budget.Reserve(ctx, peerBodiesDirectory+"/"+name, size)
	}
	record := signedPeerObjectBody{Format: peerBodiesFormatV2, PeerObjectBodyObservation: observation}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	record.Signature = ed25519.Sign(key, append([]byte(record.Format+"\x00"), raw...))
	raw, err = json.Marshal(record)
	if err != nil {
		return err
	}
	return store.Write(name, raw)
}

func readPeerObjectBody(store *statefile.Store, name, route, format string, now int64, key ed25519.PublicKey) (PeerObjectBodyObservation, bool) {
	raw, err := store.Read(name)
	var record signedPeerObjectBody
	if err != nil || storage.Decode(raw, &record, maxPeerBodyObservation) != nil ||
		record.Format != format || record.Route != route || !record.valid(format, now) {
		return PeerObjectBodyObservation{}, false
	}
	signature := record.Signature
	record.Signature = nil
	raw, err = json.Marshal(record)
	if err != nil || !ed25519.Verify(key, append([]byte(format+"\x00"), raw...), signature) {
		return PeerObjectBodyObservation{}, false
	}
	return record.PeerObjectBodyObservation, true
}

type PeerObjectTransferStatus struct {
	Format string                     `json:"format"`
	Route  string                     `json:"route"`
	Sample *PeerObjectBodyObservation `json:"sample,omitempty"`
}

// PeerObjectTransferStatus reads one currently allowed push route locally.
// The sample describes an acknowledged object and is independent of publication.
func (w *Worker) PeerObjectTransferStatus(ctx context.Context, domain, receiver string) (PeerObjectTransferStatus, error) {
	var out PeerObjectTransferStatus
	if !storage.ID(domain) || !storage.ID(receiver) {
		return out, ErrDenied
	}
	if err := w.check(ctx); err != nil {
		return out, err
	}
	raw, err := w.cache.Raw(ctx)
	if err != nil {
		return out, err
	}
	cfg, err := w.cache.Verify(raw)
	if err != nil {
		return out, err
	}
	if err = cfg.Active(time.Now()); err != nil {
		return out, err
	}
	d, ok := cfg.DomainByID(domain)
	if !ok || !d.Placement.HasEdge(w.node, receiver, "push") {
		return out, ErrDenied
	}
	route := peerObjectBodyRoute(d.Trust, w.node, receiver)
	out = PeerObjectTransferStatus{Format: "outpost-peer-object-transfer-status-1", Route: route}
	if !w.observePeerObjectBodies {
		return out, nil
	}
	store, err := statefile.OpenAt(w.root, peerBodiesDirectory, maxPeerBodyObservation, false)
	if err != nil {
		return out, nil
	}
	defer store.Close()
	key := w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	now := time.Now().UnixMilli()
	sample, valid := readPeerObjectBody(store, route+".v2.json", route, peerBodiesFormatV2, now, key)
	legacy, legacyValid := readPeerObjectBody(store, route+".json", route, peerBodiesFormatV1, now, key)
	if legacyValid && (!valid || legacy.ObservedUnixMillis > sample.ObservedUnixMillis) {
		sample, valid = legacy, true
	}
	if !valid {
		return out, nil
	}
	latest, err := w.cache.Raw(ctx)
	if err == nil && bytes.Equal(latest, raw) && cfg.Active(time.Now()) == nil && w.check(ctx) == nil {
		out.Sample = &sample
	}
	return out, nil
}
