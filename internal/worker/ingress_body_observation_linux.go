package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const ingressBodiesFormat = "outpost-ingress-object-body-1"
const ingressBodiesDirectory = "telemetry/ingress-object-bodies"
const maxIngressBodyObservation = 1024

// IngressObjectBodyObservation describes one completely consumed, accepted
// source PUT. It counts neither unsuccessful requests nor lower-layer traffic.
type IngressObjectBodyObservation struct {
	Route                   string `json:"route"`
	ObservedUnixMillis      int64  `json:"observedUnixMillis"`
	AcceptedBodyBytes       int    `json:"acceptedBodyBytes"`
	AlreadyPresentBodyBytes int    `json:"alreadyPresentBodyBytes"`
}

type signedIngressBodyObservation struct {
	Format string `json:"format"`
	IngressObjectBodyObservation
	Signature []byte `json:"signature,omitempty"`
}

func ingressBodyRoute(a ingress.Authority) string {
	return storage.Hash([]byte(fmt.Sprintf("%s/%s/%s/%s/%s/%d/%s/%s", ingressBodiesFormat,
		a.Tenant, a.Profile, a.Trust.Domain, a.Trust.Repository, a.Trust.Epoch, a.Source, a.Ingress)))
}

func ingressBodyObserver(v *view, a ingress.Authority) func(int, bool) {
	if v.ingressBodies == nil {
		return nil
	}
	route := ingressBodyRoute(a)
	return func(length int, alreadyPresent bool) {
		observation := IngressObjectBodyObservation{Route: route, ObservedUnixMillis: time.Now().UnixMilli(), AcceptedBodyBytes: length}
		if alreadyPresent {
			observation.AlreadyPresentBodyBytes = length
		}
		select {
		case v.ingressBodies <- observation:
		default:
		}
	}
}

func (m IngressObjectBodyObservation) valid() bool {
	return storage.ID(m.Route) && m.ObservedUnixMillis > 0 &&
		m.AcceptedBodyBytes > 0 && m.AcceptedBodyBytes <= generation.MaxObject &&
		(m.AlreadyPresentBodyBytes == 0 || m.AlreadyPresentBodyBytes == m.AcceptedBodyBytes)
}

func (w *Worker) recordObjectBodies(v *view) {
	for {
		select {
		case <-v.ctx.Done():
			return
		case observation := <-v.ingressBodies:
			ctx, cancel := context.WithTimeout(v.ctx, 150*time.Millisecond)
			_ = w.writeIngressObjectBody(ctx, observation)
			cancel()
		case observation := <-v.peerObjectBodies:
			ctx, cancel := context.WithTimeout(v.ctx, 150*time.Millisecond)
			_ = w.writePeerObjectBody(ctx, observation)
			cancel()
		}
	}
}

func (w *Worker) writeIngressObjectBody(ctx context.Context, observation IngressObjectBodyObservation) error {
	if w.budget == nil || !observation.valid() || observation.ObservedUnixMillis > time.Now().UnixMilli() {
		return ErrDenied
	}
	if err := w.check(ctx); err != nil {
		return err
	}
	store, err := statefile.OpenAt(w.root, ingressBodiesDirectory, maxIngressBodyObservation, true)
	if err != nil {
		return err
	}
	defer store.Close()
	key := w.cert.PrivateKey.(ed25519.PrivateKey)
	// The active view has one writer under the worker's execution lease.
	prior, valid := readIngressObjectBody(store, observation.Route, key.Public().(ed25519.PublicKey))
	if valid && prior.ObservedUnixMillis > observation.ObservedUnixMillis {
		return nil
	}
	store.Admit = func(name string, size int) (func(bool) error, error) {
		if err := w.check(ctx); err != nil {
			return nil, err
		}
		return w.budget.Reserve(ctx, ingressBodiesDirectory+"/"+name, size)
	}
	record := signedIngressBodyObservation{Format: ingressBodiesFormat, IngressObjectBodyObservation: observation}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	record.Signature = ed25519.Sign(key, append([]byte(ingressBodiesFormat+"\x00"), raw...))
	raw, err = json.Marshal(record)
	if err != nil {
		return err
	}
	if err = w.check(ctx); err != nil {
		return err
	}
	return store.Write(observation.Route+".json", raw)
}

func readIngressObjectBody(store *statefile.Store, route string, key ed25519.PublicKey) (IngressObjectBodyObservation, bool) {
	raw, err := store.Read(route + ".json")
	var record signedIngressBodyObservation
	if err != nil || storage.Decode(raw, &record, maxIngressBodyObservation) != nil ||
		record.Format != ingressBodiesFormat || record.Route != route || !record.valid() {
		return IngressObjectBodyObservation{}, false
	}
	signature := record.Signature
	record.Signature = nil
	raw, err = json.Marshal(record)
	if err != nil || !ed25519.Verify(key, append([]byte(ingressBodiesFormat+"\x00"), raw...), signature) {
		return IngressObjectBodyObservation{}, false
	}
	return record.IngressObjectBodyObservation, true
}

// LocalStatus adds optional telemetry to CLI output only. It is not a worker
// journal format, management report, or copy/recovery receipt.
type LocalStatus struct {
	Status
	IngressObjectBodyObservations []IngressObjectBodyObservation `json:"ingressObjectBodyObservations,omitempty"`
}

func (w *Worker) LocalStatus(ctx context.Context) (LocalStatus, error) {
	status, err := w.Status(ctx)
	out := LocalStatus{Status: status}
	if err != nil || !w.observeIngressObjectBodies || w.check(ctx) != nil {
		return out, err
	}
	raw, err := w.cache.Raw(ctx)
	if err != nil {
		return out, nil
	}
	now := time.Now()
	cfg, err := w.cache.Verify(raw)
	if err != nil || cfg.Active(now) != nil {
		return out, nil
	}
	store, err := statefile.OpenAt(w.root, ingressBodiesDirectory, maxIngressBodyObservation, false)
	if err != nil {
		return out, nil
	}
	defer store.Close()
	key := w.cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	for _, raw := range cfg.Ingress {
		authority, err := ingress.VerifyAuthority(raw, w.owner, now)
		if err != nil || authority.Ingress != w.node {
			continue
		}
		domain, ok := cfg.DomainByID(authority.Trust.Domain)
		if !ok || !domain.Placement.HasEdge(authority.Source, authority.Ingress, "push") {
			continue
		}
		result, ok := readIngressObjectBody(store, ingressBodyRoute(authority), key)
		if ok && result.ObservedUnixMillis <= now.UnixMilli() {
			out.IngressObjectBodyObservations = append(out.IngressObjectBodyObservations, result)
		}
	}
	if len(out.IngressObjectBodyObservations) != 0 {
		// Route reads can span a config renewal. Keep the optional projection
		// only if the same signed policy is still current at readback.
		if w.check(ctx) != nil {
			out.IngressObjectBodyObservations = nil
			return out, nil
		}
		latest, err := w.cache.Raw(ctx)
		if err != nil || !bytes.Equal(latest, raw) || cfg.Active(time.Now()) != nil {
			out.IngressObjectBodyObservations = nil
		}
	}
	return out, nil
}
