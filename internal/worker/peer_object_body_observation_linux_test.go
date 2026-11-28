package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerPeerObjectBodyAcknowledgementPersistsOnAuthorizedRoute(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.AttemptMillis = 60000
	f.endpoint(t, nil)
	sender, receiver := f.nodes[0], f.nodes[1]
	sender.observePeerObjectBodies = true
	var err error
	sender.peerBodies.Send, err = storage.NewHTTPBodyBudget(peer.MinBodyBytesPerSecond)
	must(t, err)
	receiver.peerBodies.Receive, err = storage.NewHTTPBodyBudget(peer.MinBodyBytesPerSecond)
	must(t, err)
	push, _ := f.jobs()
	f.config(t, 0, []control.Job{push})
	f.config(t, 1, []control.Job{push})
	ctx := context.Background()
	before, err := sender.PeerObjectTransferStatus(ctx, push.Domain, receiver.node)
	must(t, err)
	if before.Sample != nil {
		t.Fatal("no acknowledged object had been observed")
	}
	stopReceiver := start(t, receiver)
	defer stopReceiver()
	stopSender := start(t, sender)
	defer stopSender()
	waitFor(t, 90*time.Second, func() bool { return complete(sender, push.Operation) })
	var last PeerObjectTransferStatus
	wait(t, func() bool {
		local, err := sender.PeerObjectTransferStatus(ctx, push.Domain, receiver.node)
		must(t, err)
		last = local
		return local.Sample != nil
	})
	if last.Route != before.Route || last.Sample.Route != last.Route || last.Sample.ObservedUnixMillis < 1 ||
		last.Sample.TransportReadBodyBytes < 1 || last.Sample.TransportReadBodyBytes != last.Sample.AcknowledgedBodyBytes ||
		last.Sample.ElapsedNanos <= 0 || last.Sample.AlreadyPresentBodyBytes == nil || *last.Sample.AlreadyPresentBodyBytes != 0 {
		t.Fatalf("unexpected bound object observation: %+v", last.Sample)
	}
	stopSender()
	terminal, err := sender.PeerObjectTransferStatus(ctx, push.Domain, receiver.node)
	must(t, err)
	reopened, err := Open(Options{Directory: sender.dir, Node: sender.node, Owner: f.owner.Public().(ed25519.PublicKey),
		Certificate: sender.cert, Roots: f.ca.pool, ObservePeerObjectBodies: true})
	must(t, err)
	defer reopened.Close()
	after, err := reopened.PeerObjectTransferStatus(ctx, push.Domain, receiver.node)
	must(t, err)
	if terminal.Sample == nil || !reflect.DeepEqual(after.Sample, terminal.Sample) {
		t.Fatal("reopen changed the last recorded observation", after.Sample)
	}
	_, err = reopened.PeerObjectTransferStatus(ctx, push.Domain, f.nodes[2].node)
	if !errors.Is(err, ErrDenied) {
		t.Fatal("an undeclared route could read a sample", err)
	}
}

func TestWorkerPeerObjectBodyV2PreservesStrictLegacyReadback(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	sender, receiver := f.nodes[0], f.nodes[1]
	sender.observePeerObjectBodies = true
	push, _ := f.jobs()
	f.config(t, 0, []control.Job{push})
	ctx := context.Background()
	status := func() PeerObjectTransferStatus {
		s, err := sender.PeerObjectTransferStatus(ctx, push.Domain, receiver.node)
		must(t, err)
		return s
	}
	route := status().Route
	store, err := statefile.OpenAt(sender.root, peerBodiesDirectory, maxPeerBodyObservation, true)
	must(t, err)
	defer store.Close()
	key := sender.cert.PrivateKey.(ed25519.PrivateKey)
	const legacyFormat = "outpost-peer-object-body-1"
	type legacyRecord struct {
		Format                 string `json:"format"`
		Route                  string `json:"route"`
		ObservedUnixMillis     int64  `json:"observedUnixMillis"`
		TransportReadBodyBytes int    `json:"transportReadBodyBytes"`
		AcknowledgedBodyBytes  int    `json:"acknowledgedBodyBytes"`
		Signature              []byte `json:"signature,omitempty"`
	}
	const objectBytes = 163
	now := time.Now().UnixMilli()
	writeLegacy := func(observed int64) []byte {
		legacy := legacyRecord{legacyFormat, route, observed, objectBytes, objectBytes, nil}
		raw, err := json.Marshal(legacy)
		must(t, err)
		legacy.Signature = ed25519.Sign(key, append([]byte(legacyFormat+"\x00"), raw...))
		raw, err = json.Marshal(legacy)
		must(t, err)
		must(t, store.Write(route+".json", raw))
		return raw
	}
	legacyAt, v2At := now-1000, now-500
	legacyRaw := writeLegacy(legacyAt)
	if sample := status().Sample; sample == nil || sample.ObservedUnixMillis != legacyAt || sample.ElapsedNanos != 0 || sample.AlreadyPresentBodyBytes != nil {
		t.Fatalf("legacy reader fabricated evidence: %+v", sample)
	}
	alreadyPresent := objectBytes
	observation := PeerObjectBodyObservation{Route: route, PushedObjectBodyObservation: peer.PushedObjectBodyObservation{
		ObservedUnixMillis: v2At, TransportReadBodyBytes: objectBytes, AcknowledgedBodyBytes: objectBytes,
		ElapsedNanos: int64(30 * time.Millisecond), AlreadyPresentBodyBytes: &alreadyPresent,
	}}
	must(t, sender.writePeerObjectBody(ctx, observation))
	if sample := status().Sample; !reflect.DeepEqual(sample, &observation) {
		t.Fatalf("the exact v2 evidence was not returned: %+v", sample)
	}
	after, err := store.Read(route + ".json")
	must(t, err)
	var decoded legacyRecord
	must(t, storage.Decode(after, &decoded, maxPeerBodyObservation))
	if !bytes.Equal(after, legacyRaw) || decoded.ObservedUnixMillis != legacyAt {
		t.Fatal("v2 changed signed legacy bytes or strict legacy decoder output")
	}
	bad := observation
	wrongLength := objectBytes - 1
	bad.AlreadyPresentBodyBytes = &wrongLength
	if err = sender.writePeerObjectBody(ctx, bad); !errors.Is(err, ErrDenied) {
		t.Fatalf("impossible already-present byte count accepted: %v", err)
	}
	v2Raw, err := store.Read(route + ".v2.json")
	must(t, err)
	must(t, store.Write(route+".v2.json", append(bytes.Clone(v2Raw), '\n')))
	if sample := status().Sample; sample == nil || sample.ObservedUnixMillis != legacyAt || sample.AlreadyPresentBodyBytes != nil {
		t.Fatalf("malformed newer record hid valid older evidence: %+v", sample)
	}
	must(t, store.Write(route+".v2.json", v2Raw))
	newLegacyAt := now - 250
	writeLegacy(newLegacyAt)
	if sample := status().Sample; sample == nil || sample.ObservedUnixMillis != newLegacyAt || sample.ElapsedNanos != 0 || sample.AlreadyPresentBodyBytes != nil {
		t.Fatalf("legacy writer after downgrade did not become the latest historical sample: %+v", sample)
	}
}
