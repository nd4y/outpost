package management

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
)

func TestManagementConfigurationPreviewUsesSignedPeerCatalog(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	f.enroll(t)
	ctx := t.Context()
	cfg := configFixture(t, f)
	domain := &cfg.Domains[0]
	writer, writerKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	domain.Trust.Writer = writer
	peerKey, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	peer := f.e
	peer.Node, peer.PublicKey = identity(peerKey), peerKey
	peerEnrollment, err := SignEnrollment(peer, f.owner)
	must(t, err)
	_, err = f.r.ApplyEnrollment(ctx, f.p, id("enroll-peer-volume-node"), "INITIAL_ENROLLMENT", peerEnrollment, 0)
	must(t, err)
	const endpoint = "https://never-contact-peer.invalid"
	cfg.Nodes = append(cfg.Nodes, policy.Node{ID: peer.Node, Class: "trusted", Endpoint: endpoint})
	domain.Placement.Holders = append(domain.Placement.Holders, peer.Node)
	domain.Placement.Edges = []policy.Edge{{From: cfg.Node, To: peer.Node, Mode: "push"}, {From: peer.Node, To: cfg.Node, Mode: "pull"}}
	object := generation.Object{ID: id("peer-volume-common"), Bytes: 64}
	catalog := generation.Catalog{
		Format: generation.Format, KitFormat: generation.KitFormat, Domain: domain.Trust.Domain,
		Repository: domain.Trust.Repository, Epoch: domain.Trust.Epoch, Sequence: 1, SnapshotUnix: time.Now().Unix(), Policy: 1,
		Kits: []generation.Kit{
			{File: "0000000000000000000000000000000000000000000000000000000000000001", Version: id("v1"),
				Root: generation.Object{ID: id("private-root-a"), Bytes: 28}, Objects: []generation.Object{object}},
			{File: "0000000000000000000000000000000000000000000000000000000000000002", Version: id("v2"),
				Root: generation.Object{ID: id("private-root-b"), Bytes: 30}, Objects: []generation.Object{object}},
		},
	}
	catalogRaw, err := generation.SignCatalog(catalog, writerKey)
	must(t, err)
	gen := storage.Hash(catalogRaw)
	push, pull := id("preview-peer-push"), id("preview-peer-pull")
	cfg.Jobs = []control.Job{
		{Operation: push, Kind: "push", Domain: domain.Trust.Domain, Peer: peer.Node, Executor: cfg.Node, PeerRevision: 1, Generation: gen},
		{Operation: pull, Kind: "pull", Domain: domain.Trust.Domain, Peer: peer.Node, Executor: cfg.Node, PeerRevision: 1, Generation: gen},
	}
	input := configurationMutation(t, f, cfg, "preview-peer-catalog", 0)
	request := PeerVolumeRequest{Mutation: input, PeerOperation: push, Catalog: catalogRaw}
	path := h.base() + "/configuration/preview"
	pathPeer := path + "?include=declared-peer-volume"
	before, err := f.r.store.Read("registry.json")
	must(t, err)
	var projection PeerVolumePreview
	for _, row := range []struct{ op, mode, from, to string }{
		{push, "push", cfg.Node, peer.Node}, {pull, "pull", peer.Node, cfg.Node},
	} {
		request.PeerOperation = row.op
		status, raw := h.request(t, h.owner, http.MethodPost, pathPeer, request)
		if status != http.StatusOK {
			t.Fatalf("peer volume preview: %d %s", status, raw)
		}
		must(t, json.Unmarshal(raw, &projection))
		expected := DeclaredPeerVolume{Operation: row.op, Mode: row.mode, From: row.from, To: row.to, Domain: domain.Trust.Domain,
			Generation: gen, UniqueObjects: 3, UniqueObjectBytes: 122, CatalogBytes: len(catalogRaw)}
		if projection.Format != PeerVolumePreviewFormat || projection.PeerVolume != expected ||
			projection.UploadVolumes == nil || len(projection.UploadVolumes) != 0 ||
			projection.Preview.CapacityState != "UNKNOWN" || projection.Preview.EstimatedBytes != nil ||
			projection.Preview.CandidateDigest != storage.Hash(input.Document) ||
			bytes.Contains(raw, []byte(endpoint)) || bytes.Contains(raw, []byte(object.ID)) {
			t.Fatal("incorrect route, a private object was echoed, or capacity was implied", projection)
		}
	}
	status, raw := h.request(t, h.owner, http.MethodPost, path, input)
	legacy, err := json.Marshal(projection.Preview)
	must(t, err)
	if status != http.StatusOK || !bytes.Equal(bytes.TrimSpace(raw), legacy) {
		t.Fatalf("legacy preview changed: %d %s", status, raw)
	}

	// A correctly signed candidate cannot make a catalog signed by a foreign
	// writer (or from another epoch) authoritative for its exact generation.
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	otherWriter, err := generation.SignCatalog(catalog, wrongKey)
	must(t, err)
	foreignEpoch := catalog
	foreignEpoch.Epoch++
	wrongEpoch, err := generation.SignCatalog(foreignEpoch, writerKey)
	must(t, err)
	for _, bad := range [][]byte{otherWriter, wrongEpoch} {
		wrong := cfg
		wrong.Jobs = append([]control.Job(nil), cfg.Jobs...)
		wrong.Jobs[0].Generation = storage.Hash(bad)
		wrongInput := configurationMutation(t, f, wrong, "preview-foreign-peer-catalog", 0)
		got, _ := h.request(t, h.owner, http.MethodPost, pathPeer, PeerVolumeRequest{wrongInput, push, bad})
		if got != http.StatusForbidden {
			t.Fatalf("foreign catalog authorized: %d", got)
		}
	}
	for _, bad := range []PeerVolumeRequest{
		{input, id("unassigned-peer-job"), catalogRaw}, {input, push, otherWriter}, {input, push, nil},
	} {
		got, _ := h.request(t, h.owner, http.MethodPost, pathPeer, bad)
		if got != http.StatusForbidden && got != http.StatusBadRequest {
			t.Fatalf("misbound peer evidence accepted: %d", got)
		}
	}
	status, _ = h.request(t, h.viewer, http.MethodPost, pathPeer, request)
	if status != http.StatusForbidden {
		t.Fatal("viewer received candidate volume", status)
	}
	after, err := f.r.store.Read("registry.json")
	must(t, err)
	if !bytes.Equal(after, before) {
		t.Fatal("preview changed durable registry state")
	}
	peer.Revision++
	peer.Revoked = true
	revocation, err := SignEnrollment(peer, f.owner)
	must(t, err)
	f.r.Fault = interruptAt("management-enrollment-intent-durable")
	_, err = f.r.ApplyEnrollment(ctx, f.p, id("peer-volume-pending-revocation"), "REVOKE", revocation, peer.Revision-1)
	f.r.Fault = nil
	if err == nil {
		t.Fatal("missing durable pending revocation")
	}
	status, _ = h.request(t, h.owner, http.MethodPost, pathPeer, request)
	if status != http.StatusConflict {
		t.Fatal("pending peer revocation did not fence preview", status)
	}
}
