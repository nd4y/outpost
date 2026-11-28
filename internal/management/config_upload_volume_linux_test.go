package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

func TestManagementConfigurationPreviewUsesSignedUploadVolume(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	f.enroll(t)
	ctx := t.Context()
	cfg := configFixture(t, f)
	writer, writerKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	planner, plannerKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	domain := &cfg.Domains[0]
	domain.Trust.Writer = writer
	domain.Planner = planner
	profile := storage.Profile{Kind: "webdav", Endpoint: "https://never-contact.invalid/objects",
		Namespace: id(domain.Trust.Domain + "/" + domain.Trust.Repository), MaxObjectBytes: 64 << 10,
		Concurrency: 1, RequestsPerSecond: 1, Attempts: 1, TimeoutMillis: 1000,
		CredentialScope: "namespace", NoDelete: true}
	target := profile.ID()
	cfg.Targets = []control.Target{{ID: target, Profile: profile}}
	domain.Placement.Targets = []string{target}
	domain.Placement.AllowedClasses = []string{"trusted", "external"}
	domain.Placement.CloudEdges = []policy.CloudEdge{{Node: cfg.Node, Target: target}}

	common := bytes.Repeat([]byte{0xc5}, profile.MaxObjectBytes)
	root := []byte("encrypted test root")
	a, b := append(bytes.Clone(common), 1), append(bytes.Clone(common), 2)
	ref := func(data []byte) generation.Object {
		return generation.Object{ID: storage.Hash(data), Bytes: len(data)}
	}
	rootRef, aRef, bRef := ref(root), ref(a), ref(b)
	objects := []generation.Object{aRef, bRef}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	now := time.Now()
	catalog, err := generation.SignCatalog(generation.Catalog{
		Format: generation.Format, KitFormat: generation.KitFormat,
		Domain: domain.Trust.Domain, Repository: domain.Trust.Repository, Epoch: domain.Trust.Epoch,
		Sequence: 1, SnapshotUnix: now.Unix(), Policy: 1,
		Kits: []generation.Kit{{File: id("file"), Version: id("version"), Root: rootRef, Objects: objects}},
	}, writerKey)
	must(t, err)
	generationID := storage.Hash(catalog)
	operation := id("planned-upload")
	payloads := map[string][]byte{rootRef.ID: root, aRef.ID: a, bRef.ID: b}
	rawPlan, err := upload.BuildFromCatalog(ctx, domain.Trust, generationID, catalog, upload.Plan{
		Format: upload.Format, Operation: operation, Profile: profile,
		AllowExternal: true, AllowedClasses: []string{"trusted"},
		Workers:     []upload.Worker{{ID: f.e.Node, Class: "trusted", PublicKey: f.e.PublicKey}},
		StartMillis: now.UnixMilli(), ExpiresUnix: cfg.ExpiresUnix, SlotMillis: 2000,
	}, plannerKey, func(_ context.Context, object generation.Object) ([]byte, error) {
		return payloads[object.ID], nil
	})
	must(t, err)
	cfg.Jobs = []control.Job{{Kind: "upload", Operation: operation, Executor: cfg.Node,
		Domain: domain.Trust.Domain, Target: target, Generation: generationID, Plan: rawPlan}}
	input := configurationMutation(t, f, cfg, "preview-upload-volume", 0)
	before, err := f.r.store.Read("registry.json")
	must(t, err)
	path := h.base() + "/configuration/preview"
	enabled := path + "?include=declared-upload-volume"
	status, raw := h.request(t, h.owner, http.MethodPost, enabled, input)
	if status != http.StatusOK {
		t.Fatalf("upload volume preview: %d %s", status, raw)
	}
	var preview UploadVolumePreview
	must(t, json.Unmarshal(raw, &preview))
	expected := DeclaredUploadVolume{
		Operation: operation, Domain: domain.Trust.Domain, Target: target, Generation: generationID,
		UniquePartBytes: int64(len(common) + 2 + len(root)), UniqueParts: 4, CatalogBytes: len(catalog),
	}
	if preview.Format != UploadVolumePreviewFormat || len(preview.UploadVolumes) != 1 ||
		preview.UploadVolumes[0] != expected || preview.Preview.CapacityState != "UNKNOWN" ||
		preview.Preview.EstimatedBytes != nil || preview.Preview.CandidateDigest != storage.Hash(input.Document) ||
		bytes.Contains(raw, []byte(profile.Endpoint)) {
		t.Fatal("scope, volume or capacity meaning differs", preview)
	}

	status, raw = h.request(t, h.owner, http.MethodPost, path, input)
	legacy, err := json.Marshal(preview.Preview)
	must(t, err)
	if status != http.StatusOK || !bytes.Equal(bytes.TrimSpace(raw), legacy) {
		t.Fatalf("legacy preview changed: %d %s", status, raw)
	}
	status, _ = h.request(t, h.viewer, http.MethodPost, enabled, input)
	if status != http.StatusForbidden {
		t.Fatal("viewer received candidate upload volumes", status)
	}
	bad := cfg
	bad.Jobs = append([]control.Job(nil), cfg.Jobs...)
	bad.Jobs[0].Target = id("other-target")
	unsigned, err := json.Marshal(bad)
	must(t, err)
	bad.Signature = ed25519.Sign(f.owner, append([]byte(bad.Format+"\x00"), unsigned...))
	tampered := input
	tampered.Document, err = json.Marshal(bad)
	must(t, err)
	status, _ = h.request(t, h.owner, http.MethodPost, enabled, tampered)
	if status != http.StatusForbidden {
		t.Fatal("misbound signed upload plan was not refused", status)
	}

	cfg.Jobs = nil
	empty := configurationMutation(t, f, cfg, "preview-without-upload-plan", 0)
	status, raw = h.request(t, h.owner, http.MethodPost, enabled, empty)
	var noVolumes UploadVolumePreview
	must(t, json.Unmarshal(raw, &noVolumes))
	if status != http.StatusOK || noVolumes.UploadVolumes == nil || len(noVolumes.UploadVolumes) != 0 {
		t.Fatal("missing plan produced an invented volume", status, noVolumes)
	}
	after, err := f.r.store.Read("registry.json")
	must(t, err)
	if !bytes.Equal(after, before) {
		t.Fatal("preview changed durable registry state")
	}
}
