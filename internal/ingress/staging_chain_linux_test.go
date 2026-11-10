package ingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func TestStagedCiphertextSurvivesTwoAuthorizedHopsAndBridgeReopen(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	ca := newCA(t)
	sourceCert, firstCert, bridgeCert, finalCert := ca.node(t), ca.node(t), ca.node(t), ca.node(t)
	firstID, bridgeID, finalID := certID(t, firstCert), certID(t, bridgeCert), certID(t, finalCert)
	f := setupIDs(t, certID(t, sourceCert), firstID)

	payload := bytes.Repeat([]byte("synthetic source payload"), 64)
	must(t, os.WriteFile(f.input, payload, 0600))
	version, err := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"data"}})
	must(t, err)
	catalog, objects := f.catalog(t, []string{version.Version})
	for id, ref := range f.session.refs {
		objects[id], err = f.session.Read(ctx, filekit.Object{ID: ref.ID, Bytes: ref.Bytes})
		must(t, err)
	}
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil

	// This accepted object is deliberately outside the signed closure.
	extra := []byte("unreferenced staged ciphertext")
	extraID := storage.Hash(extra)
	objects[extraID] = extra
	required, err := generation.Dependencies(catalog, f.authority.Trust)
	must(t, err)
	if len(required) == 0 {
		t.Fatal("fixture has no catalog dependencies")
	}
	probe := filekit.Object{ID: required[0].ID, Bytes: required[0].Bytes}
	limits := peer.Limits{Concurrency: 1, Timeout: 60 * time.Second, Attempts: 1}
	newOptions := func(name, id string, cert tls.Certificate, replica *generation.Replica, staging *StagingRoutes) (RegistryOptions, []byte) {
		t.Helper()
		authority := f.authority
		authority.Ingress = id
		grant, err := SignAuthority(authority, f.control)
		must(t, err)
		intent := f.intent
		intent.Ingress = id
		intent.Authority = storage.Hash(grant)
		raw, err := SignIntent(intent, grant, f.options.Owner, f.writer, time.Now())
		must(t, err)
		return RegistryOptions{
			Directory: filepath.Join(f.base, name+"-ingress"), Authority: grant, Owner: f.options.Owner,
			Replica: replica, Certificate: cert, Roots: ca.roots, Limits: limits, Initialize: true, Staging: staging,
		}, raw
	}
	open := func(o RegistryOptions, intent []byte, id string) (*Client, string, func()) {
		t.Helper()
		registry, err := OpenRegistry(ctx, o)
		must(t, err)
		server := httptest.NewUnstartedServer(registry)
		server.TLS, err = peer.AuthenticatedServerTLS(o.Certificate, ca.roots, id)
		must(t, err)
		server.StartTLS()
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				server.Close()
				must(t, registry.Close())
			}
		}
		t.Cleanup(stop)
		client, err := NewClient(server.URL, o.Authority, intent, o.Owner, sourceCert, ca.roots, limits)
		must(t, err)
		t.Cleanup(client.Close)
		return client, server.URL, stop
	}
	newReplica := func(name string) (*generation.Replica, string) {
		t.Helper()
		dir := filepath.Join(f.base, name+"-replica")
		must(t, os.Mkdir(dir, 0700))
		replica, err := generation.Open(dir, f.authority.Trust, true)
		must(t, err)
		t.Cleanup(func() { must(t, replica.Close()) })
		return replica, dir
	}

	firstOptions, firstIntent := newOptions("first", firstID, firstCert, f.options.Replica,
		&StagingRoutes{Readers: map[string]bool{bridgeID: true}})
	first, firstURL, stopFirst := open(firstOptions, firstIntent, firstID)
	bridgeReplica, _ := newReplica("bridge")
	bridgeRoutes := &StagingRoutes{Origins: map[string]string{firstID: firstURL}, Readers: map[string]bool{finalID: true}}
	bridgeOptions, bridgeIntent := newOptions("bridge", bridgeID, bridgeCert, bridgeReplica, bridgeRoutes)
	bridge, _, stopBridge := open(bridgeOptions, bridgeIntent, bridgeID)
	must(t, first.Begin(ctx))
	must(t, bridge.Begin(ctx))
	for id, data := range objects {
		ref := filekit.Object{ID: id, Bytes: len(data)}
		_, err = first.Write(ctx, ref, data)
		must(t, err)
		must(t, bridge.PullStaged(ctx, first, ref))
	}
	stopFirst()
	stopBridge()

	bridgeOptions.Initialize = false
	bridge, bridgeURL, stopBridge := open(bridgeOptions, bridgeIntent, bridgeID)
	delete(bridgeRoutes.Readers, finalID)
	finalReplica, finalDir := newReplica("final")
	finalRoutes := &StagingRoutes{Origins: map[string]string{bridgeID: bridgeURL}}
	finalOptions, finalIntent := newOptions("final", finalID, finalCert, finalReplica, finalRoutes)
	final, _, stopFinal := open(finalOptions, finalIntent, finalID)
	finalRoutes.Origins[firstID] = firstURL
	must(t, final.Begin(ctx))
	if err := final.PullStaged(ctx, first, probe); !errors.Is(err, ErrDenied) {
		t.Fatalf("caller mutation enabled a direct shortcut: %v", err)
	}
	if _, receipt, err := final.FinishStep(ctx, catalog); !errors.Is(err, ErrIncomplete) || receipt != nil {
		t.Fatalf("incomplete capture published: receipt %v, error %v", receipt, err)
	}
	for id, data := range objects {
		must(t, final.PullStaged(ctx, bridge, filekit.Object{ID: id, Bytes: len(data)}))
	}
	inventory, err := finalReplica.Inventory(ctx)
	must(t, err)
	if len(inventory) != 0 {
		t.Fatal("unsealed ciphertext was listed as a complete generation")
	}
	stopBridge()
	must(t, final.PullStaged(ctx, bridge, probe))
	var receipt *Receipt
	for range len(required) + 1 {
		_, receipt, err = final.FinishStep(ctx, catalog)
		must(t, err)
		if receipt != nil {
			break
		}
		inventory, err = finalReplica.Inventory(ctx)
		must(t, err)
		if len(inventory) != 0 {
			t.Fatal("partially verified generation was listed as complete")
		}
	}
	if receipt == nil || receipt.Generation != storage.Hash(catalog) {
		t.Fatalf("unexpected complete receipt: %v", receipt)
	}
	if _, err := finalReplica.ReadObject(ctx, receipt.Generation, generation.Object{ID: extraID, Bytes: len(extra)}); !errors.Is(err, generation.ErrInvalid) {
		t.Fatalf("object outside the signed closure became visible: %v", err)
	}
	stopFinal()
	restored := filepath.Join(f.base, "independent-restore")
	_, err = generation.RecoverMaterialized(ctx, finalDir, receipt.Generation, f.authority.Trust, f.owner, generation.RecoverySelection{}, restored)
	must(t, err)
	data, err := os.ReadFile(filepath.Join(restored, "data"))
	must(t, err)
	if !bytes.Equal(data, payload) {
		t.Fatal("recovered bytes differ")
	}
}
