package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func TestStagedOriginAvailabilityDistinguishesTransportAndPolicyErrors(t *testing.T) {
	for _, test := range []struct {
		err         error
		unavailable bool
	}{
		{&net.DNSError{Err: "no such host", Name: "peer.invalid", IsNotFound: true}, true},
		{syscall.ETIMEDOUT, true},
		{context.DeadlineExceeded, true},
		{context.Canceled, false},
		{ErrDenied, false},
		{ErrProtocol, false},
	} {
		err := &url.Error{Op: "GET", URL: "https://peer.invalid", Err: test.err}
		if got := stagedOriginUnavailable(err); got != test.unavailable {
			t.Errorf("availability of %v = %t, want %t", err, got, test.unavailable)
		}
	}
}

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
	withdrawn := []byte("staged ciphertext for a withdrawn primary route")
	withdrawnRef := filekit.Object{ID: storage.Hash(withdrawn), Bytes: len(withdrawn)}
	objects[withdrawnRef.ID] = withdrawn
	required, err := generation.Dependencies(catalog, f.authority.Trust)
	must(t, err)
	if len(required) < 2 {
		t.Fatal("fixture needs two distinct catalog dependencies")
	}
	probe := filekit.Object{ID: required[0].ID, Bytes: required[0].Bytes}
	fallbackRef := filekit.Object{ID: required[1].ID, Bytes: required[1].Bytes}
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
	open := func(o RegistryOptions, intent []byte, id string) (*Client, *Registry, string, func()) {
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
		return client, registry, server.URL, stop
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
	first, _, firstURL, stopFirst := open(firstOptions, firstIntent, firstID)
	bridgeReplica, _ := newReplica("bridge")
	bridgeRoutes := &StagingRoutes{Origins: map[string]string{firstID: firstURL}, Readers: map[string]bool{finalID: true}}
	bridgeOptions, bridgeIntent := newOptions("bridge", bridgeID, bridgeCert, bridgeReplica, bridgeRoutes)
	bridge, _, _, stopBridge := open(bridgeOptions, bridgeIntent, bridgeID)
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
	bridge, _, bridgeURL, stopBridge := open(bridgeOptions, bridgeIntent, bridgeID)
	delete(bridgeRoutes.Readers, finalID)
	finalReplica, finalDir := newReplica("final")
	finalRoutes := &StagingRoutes{Origins: map[string]string{bridgeID: bridgeURL}}
	finalOptions, finalIntent := newOptions("final", finalID, finalCert, finalReplica, finalRoutes)
	final, finalRegistry, _, stopFinal := open(finalOptions, finalIntent, finalID)
	finalRoutes.Origins[firstID] = firstURL
	must(t, final.Begin(ctx))
	if err := final.PullStaged(ctx, first, probe); !errors.Is(err, ErrDenied) {
		t.Fatalf("caller mutation enabled a direct shortcut: %v", err)
	}
	if _, receipt, err := final.FinishStep(ctx, catalog); !errors.Is(err, ErrIncomplete) || receipt != nil {
		t.Fatalf("incomplete capture published: receipt %v, error %v", receipt, err)
	}
	if err := final.QueueStaged(ctx, first, probe); !errors.Is(err, ErrDenied) {
		t.Fatalf("queued request used a forbidden shortcut: %v", err)
	}
	stopFinal()
	delete(finalRoutes.Origins, firstID)
	finalOptions.Initialize = false
	killStagedImport(t, ctx, finalOptions, finalDir, ca.cert.Raw, &stagedImportAdmission{
		Target: finalIntent, SourceCertificate: sourceCert.Certificate[0], SourcePrivateKey: sourceCert.PrivateKey.(ed25519.PrivateKey),
		Origin: stagingOrigin{Authority: bridgeOptions.Authority, Intent: bridgeIntent}, OriginEndpoint: bridgeURL, Object: probe,
	})
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if err := final.QueueStaged(ctx, bridge, filekit.Object{ID: extraID, Bytes: len(extra)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second request replaced the pending import: %v", err)
	}
	if err := final.Check(ctx, probe); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("queued acceptance was mistaken for object presence: %v", err)
	}
	must(t, final.QueueStaged(ctx, bridge, probe))
	must(t, final.QueueStaged(ctx, bridge, probe))
	stopFinal()
	unpaused := func(string) bool { return false }
	delete(finalRoutes.Origins, bridgeID)
	_, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); err != nil || advanced {
		t.Fatalf("withdrawn route was used: %v, %v", advanced, err)
	}
	stopFinal()
	finalRoutes.Origins[bridgeID] = bridgeURL
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, func(op string) bool { return op == f.intent.Operation }); err != nil || advanced {
		t.Fatalf("paused capture advanced: %v, %v", advanced, err)
	}
	for id, data := range objects {
		if id != probe.ID && id != extraID && id != fallbackRef.ID && id != withdrawnRef.ID {
			must(t, final.PullStaged(ctx, bridge, filekit.Object{ID: id, Bytes: len(data)}))
		}
	}
	inventory, err := finalReplica.Inventory(ctx)
	must(t, err)
	if len(inventory) != 0 {
		t.Fatal("unsealed ciphertext was listed as a complete generation")
	}
	stopFinal()
	killStagedImport(t, ctx, finalOptions, finalDir, ca.cert.Raw, nil)
	stopBridge()
	delete(finalRoutes.Origins, bridgeID)
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	must(t, final.Check(ctx, probe))
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); err != nil || !advanced {
		t.Fatalf("verified local object did not clear the queue after route withdrawal: %v, %v", advanced, err)
	}
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); err != nil || advanced {
		t.Fatalf("completed request did not leave the queue: %v, %v", advanced, err)
	}
	stopFinal()
	finalRoutes.Origins[bridgeID] = bridgeURL
	final, _, _, stopFinal = open(finalOptions, finalIntent, finalID)
	must(t, final.PullStaged(ctx, bridge, probe))

	extraRef := filekit.Object{ID: extraID, Bytes: len(extra)}
	must(t, final.QueueStaged(ctx, bridge, extraRef))
	stopFinal()
	firstOptions.Initialize = false
	firstOptions.Staging.Readers[finalID] = true
	first, _, firstURL, stopFirst = open(firstOptions, firstIntent, firstID)
	finalRoutes.Origins[firstID] = firstURL
	final, _, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if err := final.QueueStaged(ctx, first, extraRef); !errors.Is(err, ErrConflict) {
		t.Fatalf("queued import switched while its old route remained admitted: %v", err)
	}
	stopFinal()
	delete(finalRoutes.Origins, bridgeID)
	final, _, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if err := final.QueueStaged(ctx, bridge, extraRef); !errors.Is(err, ErrDenied) {
		t.Fatalf("withdrawn origin still admitted a request: %v", err)
	}
	other := filekit.Object{ID: storage.Hash([]byte("different object")), Bytes: len("different object")}
	if err := final.QueueStaged(ctx, first, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement changed the queued object: %v", err)
	}
	must(t, final.QueueStaged(ctx, first, extraRef))
	stopFinal()
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); err != nil || !advanced {
		t.Fatalf("rebound import did not finish with the bridge offline: %v, %v", advanced, err)
	}
	must(t, final.Check(ctx, extraRef))

	// The primary is still allowed by policy but offline. A fallback must
	// be admitted both when the source queues it and when the worker uses it.
	stopFinal()
	finalRoutes.Origins[bridgeID] = bridgeURL
	delete(finalRoutes.Origins, firstID)
	final, _, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if err := final.QueueStagedWithFallback(ctx, bridge, first, fallbackRef); !errors.Is(err, ErrDenied) {
		t.Fatalf("unadmitted fallback entered the queue: %v", err)
	}
	stopFinal()
	finalRoutes.Origins[firstID] = firstURL
	final, _, _, stopFinal = open(finalOptions, finalIntent, finalID)
	must(t, final.QueueStagedWithFallback(ctx, bridge, first, fallbackRef))
	must(t, final.QueueStagedWithFallback(ctx, bridge, first, fallbackRef))
	if err := final.QueueStaged(ctx, bridge, fallbackRef); !errors.Is(err, ErrConflict) {
		t.Fatalf("nonidentical request replaced the fallback: %v", err)
	}
	stopFinal()
	delete(finalRoutes.Origins, firstID)
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); !errors.Is(err, ErrDenied) || advanced {
		t.Fatalf("withdrawn fallback was used: %v, %v", advanced, err)
	}
	if err := final.Check(ctx, fallbackRef); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object arrived through the withdrawn fallback: %v", err)
	}
	stopFinal()
	finalRoutes.Origins[firstID] = firstURL
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); err != nil || !advanced {
		t.Fatalf("admitted fallback did not finish with the primary offline: %v, %v", advanced, err)
	}
	must(t, final.Check(ctx, fallbackRef))
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); err != nil || advanced {
		t.Fatalf("completed fallback did not leave the queue: %v, %v", advanced, err)
	}

	// Remote denial on an admitted route still stops the attempt. Removing
	// that route locally lets the worker use the independently admitted fallback.
	stopFinal()
	delete(bridgeRoutes.Readers, finalID)
	bridge, _, bridgeURL, stopBridge = open(bridgeOptions, bridgeIntent, bridgeID)
	finalRoutes.Origins[bridgeID] = bridgeURL
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	must(t, final.QueueStagedWithFallback(ctx, bridge, first, withdrawnRef))
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); !errors.Is(err, ErrDenied) || advanced {
		t.Fatalf("remote denial should stop the queued import: %v, %v", advanced, err)
	}
	if err := final.Check(ctx, withdrawnRef); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remote denial allowed fallback: %v", err)
	}
	stopFinal()
	delete(finalRoutes.Origins, bridgeID)
	final, finalRegistry, _, stopFinal = open(finalOptions, finalIntent, finalID)
	if advanced, err := finalRegistry.AdvanceStagedImport(ctx, unpaused); err != nil || !advanced {
		t.Fatalf("still admitted fallback did not finish after primary withdrawal: %v, %v", advanced, err)
	}
	must(t, final.Check(ctx, withdrawnRef))
	stopBridge()
	stopFirst()

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
