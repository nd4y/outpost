package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestHolderEpochTransitionRevokesOldBranchAndPreservesIndependentHistory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.cfg.Limits.AttemptMillis = 60000
	server := f.endpoint(t, nil)
	oldPush, _ := f.jobs()
	f.config(t, 0, []control.Job{oldPush})
	previous := f.config(t, 1, []control.Job{oldPush})
	oldPolicy, e := control.Sign(previous, f.owner)
	must(t, e)
	stopB := start(t, f.nodes[1])
	stopA := start(t, f.nodes[0])
	waitFor(t, 90*time.Second, func() bool { return complete(f.nodes[0], oldPush.Operation) })
	stopA()
	stopB()
	oldTrust := f.domain.Trust
	oldReplicaPath := filepath.Join(DomainDirectory(f.nodes[1].dir, oldTrust), "replica")
	oldReplica, e := generation.Open(oldReplicaPath, oldTrust, false)
	must(t, e)
	oldCatalog, e := oldReplica.Catalog(ctx, f.generation)
	must(t, e)
	must(t, oldReplica.VerifyComplete(ctx, f.generation))
	must(t, oldReplica.Close())

	// The owner prepares new encryption and signing material outside all workers.
	// The logical domain/repository is retained; its writer epoch advances.
	nextOwner, e := filekit.NewOwner()
	must(t, e)
	nextOwner.Domain = oldTrust.Domain
	writer, writerKey := key(t)
	maintenance, _ := key(t)
	planner, _ := key(t)
	nextDomain := f.domain
	nextDomain.Trust = generation.Trust{Domain: oldTrust.Domain, Repository: oldTrust.Repository, Epoch: oldTrust.Epoch + 1, Writer: writer, Maintenance: maintenance}
	nextDomain.Planner = planner
	newContent := make([]byte, len(f.content))
	_, e = rand.Read(newContent)
	must(t, e)
	input := filepath.Join(f.base, "epoch-two-input")
	must(t, os.WriteFile(input, newContent, 0640))
	store, e := filekit.OpenStore(filepath.Join(f.base, "epoch-two-owner-store"), nextOwner, true)
	must(t, e)
	version, e := store.Backup(ctx, input, filekit.BackupOptions{Names: []string{"dataset/данные.bin"}})
	must(t, e)
	newSourcePath := filepath.Join(DomainDirectory(f.nodes[0].dir, nextDomain.Trust), "replica")
	must(t, os.MkdirAll(newSourcePath, 0700))
	source, e := generation.Open(newSourcePath, nextDomain.Trust, true)
	must(t, e)
	newGeneration, e := generation.Seal(ctx, store, []string{version.Version}, source, generation.Catalog{Format: generation.Format, Domain: nextDomain.Trust.Domain, Repository: nextDomain.Trust.Repository, Epoch: nextDomain.Trust.Epoch, Sequence: 1, SnapshotUnix: time.Now().Unix(), Policy: 2, KitFormat: generation.KitFormat}, writerKey)
	must(t, e)
	must(t, source.Close())
	must(t, store.Close())
	newPush := oldPush
	newPush.Operation = storage.Hash([]byte("epoch-two-transfer"))
	newPush.Generation = newGeneration
	newPush.PeerRevision = 2
	f.domain = nextDomain
	f.cfg.Revision = 2
	f.config(t, 0, []control.Job{newPush})
	f.config(t, 1, []control.Job{newPush})
	stopB = start(t, f.nodes[1])
	stopA = start(t, f.nodes[0])
	waitFor(t, 90*time.Second, func() bool { return complete(f.nodes[0], newPush.Operation) })
	if !errors.Is(f.nodes[1].Accept(ctx, oldPolicy), control.ErrRollback) {
		t.Fatal("old signed configuration replaced the current epoch")
	}
	// A current certificate and an old operation cannot make historical data
	// visible through the new worker view after its signed grant was withdrawn.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[0].cert}}}}
	defer client.CloseIdleConnections()
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/"+oldTrust.Domain+"/generations/"+f.generation+"/catalog", nil)
	must(t, e)
	request.Header.Set("Outpost-Operation", oldPush.Operation)
	request.Header.Set("Outpost-Mode", "push")
	response, e := client.Do(request)
	must(t, e)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("withdrawn old branch remained available", response.StatusCode)
	}
	stopA()
	stopB()
	server.Close()

	newReplicaPath := filepath.Join(DomainDirectory(f.nodes[1].dir, nextDomain.Trust), "replica")
	if oldReplicaPath == newReplicaPath {
		t.Fatal("successor overwrote the retained epoch directory")
	}
	current, e := generation.Open(newReplicaPath, nextDomain.Trust, false)
	must(t, e)
	fetched := false
	if _, e = current.Receive(ctx, oldCatalog, func(generation.Object) ([]byte, error) {
		fetched = true
		return nil, errors.New("old epoch payload must not be fetched")
	}); e == nil || fetched {
		t.Fatal("old signed catalog crossed the new epoch before verification", e, fetched)
	}
	status, e := current.Status(ctx)
	must(t, e)
	if status.LatestComplete != newGeneration || status.HighestSequence != 1 || len(status.Complete) != 1 || len(status.Receiving) != 0 {
		t.Fatal("old branch changed the successor's complete state", status)
	}
	must(t, current.Close())

	// Reopen the actual holder on its cached owner policy with no source/server.
	must(t, f.nodes[1].Close())
	holder, e := Open(Options{Directory: f.nodes[1].dir, Node: f.nodes[1].node, Owner: f.owner.Public().(ed25519.PublicKey), Certificate: f.nodes[1].cert, Roots: f.ca.pool})
	must(t, e)
	defer holder.Close()
	stop := start(t, holder)
	wait(t, func() bool {
		holder.mu.Lock()
		defer holder.mu.Unlock()
		return holder.active != nil && holder.active.cfg.Revision == 2
	})
	// A higher configuration revision does not reset the epoch floor.
	previous.Revision = 3
	rollback, e := control.Sign(previous, f.owner)
	must(t, e)
	if !errors.Is(holder.Accept(ctx, rollback), control.ErrRollback) {
		t.Fatal("holder reopen lost its persistent epoch floor")
	}
	stop()
	must(t, f.nodes[0].Close())
	must(t, os.Chmod(f.nodes[0].dir, 0000))
	defer func() { must(t, os.Chmod(f.nodes[0].dir, 0700)) }()
	if _, e = os.Stat(filepath.Join(f.nodes[0].dir, "domains")); !errors.Is(e, os.ErrPermission) {
		t.Fatal("source remained accessible during independent holder restore", e)
	}
	for _, item := range []struct {
		name, path, generation, version string
		trust                           generation.Trust
		owner                           filekit.Owner
		content                         []byte
	}{
		{"old", oldReplicaPath, f.generation, f.version, oldTrust, f.dataOwner, f.content},
		{"new", newReplicaPath, newGeneration, version.Version, nextDomain.Trust, nextOwner, newContent},
	} {
		replica, e := generation.Open(item.path, item.trust, false)
		must(t, e)
		must(t, replica.VerifyComplete(ctx, item.generation))
		kit := filepath.Join(f.base, "offline-"+item.name+"-kit")
		must(t, replica.ExportKit(ctx, item.generation, item.version, kit))
		must(t, replica.Close())
		readOnly, e := item.owner.RecoveryMaterial()
		must(t, e)
		if len(readOnly.SigningKey) != 0 {
			t.Fatal("offline owner material can sign new data")
		}
		reader, e := filekit.OpenStore(kit, readOnly, false)
		must(t, e)
		output := filepath.Join(f.base, "offline-"+item.name+"-restored")
		_, e = reader.Restore(ctx, item.version, output)
		must(t, e)
		must(t, reader.Close())
		data, e := os.ReadFile(filepath.Join(output, "dataset/данные.bin"))
		must(t, e)
		if !bytes.Equal(data, item.content) {
			t.Fatal("retained epoch restored different bytes", item.name)
		}
		wrong := nextOwner
		if item.name == "new" {
			wrong = f.dataOwner
		}
		if opened, e := filekit.OpenStore(kit, wrong, false); e == nil {
			_, restoreErr := opened.Restore(ctx, item.version, filepath.Join(f.base, "wrong-"+item.name+"-epoch"))
			must(t, opened.Close())
			if restoreErr == nil {
				t.Fatal("another epoch's owner material decrypted the kit", item.name)
			}
		}
	}
	t.Log("holder epoch2 is current after reopen; old grant/catalog and higher-revision epoch rollback rejected; both retained epochs restored offline with distinct read-only owner kits")
}
